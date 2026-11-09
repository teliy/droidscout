"""Сопряжение «Отладка по Wi-Fi» (Android 11+) и защищённый ADB-транспорт.

Что происходит при сопряжении (протокол из packages/modules/adb):
1. TCP-соединение на порт сопряжения (он показан на экране телефона
   рядом с 6-значным кодом).
2. TLS 1.3 строго, с клиентским сертификатом: self-signed X.509 для
   нашего RSA-ключа adb (того же, которым потом подписываем AUTH-токены).
   Сертификат сервера не проверяем — как и сам adb.
3. Из TLS-сессии экспортируется 64 байта keying material (лейбл
   «adb-label», RFC 8446 exporter) и добавляется к паролю — код без
   этого знания бесполезен, сессию нельзя «переприсвоить».
4. Обмен SPAKE2-сообщениями (curve25519, см. spake2.py): пароль =
   ASCII-код (6 цифр) + экспортированные 64 байта.
5. Ключ шифрования: HKDF-SHA256(выход SPAKE2, пустая соль,
   info="adb pairing_auth aes-128-gcm key", 16 байт).
6. Обе стороны шлют PeerInfo (ровно 8192 байта: тип + данные),
   зашифрованный AES-128-GCM с нулевым nonce (little-endian счётчик
   сообщений, у нас он всегда 0). Мы отдаём открытый ключ adb
   (base64 RSAPublicKey + « droidscout» + NUL) — телефон сохраняет его
   в adb_keys, после чего обычный ADB-протокол работает внутри
   TLS-канала на «обычном» порту подключения.

Зависимости: pyOpenSSL (в requirements.txt). Без него сопряжение
недоступно, остальное приложение работает как раньше.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import select
import socket
import struct
import threading
import time

from . import config, pure_adb
from .aesgcm import AesGcm
from .spake2 import KEY_SIZE, MSG_SIZE, ROLE_ALICE, Spake2

# --------------------------------------------------------------- константы
_HEADER = struct.Struct(">BBI")      # version:u8, type:u8, payload:u32 (BE)
VERSION = 1
TYPE_SPAKE2_MSG = 0                  # adb.proto.PairingPacket.Type
TYPE_PEER_INFO = 1
MAX_PAYLOAD = 8192 * 2               # kMaxPayloadSize = kMaxPeerInfoSize * 2
PEER_INFO_SIZE = 8192                # sizeof(PeerInfo): uint8 type + data[8191]
ADB_RSA_PUB_KEY = 0                  # PeerInfoType
ADB_DEVICE_GUID = 1

_EXPORT_LABEL = b"adb-label"         # kExportedKeyLabel из tls_connection.cpp
_EXPORT_LEN = 64                     # kExportedKeySize
_HKDF_INFO = b"adb pairing_auth aes-128-gcm key"   # sizeof - 1, без NUL

CLIENT_NAME = b"adb pair client\x00"  # kClientName/kServerName с NUL
SERVER_NAME = b"adb pair server\x00"

try:                                    # pyOpenSSL нужен только для Wi-Fi-режима
    from OpenSSL import SSL as _SSL
except ImportError:                     # остальное приложение работает без него
    _SSL = None


class PairError(Exception):
    """Ошибка сопряжения. code — машинный код для переводов i18n."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------ HKDF
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract + expand)."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, prev, i = b"", b"", 1
    while len(out) < length:
        prev = hmac.new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        out += prev
        i += 1
    return out[:length]


# ------------------------------------------------------- TLS-обвязка
def _tls_available() -> bool:
    try:
        import OpenSSL  # noqa: F401
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _build_cert_pems(keypair: dict) -> "tuple[str, str]":
    """Self-signed X.509 (CN=adb) для RSA-ключа adb — как GenerateX509Certificate
    в adb (контент серта устройством не разбирается, важен только публичный
    ключ внутри). Возвращает (cert_pem, key_pem)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    priv = rsa.RSAPrivateNumbers(
        p=keypair["p"], q=keypair["q"], d=keypair["d"],
        dmp1=keypair["d"] % (keypair["p"] - 1),
        dmq1=keypair["d"] % (keypair["q"] - 1),
        iqmp=pow(keypair["q"], -1, keypair["p"]),
        public_numbers=rsa.RSAPublicNumbers(keypair["e"], keypair["n"]),
    ).private_key()

    key_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode("ascii")

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adb")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .sign(priv, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return cert_pem, key_pem


class TlsSock:
    """Обёртка pyOpenSSL-соединения под интерфейс сокета, которого ждёт
    pure_adb (recv/sendall/settimeout/close). Сокет в Python при
    settimeout фактически неблокирующий, поэтому WantRead/WantWrite
    обрабатываются через select с общим дедлайном."""

    def __init__(self, conn, raw, timeout: float):
        self.conn = conn
        self.raw = raw
        self._timeout = timeout

    # -- служебное -------------------------------------------------------
    def fileno(self):
        return self.raw.fileno()

    def settimeout(self, timeout):
        self._timeout = timeout

    def close(self):
        try:
            self.conn.shutdown()
        except Exception:
            pass
        try:
            self.raw.close()
        except OSError:
            pass

    def _deadline(self):
        return time.monotonic() + (self._timeout if self._timeout else 30.0)

    def _wait(self, write: bool, deadline: float):
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout("TLS: тайм-аут обмена")
        try:
            if write:
                select.select([], [self.conn], [], left)
            else:
                select.select([self.conn], [], [], left)
        except (OSError, ValueError):
            pass  # сокет уже закрыт — следующий recv/sendall сообщит

    # -- интерфейс сокета --------------------------------------------------
    def recv(self, size: int) -> bytes:
        deadline = self._deadline()
        while True:
            try:
                return self.conn.recv(size)
            except _SSL.WantReadError:
                self._wait(False, deadline)
            except _SSL.WantWriteError:
                self._wait(True, deadline)
            except _SSL.ZeroReturnError:
                return b""                       # аккуратное закрытие peer'ом

    def sendall(self, data: bytes):
        deadline = self._deadline()
        while True:
            try:
                self.conn.sendall(data)
                return
            except _SSL.WantReadError:
                self._wait(False, deadline)
            except _SSL.WantWriteError:
                self._wait(True, deadline)

    def export_keying_material(self, label: bytes, length: int) -> bytes:
        return self.conn.export_keying_material(label, length)


def tls_connect(host: str, port: int, timeout: float, keypair: dict) -> TlsSock:
    """TCP + TLS 1.3 с клиентским сертификатом (adb-style)."""
    try:
        from OpenSSL import SSL, crypto
    except ImportError as exc:
        raise PairError("pyopenssl") from exc

    cert_pem, key_pem = _build_cert_pems(keypair)
    try:
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        ctx.use_certificate(
            crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
        ctx.use_privatekey(
            crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
        ctx.set_verify(SSL.VERIFY_NONE, callback=None)  # как у adb: любой серт
    except Exception as exc:
        raise PairError("tls", str(exc)) from exc

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise PairError("connect", str(exc)) from exc
    try:
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    conn = SSL.Connection(ctx, raw)
    conn.set_connect_state()
    deadline = time.monotonic() + timeout
    while True:
        try:
            conn.do_handshake()
            break
        except SSL.WantReadError:
            _wait_raw(raw, False, deadline)
        except SSL.WantWriteError:
            _wait_raw(raw, True, deadline)
        except SSL.Error as exc:
            raw.close()
            raise PairError("tls", str(exc)) from exc
        except OSError as exc:
            raw.close()
            raise PairError("connect", str(exc)) from exc
    return TlsSock(conn, raw, timeout)


def _wait_raw(raw: socket.socket, write: bool, deadline: float):
    left = deadline - time.monotonic()
    if left <= 0:
        raw.close()
        raise PairError("timeout", "TLS handshake")
    try:
        if write:
            select.select([], [raw], [], left)
        else:
            select.select([raw], [], [], left)
    except (OSError, ValueError):
        pass


def wrap_tls(raw: socket.socket, timeout: float, keypair: dict) -> TlsSock:
    """Обернуть уже открытый TCP-сокет в TLS (для AdbDevice.secure)."""
    try:
        from OpenSSL import SSL, crypto
    except ImportError as exc:
        raise PairError("pyopenssl") from exc

    cert_pem, key_pem = _build_cert_pems(keypair)
    try:
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.set_max_proto_version(SSL.TLS1_3_VERSION)
        ctx.use_certificate(
            crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem))
        ctx.use_privatekey(
            crypto.load_privatekey(crypto.FILETYPE_PEM, key_pem))
        ctx.set_verify(SSL.VERIFY_NONE, callback=None)
    except Exception as exc:
        raise PairError("tls", str(exc)) from exc

    conn = SSL.Connection(ctx, raw)
    conn.set_connect_state()
    deadline = time.monotonic() + timeout
    while True:
        try:
            conn.do_handshake()
            break
        except SSL.WantReadError:
            _wait_raw(raw, False, deadline)
        except SSL.WantWriteError:
            _wait_raw(raw, True, deadline)
        except SSL.Error as exc:
            raw.close()
            raise PairError("tls", str(exc)) from exc
        except OSError as exc:
            raw.close()
            raise PairError("connect", str(exc)) from exc
    return TlsSock(conn, raw, timeout)


# ------------------------------------------- протокол сопряжения (PAIR)
def _write_packet(sock: TlsSock, ptype: int, payload: bytes) -> None:
    sock.sendall(_HEADER.pack(VERSION, ptype, len(payload)) + payload)


def _read_exact(sock: TlsSock, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise PairError("closed")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_packet(sock: TlsSock) -> "tuple[int, bytes]":
    version, ptype, length = _HEADER.unpack(_read_exact(sock, _HEADER.size))
    if version != VERSION:
        raise PairError("proto", f"version {version}")
    if length == 0 or length > MAX_PAYLOAD:
        raise PairError("proto", f"payload {length}")
    return ptype, _read_exact(sock, length)


def _gcm_nonce(seq: int) -> bytes:
    """12-байтный nonce: little-endian u64 счётчик + 4 нулевых байта."""
    return seq.to_bytes(8, "little") + b"\x00" * 4


def pair(host: str, port: int, code: str, timeout: float = 15.0,
         keypair: "dict | None" = None) -> str:
    """Сопряжение с устройством. Возвращает GUID устройства.

    Бросает PairError: connect/tls/timeout/closed/code/proto.
    """
    if not code or not code.strip().isdigit() or len(code.strip()) != 6:
        raise PairError("code")
    if not _tls_available():
        raise PairError("pyopenssl")
    key = keypair or pure_adb.load_or_create_keys()
    if not key:
        raise PairError("nokey")

    sock = tls_connect(host, port, timeout, key)
    try:
        # Пароль = ASCII-код + 64 байта экспорта TLS (см. SetupTlsConnection)
        exported = sock.export_keying_material(_EXPORT_LABEL, _EXPORT_LEN)
        password = code.strip().encode("ascii") + exported

        spake = Spake2(ROLE_ALICE, CLIENT_NAME, SERVER_NAME)
        _write_packet(sock, TYPE_SPAKE2_MSG, spake.generate_message(password))
        ptype, their_msg = _read_packet(sock)
        if ptype != TYPE_SPAKE2_MSG:
            raise PairError("proto", f"packet {ptype}")
        try:
            key64 = spake.process_message(their_msg)
        except ValueError as exc:
            raise PairError("proto", str(exc)) from exc
        aes = AesGcm(hkdf_sha256(key64, b"", _HKDF_INFO, 16))

        # Наш PeerInfo: тип + открытый ключ adb (то, что попадёт в adb_keys)
        blob = pure_adb.android_pubkey_blob(key)
        info = bytearray(PEER_INFO_SIZE)
        info[0] = ADB_RSA_PUB_KEY
        info[1:1 + len(blob)] = blob
        try:
            ct = aes.encrypt(_gcm_nonce(0), bytes(info), b"")
        except ValueError as exc:
            raise PairError("proto", str(exc)) from exc
        _write_packet(sock, TYPE_PEER_INFO, ct)

        # Ответ устройства: при неверном коде adbd не может расшифровать
        # наш PeerInfo и обрывает соединение — клиент видит либо ошибку
        # GCM, либо EOF от TLS. Оба случая = «неверный код или обрыв»
        # (сам adb показывает ровно такую же неоднозначность).
        try:
            ptype, reply = _read_packet(sock)
            if ptype != TYPE_PEER_INFO:
                raise PairError("proto", f"packet {ptype}")
            pt = aes.decrypt(_gcm_nonce(0), reply, b"")
        except PairError:
            raise
        except Exception as exc:            # TLS EOF / SysCallError от adbd
            raise PairError("code", str(exc)) from exc
        if len(pt) != PEER_INFO_SIZE:
            raise PairError("proto", f"peer info {len(pt)}")
        if pt[0] != ADB_DEVICE_GUID:
            raise PairError("proto", f"peer type {pt[0]}")
        guid = bytes(pt[1:]).split(b"\x00", 1)[0].decode("utf-8", "replace")
        return guid
    except PairError:
        raise
    except (OSError, socket.timeout) as exc:
        raise PairError("closed", str(exc)) from exc
    finally:
        sock.close()


# --------------------------------------- реестр защищённых подключений
_lock = threading.Lock()
_cache = None   # dict[ip] = port


def _registry_path() -> str:
    return os.path.join(config.config_dir(), "wifi_devices.json")


def _load() -> dict:
    global _cache
    with _lock:
        if _cache is None:
            try:
                with open(_registry_path(), encoding="utf-8") as fh:
                    data = json.load(fh)
                _cache = {str(k): int(v) for k, v in data.items()}
            except (OSError, ValueError, AttributeError):
                _cache = {}
        return _cache


def _save() -> None:
    with _lock:
        try:
            os.makedirs(os.path.dirname(_registry_path()), exist_ok=True)
            with open(_registry_path(), "w", encoding="utf-8") as fh:
                json.dump(_cache, fh, ensure_ascii=False, indent=1)
        except OSError:
            pass  # настройки не критичны — приложение продолжит работать


def get_secure_port(ip: str) -> "int | None":
    """Порт защищённого ADB (Android 11+), если устройство сопряжено."""
    return _load().get(ip)


def register_secure(ip: str, port: int) -> None:
    _load()[ip] = int(port)
    _save()


def forget_secure(ip: str) -> None:
    if ip in _load():
        del _cache[ip]
        _save()
