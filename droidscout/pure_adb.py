"""Встроенный ADB-клиент на чистом Python (только стандартная библиотека).

Подключается напрямую к adbd устройства по TCP (порт 5555, «Отладка по USB
по сети» / «ADB по сети») и реализует протокол SMART-сокетов:
CNXN / AUTH / OPEN / OKAY / WRTE / CLSE.

Почему «свой adb» вместо внешнего бинарника:
  * не нужен установленный Platform-Tools — ничего качать не требуется;
  * один запрос ``getprop`` вместо десяти запусков adb-процесса;
  * нет черного окна консоли (Windows) и зависимостей от PATH;
  * ключи совместимы с официальным adb: сначала используется
    ``~/.android/adbkey`` (устройства, авторизованные adb, примут нас
    без повторного подтверждения), иначе генерируется собственный ключ.

USB-устройства не поддерживаются — только сетевой режим adbd.
"""

import base64
import hashlib
import math
import os
import re
import secrets
import select
import socket
import struct
import threading
import time
from shlex import quote as shlex_quote

from . import config
from . import journal

# ---------------------------------------------------------------- константы
A_VERSION = 0x01000001          # версия протокола (device возьмёт минимум)
MAX_PAYLOAD = 256 * 1024        # предлагаемый размер чанка
_CNXN_GRACE = 1.0               # окно ожидания AUTH после первого CNXN (сек)
_TLS_CNXN_WAIT = 8.0            # окно ожидания CNXN внутри TLS (сек)
_MAX_RECV = 16 * 1024 * 1024    # санитарный предел длины пакета от устройства

# Команда в заголовке пакета — little-endian uint32, поэтому первые 4 байта
# пакета на проводе читаются как ASCII-имя команды (Wireshark разбирает ADB
# именно по этим байтам). Значения сверены с adb.h из AOSP:
#   A_CNXN 0x4e584e43, A_AUTH 0x48545541, A_OPEN 0x4e45504f,
#   A_OKAY 0x59414b4f, A_WRTE 0x45545257, A_CLSE 0x45534c43.
# История: в 1.6.0 пять констант были записаны с обратным порядком байтов
# (например OPEN = 0x4F50454E -> на проводе "NEPO"). CNXN был верным, поэтому
# handshake проходил, а OPEN adbd молча игнорировал ("handle_packet: what is
# 0x4f50454e?!") — любая shell-команда падала по таймауту, хотя в консоли
# adb всё работало. Мок-тесты не ловили это, потому что фейковый сервер брал
# константы из того же модуля. Теперь константы пинятся тестом (см.
# scripts/test_pure_adb.py) и самопроверкой ниже.
A_CNXN = 0x4E584E43             # "CNXN" — установка соединения
A_AUTH = 0x48545541             # "AUTH"  — аутентификация RSA
A_OPEN = 0x4E45504F             # "OPEN"  — открыть поток (shell:…)
A_OKAY = 0x59414B4F             # "OKAY"  — подтверждение
A_WRTE = 0x45545257             # "WRTE"  — данные потока
A_CLSE = 0x45534C43             # "CLSE"  — закрыть поток
A_STLS = 0x534C5453             # "STLS" — переход транспорта на TLS

for _cmd_name, _cmd_value in (("CNXN", A_CNXN), ("AUTH", A_AUTH),
                              ("OPEN", A_OPEN), ("OKAY", A_OKAY),
                              ("WRTE", A_WRTE), ("CLSE", A_CLSE),
                              ("STLS", A_STLS)):
    assert _cmd_value == int.from_bytes(_cmd_name.encode("ascii"), "little"), \
        f"ADB command constant for {_cmd_name} has wrong byte order"
del _cmd_name, _cmd_value

TLS_VERSION_MIN = 0x01000000    # минимальная версия TLS-транспорта adb

# CNXN-приветствие защищённого транспорта — как у официального adb
# (protocol.TXT: "host::features=…"). tls_auth заявляет умение STLS-перехода;
# остальной список совпадает с kFeatures adb — телефон не начнёт
# использование фичи, пока клиент сам не запросит соответствующий сервис.
_CONNECT_FEATURES = (b"host::features=shell_v2,cmd,stat_v2,ls_v2,"
                     b"fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,"
                     b"abb_exec,remount_shell,track_app,sendrecv_v2,"
                     b"sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,"
                     b"sendrecv_v2_dry_run_send,openscreen_mdns,tls_auth\x00")

AUTH_TOKEN = 1                  # device прислал одноразовый токен
AUTH_SIGN = 2                   # мы подписали токен приватным ключом
AUTH_RSAPUBLICKEY = 3           # мы прислали открытый ключ (нужно «Разрешить»)

_DIGEST_INFO_SHA1 = bytes.fromhex("3021300906052b0e03021a05000414")
_PROP_RE_TMPL = r"^\[([^\]]+)\]:\s+\[(.*)\]$"


class AdbError(Exception):
    """Общая ошибка протокола ADB."""


class AdbUnauthorized(AdbError):
    """Устройство не подтвердило отпечаток нашего ключа."""


class AdbTimeout(AdbError):
    """Таймаут соединения или ответа устройства."""


# ------------------------------------------------------------------ RSA-ключи
def _der_read(data: bytes, offset: int = 0):
    """Читает один TLV-элемент DER. Возвращает (tag, value, next_offset)."""
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + nbytes], "big")
        offset += nbytes
    return tag, data[offset:offset + length], offset + length


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_int(value: int) -> bytes:
    data = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if data[0] & 0x80:            # избегаем «отрицательного» старшего бита
        data = b"\x00" + data
    return b"\x02" + _der_len(len(data)) + data


def serialize_pkcs1(key: dict) -> bytes:
    """Кодирует ключ в DER-структуру RSAPrivateKey (PKCS#1)."""
    p, q, d, n = key["p"], key["q"], key["d"], key["n"]
    ints = [0, n, key["e"], d, p, q,
            d % (p - 1), d % (q - 1), pow(q, -1, p)]
    body = b"".join(_der_int(v) for v in ints)
    return b"\x30" + _der_len(len(body)) + body


def parse_pkcs1_pem(pem_text: str) -> dict:
    """Разбирает '-----BEGIN RSA PRIVATE KEY-----' (формат adbkey)."""
    body = "".join(line for line in pem_text.splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    tag, seq, _ = _der_read(der)
    if tag != 0x30:
        raise AdbError("not a PKCS#1 structure")
    ints = []
    offset = 0
    while offset < len(seq):
        t, value, offset = _der_read(seq, offset)
        if t == 0x02:
            ints.append(int.from_bytes(value, "big"))
    if len(ints) < 6:
        raise AdbError("short RSA private key")
    # [version, n, e, d, p, q, dp, dq, qinv]
    return {"n": ints[1], "e": ints[2], "d": ints[3], "p": ints[4], "q": ints[5]}


def to_pem(key: dict) -> str:
    der = serialize_pkcs1(key)
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines)
            + "\n-----END RSA PRIVATE KEY-----\n")


# Малые простые для быстрой фильтрации кандидатов
_SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
                 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
                 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
                 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
                 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349]


def _is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_keypair(bits: int = 2048) -> dict:
    """Генерирует RSA-ключ (чистый Python; 2048 бит занимает несколько секунд)."""
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        return {"n": n, "e": e, "d": pow(e, -1, phi), "p": p, "q": q}


def _gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def sign_token(key: dict, token: bytes) -> bytes:
    """Подпись токена adbd: RSASSA-PKCS1-v1_5(SHA-1(token))."""
    digest = hashlib.sha1(token).digest()
    digest_info = _DIGEST_INFO_SHA1 + digest
    k = (key["n"].bit_length() + 7) // 8
    padding = k - len(digest_info) - 3
    em = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    sig = pow(int.from_bytes(em, "big"), key["d"], key["n"])
    return sig.to_bytes(k, "big")


def verify_token(key: dict, token: bytes, signature: bytes) -> bool:
    """Проверка подписи (нужна для самотестирования)."""
    k = (key["n"].bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), key["e"], key["n"])
    em = em.to_bytes(k, "big")
    digest_info = _DIGEST_INFO_SHA1 + hashlib.sha1(token).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return em == expected


def android_pubkey_blob(key: dict, user: str = "droidscout") -> bytes:
    """Открытый ключ в формате RSAPublicKey adbd (base64 + ' user' + NUL)."""
    n, e = key["n"], key["e"]
    bits = n.bit_length()
    words = bits // 32
    r = 1 << bits
    # Параметры Монтгомери, требуемые реализацией adb на устройстве
    n0inv = (-pow(n, -1, 1 << 32)) % (1 << 32)
    rr = (r * r) % n
    raw = struct.pack("<I", words)
    raw += struct.pack("<I", n0inv)
    raw += n.to_bytes(words * 4, "little")
    raw += rr.to_bytes(words * 4, "little")
    raw += struct.pack("<I", e)
    return base64.b64encode(raw) + b" " + user.encode() + b"\x00"


# ------------------------------------------------------------- хранилище ключей
_key_lock = threading.Lock()
_key_cache = None


def key_file_path() -> str:
    """Наш файл ключа (каталог настроек приложения)."""
    return os.path.join(config.config_dir(), "adbkey")


def load_or_create_keys(create: bool = True) -> "dict | None":
    """Ключи для AUTH: системный ~/.android/adbkey или собственный.

    Системный ключ приоритетен: устройства, уже авторизовавшие adb,
    примут и наш клиент без нового диалога подтверждения.
    """
    global _key_cache
    with _key_lock:
        if _key_cache:
            return _key_cache
        candidates = [os.path.join(os.path.expanduser("~"), ".android", "adbkey"),
                      key_file_path()]
        for path in candidates:
            try:
                with open(path, encoding="ascii") as f:
                    key = parse_pkcs1_pem(f.read())
                _key_cache = key
                return key
            except (OSError, ValueError, AdbError):
                continue
        if not create:
            return None
        key = generate_keypair(2048)
        path = key_file_path()
        try:
            with open(path, "w", encoding="ascii") as f:
                f.write(to_pem(key))
            os.chmod(path, 0o600)
            with open(path + ".pub", "wb") as f:
                f.write(android_pubkey_blob(key))
        except OSError:
            pass  # ключ останется только в памяти
        _key_cache = key
        return key


# --------------------------------------------------------------- протокол ADB
class _Message:
    __slots__ = ("cmd", "arg0", "arg1", "data")

    def __init__(self, cmd, arg0, arg1, data):
        self.cmd, self.arg0, self.arg1, self.data = cmd, arg0, arg1, data


def checksum(data: bytes) -> int:
    """Контрольная сумма ADB — простая сумма байтов (не CRC!).

    Именно её считает официальный adb/adbd (check_data в adb.cpp):
    sum(data) & 0xFFFFFFFF.
    """
    return sum(data) & 0xFFFFFFFF


def encode_message(cmd: int, arg0: int, arg1: int, data: bytes) -> bytes:
    header = struct.pack("<IIIIII", cmd, arg0, arg1, len(data),
                         checksum(data), cmd ^ 0xFFFFFFFF)
    return header + data


def _read_exact(sock, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise AdbError("connection closed by device")
        chunks.extend(chunk)
    return bytes(chunks)


class AdbDevice:
    """Клиент adbd по TCP. Пример::

        dev = AdbDevice("192.168.1.50")
        dev.connect()
        print(dev.shell("getprop ro.product.model"))
    """

    def __init__(self, host: str, port: int = 5555, timeout: float = 10.0,
                 keypair: "dict | None" = None, tls: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_payload = 4 * 1024
        self.sock = None
        self._local_id = 1
        self.keypair = keypair
        self.tls = tls                  # ADB внутри TLS 1.3 (Android 11+ Wi-Fi)
        self.public_key_sent = False   # True → устройство ждало подтверждения
        self.bad_checksums = 0         # пакеты с неверной суммой (кривые прошивки)

    # ------------------------------------------------------------- соединение
    def connect(self, auth_timeout: "float | None" = None):
        """Рукопожатие CNXN + RSA-авторизация. Бросает AdbUnauthorized,
        если пользователь не подтвердил ключ на устройстве.

        Обычный adbd (порт 5555): устройство шлёт свой CNXN сразу после
        accept; затем, если включена защита, шлёт AUTH TOKEN — уже после
        получения нашего CNXN. При успешной авторизации устройство шлёт
        второй CNXN. Если после первого CNXN тишина (grace-окно) —
        устройство без авторизации (ro.adb.secure=0).

        «Отладка по Wi-Fi» (Android 11+, tls=True) — сверено с исходниками
        AOSP packages/modules/adb (adb.cpp: handle_new_connection →
        send_tls_request; adb_wifi.cpp: adbd_wifi_secure_connect):
        1) канал начинается открыто: мы шлём CNXN — телефон отвечает
           A_STLS (своего открытого CNXN он НЕ шлёт);
        2) мы отвечаем A_STLS, обе стороны делают TLS 1.3 с клиентским
           сертификатом (телефон проверяет наш ключ по сохранённому
           при сопряжении);
        3) CNXN внутри TLS первым шлёт САМ телефон
           (adbd_wifi_secure_connect → send_connect). Наш повторный CNXN
           там запрещён: в adbd любой CNXN проходит через
           handle_new_connection, который делает handle_offline и снова
           send_tls_request — транспорт разрушается сразу после
           «успешного» рукопожатия. Это был баг 1.7.3: сопряжение
           проходило, а «Подключить» падало с любым портом.

        Если телефон молчит или рвёт соединение после нашего открытого
        CNXN, пробуем второй сценарий на свежем TCP: часть прошивок
        начинает TLS сразу после connect (ClientHello первым).
        """
        deadline = auth_timeout or max(self.timeout, 30.0)
        if not self.tls:
            self._open_tcp()
            self._send(A_CNXN, A_VERSION, MAX_PAYLOAD, b"host::\x00")
            self._finish_handshake(deadline, saw_cnxn=False, secure=False)
            return

        first_exc = None
        for tls_first in (False, True):
            try:
                self._open_tcp()
            except AdbError:
                if first_exc is not None:
                    raise first_exc from None   # порт недоступен — ретраи не помогут
                raise
            try:
                self._connect_secure(tls_first, deadline)
                return
            except AdbUnauthorized:
                raise          # телефон явно отклонил ключ — ретрай бессмыслен
            except AdbError as exc:
                first_exc = first_exc or exc
                self.close()
        raise first_exc

    def _open_tcp(self):
        try:
            self.sock = socket.create_connection((self.host, self.port),
                                                 timeout=self.timeout)
        except OSError as exc:
            raise AdbError(f"connect: {exc}") from exc
        self.sock.settimeout(self.timeout)
        try:
            # Nagle вносит задержки в пакетный обмен «запрос-ответ»
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass  # экзотическая платформа — работает и без этого

    def _connect_secure(self, tls_first: bool, deadline: float):
        """Рукопожатие «Отладки по Wi-Fi».

        tls_first=False — канонический AOSP-сценарий: CNXN → STLS → TLS;
        tls_first=True — прошивки, начинающие TLS сразу после connect.
        """
        from . import wifi_pair
        key = self.keypair or load_or_create_keys()
        saw_cnxn = False
        if tls_first:
            self.sock = self._wrap_tls(key)
            # внутри TLS первым CNXN присылает телефон
        else:
            self._send(A_CNXN, A_VERSION, MAX_PAYLOAD, _CONNECT_FEATURES)
            try:
                first = self._recv(min(self.timeout, 6.0))
            except (socket.timeout, TimeoutError) as exc:
                raise AdbTimeout("no CNXN/STLS answer from device") from exc
            except OSError as exc:
                raise AdbError(f"device closed connection: {exc}") from exc
            if first.cmd == A_STLS:
                self._send(A_STLS, first.arg0 or TLS_VERSION_MIN, 0, b"")
                self.sock = self._wrap_tls(key)
            elif first.cmd == A_CNXN:
                # На этом порту обычный adbd без «Отладки по Wi-Fi»
                # (например, в шаг 2 ввели порт 5555 приставки) — работаем
                # в открытом виде; его CNXN уже прочитан.
                self.max_payload = max(1024, min(first.arg1, MAX_PAYLOAD))
                saw_cnxn = True
            else:
                self.close()
                raise AdbError(
                    f"unexpected packet 0x{first.cmd:08x} instead of STLS")
        self._finish_handshake(deadline, saw_cnxn=saw_cnxn,
                               secure=not saw_cnxn)

    def _wrap_tls(self, key: dict):
        """TLS 1.3 с клиентским сертификатом поверх текущего TCP-сокета."""
        from . import wifi_pair
        try:
            return wifi_pair.wrap_tls(self.sock, self.timeout, key)
        except wifi_pair.PairError as exc:
            # PairError → AdbError с машинным префиксом «tls:» для
            # классификации в UI (неверный порт/ключ прошивки и т.п.)
            raise AdbError(f"tls: {exc.detail or exc.code}") from exc

    def _finish_handshake(self, deadline: float, saw_cnxn: bool,
                          secure: bool):
        """Цикл CNXN/AUTH после установления транспорта."""
        deadline_ts = _now() + deadline
        pubkey_sent = False
        tokens_seen = 0
        try:
            while True:
                remaining = deadline_ts - _now()
                if remaining <= 0:
                    if pubkey_sent:
                        raise AdbUnauthorized("user did not confirm the key")
                    raise AdbTimeout("handshake timeout")
                # После первого CNXN ждём возможный AUTH короткое окно
                wait = remaining if not saw_cnxn else min(remaining, _CNXN_GRACE)
                if secure:
                    # Внутри TLS первым CNXN шлёт телефон сразу после
                    # рукопожатия — ждать дольше 8 с бессмысленно
                    wait = min(wait, _TLS_CNXN_WAIT)
                try:
                    message = self._recv(wait)
                except (socket.timeout, TimeoutError) as exc:
                    if pubkey_sent:
                        raise AdbUnauthorized("user did not confirm the key") from exc
                    if saw_cnxn:
                        return  # insecure-устройство: после CNXN тишина
                    if secure:
                        raise AdbTimeout(
                            "no CNXN inside TLS — key not accepted?") from exc
                    raise AdbTimeout("handshake timeout") from exc
                except AdbError as exc:
                    # Устройство разорвало соединение: если оно уже увидело
                    # наш открытый ключ — считаем, что подтверждения не было.
                    if pubkey_sent:
                        raise AdbUnauthorized("user did not confirm the key") from exc
                    raise
                if message.cmd == A_CNXN:
                    self.max_payload = max(1024, min(message.arg1, MAX_PAYLOAD))
                    if secure:
                        return        # TLS уже авторизовал нас — AUTH не будет
                    if tokens_seen:
                        return        # подтверждение после авторизации
                    if saw_cnxn:
                        return        # повторный CNXN без AUTH — insecure
                    saw_cnxn = True
                    continue
                if message.cmd == A_STLS and not secure:
                    # Запрос TLS-перехода после открытого обмена (часть
                    # прошивок шлёт STLS после своего CNXN): отвечаем и
                    # продолжаем внутри TLS — CNXN пришлёт телефон.
                    self._send(A_STLS, message.arg0 or TLS_VERSION_MIN, 0, b"")
                    self.sock = self._wrap_tls(
                        self.keypair or load_or_create_keys())
                    secure = True
                    continue
                if message.cmd == A_AUTH and message.arg0 == AUTH_TOKEN:
                    tokens_seen += 1
                    # Всегда подписываем токен: если ключ уже известен устройству,
                    # следующего пакета не будет — придёт CNXN.
                    self._send(A_AUTH, AUTH_SIGN, 0, self._sign(message.data))
                    # Второй токен означает, что подпись незнакома: предлагаем
                    # открытый ключ (на устройстве появится диалог «Разрешить»).
                    if tokens_seen >= 2 and not pubkey_sent:
                        pubkey_sent = True
                        self.public_key_sent = True
                        self._send(A_AUTH, AUTH_RSAPUBLICKEY, 0, self._pubkey())
                    continue
                raise AdbError(f"unexpected packet 0x{message.cmd:08x} in handshake")
        except Exception:
            self.close()
            raise

    def _sign(self, token: bytes) -> bytes:
        key = self.keypair or load_or_create_keys(create=False)
        if not key:
            raise AdbUnauthorized("no RSA key available")
        return sign_token(key, token)

    def _pubkey(self) -> bytes:
        key = self.keypair or load_or_create_keys(create=False)
        if not key:
            raise AdbUnauthorized("no RSA key available")
        return android_pubkey_blob(key)

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_exc):
        self.close()

    # ------------------------------------------------------------- потоки данных
    def _collect(self, service: bytes, timeout: "float | None" = None) -> bytes:
        """Открывает поток service и собирает вывод до CLSE (бинарно-безопасно)."""
        if not self.sock:
            raise AdbError("not connected")
        local_id = self._local_id
        self._local_id += 2
        output = bytearray()
        # Сервис шлётся без завершающего NUL — ровно как официальный adb;
        # adbd сам терминирует строку (smart_socket_data[len] = 0).
        self._send(A_OPEN, local_id, 0, service)
        deadline = _now() + (timeout or self.timeout)
        while True:
            remaining = deadline - _now()
            if remaining <= 0:
                raise AdbTimeout("shell timeout")
            try:
                message = self._recv(remaining)
            except (socket.timeout, TimeoutError) as exc:
                raise AdbTimeout("shell timeout") from exc
            # Стандарт: устройство шлёт arg0 = свой (remote) id, arg1 = наш
            # (local) id. Кривые прошивки путают аргументы местами — у нас
            # на соединении ровно один поток, поэтому сверяемся с обоими.
            if message.cmd == A_OKAY and local_id in (message.arg0, message.arg1):
                continue
            if message.cmd == A_WRTE and local_id in (message.arg0, message.arg1):
                output.extend(message.data)
                remote = message.arg0 if message.arg0 != local_id else message.arg1
                self._send(A_OKAY, local_id, remote)
                continue
            if message.cmd == A_CLSE and local_id in (message.arg0, message.arg1):
                return bytes(output)
            if message.cmd == A_AUTH:
                raise AdbError("device restarted authentication mid-session")

    def shell(self, command: str, timeout: "float | None" = None) -> str:
        """Выполняет команду через 'shell:' и возвращает stdout+stderr."""
        return self._collect(b"shell:" + command.encode("utf-8"),
                             timeout).decode("utf-8", errors="replace")

    def shell_bytes(self, command: str, timeout: "float | None" = None) -> bytes:
        """shell: с бинарным выводом (без декодирования)."""
        return self._collect(b"shell:" + command.encode("utf-8"), timeout)

    def exec_out(self, command: str, timeout: "float | None" = None) -> bytes:
        """Сервис 'exec:' — сырой поток без pty: бинарный вывод не искажается
        (аналог 'adb exec-out'). Подходит для screencap/cat и т.п."""
        return self._collect(b"exec:" + command.encode("utf-8"), timeout)

    # ------------------------------------------------------------- удобства
    def get_properties(self, timeout: "float | None" = None) -> "dict[str, str]":
        """Все свойства устройства одним вызовом 'getprop'."""
        text = self.shell("getprop", timeout=timeout)
        pattern = re.compile(_PROP_RE_TMPL, re.M)
        return {key: value for key, value in pattern.findall(text)}

    def serial(self) -> str:
        return self.shell("getprop ro.serialno", timeout=10).strip()

    def pull_file(self, remote_path: str, timeout: "float | None" = None) -> bytes:
        """Читает файл с устройства: 'cat' через exec: (бинарно-безопасно).
        Fallback — base64 (спасает от pty-искажений на старых adbd)."""
        quoted = shlex_quote(remote_path)
        data = self.exec_out(f"cat {quoted}", timeout=timeout)
        if data:
            return data
        text = self.shell(f"base64 {quoted}", timeout=timeout)
        return base64.b64decode(re.sub(r"\s+", "", text)) if text.strip() else b""

    def push_bytes(self, data: bytes, remote_path: str,
                   timeout: "float | None" = None,
                   progress: "Callable[[int, int], None] | None" = None,
                   should_stop: "Callable[[], bool] | None" = None) -> None:
        """Кладёт файл на устройство через сервис 'sync:' (SEND/DATA/DONE).

        Соединение не закрывается — можно продолжить работу (например,
        вызвать shell("pm install …") сразу после передачи APK).

        progress(отправлено_байт, всего_байт) вызывается после каждого
        чанка — для диалога прогресса в UI. should_stop() проверяется
        между чанками: True -> AdbError('push cancelled') — так работает
        кнопка «Отмена». Подтверждения OKAY дочитываются в процессе
        передачи (_drain_sync): без этого на файлах в сотни мегабайт
        TCP-буферы переполняются и передача замирает навсегда.
        """
        if not self.sock:
            raise AdbError("not connected")
        deadline = _now() + (timeout or self.timeout)

        def remaining() -> float:
            left = deadline - _now()
            if left <= 0:
                raise AdbTimeout("sync timeout")
            return left

        local_id = self._local_id
        self._local_id += 2
        self._send(A_OPEN, local_id, 0, b"sync:")
        got_okay = False
        while not got_okay:
            message = self._recv(remaining())
            if message.cmd == A_OKAY and message.arg1 == local_id:
                got_okay = True
            elif message.cmd == A_WRTE and message.arg1 == local_id:
                self._send(A_OKAY, local_id, message.arg0)
            elif message.cmd == A_CLSE and message.arg1 == local_id:
                raise AdbError("sync stream rejected")

        def sync(cmd: bytes, payload: bytes = b"") -> None:
            # Заголовок sync-кадра: 4-байтовое слово команды + длина
            self._send(A_WRTE, local_id, 0,
                       struct.pack("<4sI", cmd, len(payload)) + payload)

        def sync_ack() -> bytes:
            # читает подтверждение устройства (ACK на WRTE + ответ команды)
            while True:
                message = self._recv(remaining())
                if message.cmd == A_WRTE and message.arg1 == local_id:
                    self._send(A_OKAY, local_id, message.arg0)
                    if message.data[:4] in (b"OKAY", b"FAIL", b"QUIT"):
                        return message.data
                elif message.cmd == A_OKAY and message.arg1 == local_id:
                    continue
                elif message.cmd == A_CLSE and message.arg1 == local_id:
                    raise AdbError("sync stream closed unexpectedly")

        # Поток-уровня ответ (OKAY/FAIL в данных WRTE) устройство шлёт только
        # после DONE; промежуточные socket-ACK (A_OKAY) дочитываются в конце.
        sync(b"SEND", remote_path.encode("utf-8") + b",0644")
        chunk_size = max(1024, min(self.max_payload, 32 * 1024))
        total = len(data)
        for offset in range(0, total, chunk_size):
            if should_stop is not None and should_stop():
                raise AdbError("push cancelled")
            chunk = data[offset:offset + chunk_size]
            sync(b"DATA", chunk)
            if progress is not None:
                try:
                    progress(offset + len(chunk), total)
                except Exception:  # noqa: BLE001 — прогресс не роняет передачу
                    pass
            self._drain_sync(local_id, remaining)
        sync(b"DONE", struct.pack("<I", int(time.time())))
        answer = sync_ack()
        if answer[:4] == b"FAIL":
            size = struct.unpack("<I", answer[4:8])[0] if len(answer) >= 8 else 0
            reason = answer[8:8 + size].decode("utf-8", "replace") if size else "push failed"
            raise AdbError(f"sync push failed: {reason}")
        try:
            sync(b"QUIT")
            sync_ack()
        except (AdbError, AdbTimeout):
            pass  # устройство уже закрыло поток — не критично

    def _drain_sync(self, local_id: int, remaining) -> None:
        """Забирает готовые OKAY-подтверждения adbd во время передачи.

        adbd шлёт OKAY на каждый WRTE. Если клиент не читает их в процессе
        отправки, на больших файлах приёмный TCP-буфер заполняется:
        adbd блокируется на отправке очередного OKAY, перестаёт принимать
        DATA — передача замирает навсегда (классический sync-deadlock).
        Здесь неблокирующе (select) забираем то, что уже пришло; полный
        разбор хвоста делает sync_ack после DONE.
        """
        if not self.sock:
            return
        readable, _, _ = select.select([self.sock], [], [], 0)
        if not readable:
            return
        message = self._recv(remaining())
        if message.cmd == A_CLSE and message.arg1 == local_id:
            raise AdbError("sync stream closed unexpectedly")
        if message.cmd == A_WRTE and message.arg1 == local_id:
            self._send(A_OKAY, local_id, message.arg0)
        # A_OKAY (и прочее) — учтено, продолжаем отправку

    # ------------------------------------------------------------- транспорт
    def _send(self, cmd: int, arg0: int, arg1: int, data: bytes = b""):
        payload = encode_message(cmd, arg0, arg1, data)
        try:
            self.sock.sendall(payload)
        except OSError as exc:
            raise AdbError(f"send: {exc}") from exc

    def _recv(self, timeout: float) -> _Message:
        self.sock.settimeout(timeout)
        header = _read_exact(self.sock, 24)
        cmd, arg0, arg1, length, crc, magic = struct.unpack("<IIIIII", header)
        if cmd ^ 0xFFFFFFFF != magic or length > _MAX_RECV:
            # Рассинхронизация потока — дальше читать бессмысленно.
            raise AdbError("corrupted packet header")
        data = _read_exact(self.sock, length) if length else b""
        if data and checksum(data) != crc:
            # НЕ отбрасываем пакет. Официальный adb проверку суммы полученных
            # пакетов тоже фактически игнорирует (check_data() в adb.cpp
            # только логирует несовпадение). Часть прошивок — прежде всего
            # ТВ-приставки с модифицированными сборками adbd — шлёт заведомо
            # неверные суммы при корректных данных; раньше из-за этого
            # соединение падало с «corrupted packet payload».
            self.bad_checksums += 1
        return _Message(cmd, arg0, arg1, data)


def _now() -> float:
    return time.monotonic()


# ------------------------------------------------------------- высокоуровневое
def query_device(ip: str, port: int = 5555, timeout: float = 8.0,
                 create_keys: bool = True) -> "tuple[dict[str, str], str]":
    """Опрашивает устройство, возвращает (свойства, код_ошибки).

    Коды ошибок: '' — успех; 'unauthorized'; 'conn:<детали>'.
    """
    try:
        keypair = load_or_create_keys(create=create_keys)
    except Exception as exc:  # noqa: BLE001 — сбой генерации не должен ронять UI
        journal.error(f"{ip}:{port}", "poll/keygen", exc)
        return {}, f"conn:keygen failed: {exc}"
    device = AdbDevice(ip, port, timeout=timeout, keypair=keypair)
    try:
        device.connect(auth_timeout=max(timeout, 30.0))
    except AdbUnauthorized as exc:
        journal.error(f"{ip}:{port}", "poll/connect", exc)
        return {}, "unauthorized"
    except AdbTimeout as exc:
        journal.error(f"{ip}:{port}", "poll/connect", exc)
        return {}, f"conn:{exc}"
    except AdbError as exc:
        journal.error(f"{ip}:{port}", "poll/connect", exc)
        return {}, f"conn:{exc}"
    except OSError as exc:
        journal.error(f"{ip}:{port}", "poll/connect", exc)
        return {}, f"conn:{exc}"
    try:
        raw = device.get_properties(timeout=timeout)
        journal.event(f"{ip}:{port}", f"poll ok: {len(raw)} свойств")
        return _normalize(raw), ""
    except (AdbError, OSError) as exc:
        journal.error(f"{ip}:{port}", "poll/getprop", exc)
        return {}, f"conn:{exc}"
    finally:
        device.close()


_PROP_MAP = (
    ("ro.product.model", "model"),
    ("ro.product.brand", "brand"),
    ("ro.product.manufacturer", "manufacturer"),
    ("ro.product.name", "name"),
    ("ro.product.device", "device"),
    ("ro.build.version.release", "android_version"),
    ("ro.build.version.sdk", "sdk"),
    ("ro.build.version.security_patch", "security_patch"),
    ("ro.serialno", "serial"),
    ("ro.boot.serialno", "serial_boot"),
)


def _normalize(raw: "dict[str, str]") -> "dict[str, str]":
    """Оставляет только значимые свойства и переименовывает в ключи UI."""
    props = {}
    for src, dst in _PROP_MAP:
        value = (raw.get(src) or "").strip()
        if not value and src.startswith("ro.product."):
            # На старых Android имена вида ro.product.device.<product>
            suffix = src.rsplit(".", 1)[-1]
            for key, val in raw.items():
                if key.startswith("ro.product.") and key.endswith("." + suffix) and val.strip():
                    value = val.strip()
                    break
        if value and len(value) <= 120:
            props[dst] = value
    return props
