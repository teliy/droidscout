"""Сетевые зонды DroidScout: TTL, глубокий скан портов, распознавание сервисов.

Дополнительно: Wake-on-LAN и UDP-разведка (mDNS, SSDP, SNMP, NetBIOS).
Модуль не зависит от Qt — только стандартная библиотека, покрыт тестами
(scripts/test_netprobe.py).

Принципы:
  * scan_all_ports() — TCP connect-скан всех 65535 портов через пул потоков;
  * probe_port()     — «поговорить» с открытым портом: сначала читаем баннер,
    затем шлём протокольные зонды (HTTP/RTSP/Redis), распознаём сервис;
  * classify_banner()— чистая функция: байты ответа -> (протокол, описание).
"""

import re
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from typing import Callable, Dict, List, Optional, Tuple

# --------------------------------------------------------------- TTL / ping

_TTL_RE = re.compile(r"(?i)\bttl[=: ]\s*(\d+)")


def parse_ping_ttl(output: str) -> int:
    """Извлекает TTL из вывода ping (Windows/Linux/macOS). 0 — не найден."""
    match = _TTL_RE.search(output or "")
    return int(match.group(1)) if match else 0


# Базовый TTL популярных стеков: 64 — Linux/Unix/встраиваемые, 128 — Windows,
# 255 — часть сетевого железа. Ответ приходит уменьшенным на число хопов (в
# локальной сети — 0..1), поэтому допускаем окно.
TTL_WINDOWS = range(113, 137)
TTL_LINUX = range(49, 81)
TTL_NETWORK = range(225, 256)


def ttl_guess(ttl: int) -> str:
    """'windows' | 'linux' | 'network' | '' — категория по значению TTL."""
    if not ttl:
        return ""
    if ttl in TTL_WINDOWS:
        return "windows"
    if ttl in TTL_NETWORK:
        return "network"
    if ttl in TTL_LINUX:
        return "linux"
    # вне типичных значений — ближайшее предположение
    if ttl > 136:
        return "network"
    return "linux"


TTL_LABELS = {
    "windows": ("Windows-подобная ОС", "Windows-like OS"),
    "linux": ("Linux/встраиваемая система", "Linux/embedded"),
    "network": ("сетевое оборудование", "network equipment"),
}


def ttl_evidence(ttl: int, lang: str = "ru") -> str:
    """Строка признака вида 'TTL 128: Windows-подобная ОС'."""
    guess = ttl_guess(ttl)
    if not guess:
        return f"TTL {ttl}"
    label = TTL_LABELS[guess][0 if lang == "ru" else 1]
    return f"TTL {ttl}: {label}"


# ------------------------------------------------------ глубокий скан портов

def scan_all_ports(ip: str, port_range: Tuple[int, int] = (1, 65535),
                   timeout: float = 0.35, workers: int = 600,
                   progress: "Optional[Callable[[int, int], None]]" = None,
                   stop: Optional[threading.Event] = None,
                   deadline_sec: float = 240.0) -> List[int]:
    """TCP connect-скан полного диапазона портов.

    Возвращает список открытых портов. progress(done, total) — для прогресса,
    stop (threading.Event) — прервать. На «молчащих» (firewall) хостах весь
    диапазон занимает до deadline_sec, на обычной LAN — секунды.
    """
    lo, hi = port_range
    total = hi - lo + 1
    if total <= 0:
        return []
    opened: List[int] = []
    lock = threading.Lock()
    done = [0]
    started = time.monotonic()

    def sweep(port: int) -> None:
        if stop is not None and stop.is_set():
            return
        if time.monotonic() - started > deadline_sec:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                ok = sock.connect_ex((ip, port)) == 0
            finally:
                sock.close()
        except OSError:
            ok = False
        with lock:
            done[0] += 1
            if ok:
                opened.append(port)
            if progress and (done[0] % 512 == 0 or done[0] == total):
                try:
                    progress(done[0], total)
                except Exception:  # noqa: BLE001 — прогресс не роняет скан
                    pass

    workers = max(1, min(workers, total))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(sweep, p) for p in range(lo, hi + 1)]
        for _fut in as_completed(futures):
            pass
    return sorted(set(opened))


# --------------------------------------------------- распознавание сервисов

# Протоколы, где сервер говорит первым (баннер сразу после connect)
SERVER_FIRST = {21, 22, 23, 25, 110, 119, 143, 465, 587, 993, 995, 5900, 6667}
# Порты, где ожидаем TLS
TLS_PORTS = {443, 465, 563, 614, 8443, 993, 995}
# Порты, куда осмысленно слать HTTP-запрос в первую очередь
HTTP_PORTS = {80, 81, 88, 591, 3128, 3000, 5000, 7000, 8000, 8008, 8080,
              8081, 8088, 8090, 8443, 8899, 9000, 9080, 9090, 32400, 36669,
              6466, 49152, 49153, 49154}
RTSP_PORTS = {554, 8554}

_HTTP_REQ = ("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DroidScout/1\r\n"
             "Accept: */*\r\nConnection: close\r\n\r\n")
_RTSP_REQ = ("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: DroidScout/1\r\n\r\n")


def _recv_some(sock, wait: float, limit: int = 2048) -> bytes:
    """Читает до limit байт, ожидая не дольше wait секунд."""
    chunks: List[bytes] = []
    size = 0
    deadline = time.monotonic() + wait
    sock.settimeout(max(0.05, wait))
    while size < limit and time.monotonic() < deadline:
        try:
            part = sock.recv(min(1024, limit - size))
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if not part:
            break
        chunks.append(part)
        size += len(part)
        # баннер получен — не ждём остаток окна
        if size >= 16:
            break
    return b"".join(chunks)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def classify_banner(port: int, raw: bytes) -> Tuple[str, str]:
    """Чистая функция: (протокол, краткое описание) по ответу порта.

    Возвращает протокол в нижнем регистре: http/https/ssh/ftp/smtp/pop3/imap/
    rtsp/vnc/telnet/redis/binary/tcp. Описание — первая строка/заголовки.
    """
    if not raw:
        return "tcp", ""
    first_line = raw.split(b"\n", 1)[0][:200]
    text_head = raw[:1024]

    if raw.startswith(b"SSH-"):
        return "ssh", first_line.decode("latin-1", "replace").strip()

    if raw.startswith(b"RFB "):
        return "vnc", first_line.decode("latin-1", "replace").strip()

    if raw.startswith((b"HTTP/", b"ICY ")):
        server = _header_value(raw, "Server")
        title = _html_title(raw)
        bits: List[str] = [first_line.decode("latin-1", "replace").strip()]
        if server:
            bits.append("Server: " + server)
        if title:
            bits.append("Title: " + title)
        return ("https" if port in TLS_PORTS else "http"), " | ".join(bits)

    if raw.startswith(b"RTSP/"):
        return "rtsp", first_line.decode("latin-1", "replace").strip()

    if raw.startswith(b"+OK"):
        return "pop3", first_line.decode("latin-1", "replace").strip()
    if raw.startswith(b"* OK") or raw.startswith(b"* BYE"):
        return "imap", first_line.decode("latin-1", "replace").strip()
    if raw.startswith(b"220") and (b"FTP" in text_head or port == 21):
        return "ftp", first_line.decode("latin-1", "replace").strip()
    if raw.startswith(b"220") and (b"ESMTP" in text_head or port in (25, 465, 587)):
        return "smtp", first_line.decode("latin-1", "replace").strip()
    if raw.startswith(b"+PONG") or (raw.startswith(b"-ERR") and port == 6379):
        return "redis", first_line.decode("latin-1", "replace").strip()
    if raw.startswith(b"NOTICE") or raw.startswith(b":"):  # IRC-подобные
        return "irc", first_line.decode("latin-1", "replace").strip()

    # telnet: IAC-последовательности или приглашение login
    if raw[:1] == b"\xff" or b"\xff\xfb" in raw[:64] or b"\xff\xfd" in raw[:64]:
        return "telnet", "IAC"
    low = raw.lower()
    if b"login:" in low or b"password:" in low or b"username:" in low:
        return "telnet", first_line.decode("latin-1", "replace").strip()[:120]

    if _printable_ratio(raw[:512]) < 0.7:
        return "binary", raw[:48].hex(" ")

    return "tcp", first_line.decode("latin-1", "replace").strip()[:160]


def _header_value(raw: bytes, name: str) -> str:
    match = re.search(rb"(?im)^" + name.encode() + rb":\s*(.+)\r?$", raw)
    return match.group(1).decode("latin-1", "replace").strip()[:120] if match else ""


def _html_title(raw: bytes) -> str:
    match = re.search(rb"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(rb"\s+", b" ", match.group(1)).decode("utf-8", "replace").strip()[:160]


def probe_port(ip: str, port: int, timeout: float = 2.5) -> Dict[str, object]:
    """«Поговорить» с открытым портом и распознать сервис.

    Возвращает словарь: port, proto ('' если ответа нет), detail, raw (bytes),
    tls, cert_cn, cert_issuer. Соединение закрывает.
    """
    result: Dict[str, object] = {"port": port, "proto": "", "detail": "",
                                 "raw": b"", "tls": False,
                                 "cert_cn": "", "cert_issuer": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as exc:
        result["detail"] = f"connect: {exc}"
        return result
    raw = b""
    try:
        sock.settimeout(timeout)
        if port in TLS_PORTS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls = ctx.wrap_socket(sock, server_hostname=ip)
                result["tls"] = True
                sock = tls
                der = tls.getpeercert(binary_form=True)
                if der:
                    cn, issuer = _cert_names(der)
                    result["cert_cn"], result["cert_issuer"] = cn, issuer
            except (ssl.SSLError, OSError) as exc:
                result["detail"] = "tls: " + str(exc)[:160]
                return result

        # 1) ждём баннер сервера
        raw = _recv_some(sock, 1.2 if port in SERVER_FIRST else 0.7)
        # 2) зонды по типу порта
        if not raw:
            if port in RTSP_PORTS:
                sock.sendall(_RTSP_REQ.encode())
            elif port == 6379:
                sock.sendall(b"PING\r\n")
            elif port in (23, 2323):
                sock.sendall(b"\r\n")
            else:
                sock.sendall(_HTTP_REQ.format(host=ip).encode())
            raw = _recv_some(sock, min(1.6, timeout))
        # 3) последний шанс: пустая строка (telnet-приглашение, странные службы)
        if not raw and port not in HTTP_PORTS and port not in TLS_PORTS:
            try:
                sock.sendall(b"\r\n")
                raw = _recv_some(sock, 0.8)
            except OSError:
                pass
    except OSError as exc:
        result["detail"] = str(exc)[:160]
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass

    proto, detail = classify_banner(port, raw)
    # HTTP-зонд попал в не-HTTP службу — не выдаём её за http
    if proto in ("http", "https") and not raw.startswith((b"HTTP/", b"ICY ")):
        proto, detail = "tcp", raw[:48].hex(" ") if raw else ""
    result["proto"] = proto
    result["detail"] = detail or result["detail"]
    result["raw"] = raw[:8192]
    return result


# --------------------------------------------------------------- сертификат

_OID_CN = b"\x55\x04\x03"     # 2.5.4.3  commonName
_OID_O = b"\x55\x04\x0a"      # 2.5.4.10 organizationName


def _der_value(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    """Читает TLV (multi-byte длины поддерживаются). Возвращает (tag, value, next)."""
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[offset:offset + nbytes], "big")
        offset += nbytes
    return tag, data[offset:offset + length], offset + length


def _cert_names(der: bytes) -> Tuple[str, str]:
    """Достаёт commonName издателя и субъекта из DER-сертификата (эвристика)."""
    def find_after(oid: bytes) -> List[str]:
        found: List[str] = []
        pos = 0
        while True:
            pos = der.find(oid, pos)
            if pos < 0:
                break
            pos += len(oid)
            try:
                _tag, value, _next = _der_value(der, pos)
                if value and _printable_ratio(value) > 0.5 and len(value) < 128:
                    found.append(value.decode("utf-8", "replace"))
            except (IndexError, struct.error):
                continue
        return found

    cn = find_after(_OID_CN)
    org = find_after(_OID_O)
    subject = (org[:1] + cn[:1]) if (cn or org) else []
    issuer_part = subject[0] if subject else ""
    owner = subject[-1] if len(subject) > 1 else issuer_part
    return owner or (cn[-1] if cn else ""), issuer_part


# ------------------------------------------------------------ UDP-разведка

def wake_on_lan(mac: str, broadcast: str = "255.255.255.255") -> None:
    """Отправляет magic packet (6x FF + 16x MAC) на UDP 9 и 7."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        raise ValueError("bad MAC: " + mac)
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(1.0)
        for port in (9, 7):
            try:
                sock.sendto(packet, (broadcast, port))
            except OSError:
                continue


def ssdp_probe(ip: str, timeout: float = 2.0) -> str:
    """Одноадресный M-SEARCH конкретному устройству. Возвращает ST/LOCATION."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").format(ip=ip)
    reply = _udp_exchange(ip, 1900, msg.encode(), timeout, repeats=2)
    if not reply:
        return ""
    lines = []
    for pattern, name in ((rb"(?im)^ST:\s*(.+)$", "ST"),
                          (rb"(?im)^LOCATION:\s*(.+)$", "LOCATION"),
                          (rb"(?im)^SERVER:\s*(.+)$", "SERVER")):
        match = re.search(pattern, reply)
        if match:
            lines.append(f"{name}: {match.group(1).decode('latin-1', 'replace').strip()[:160]}")
    return " | ".join(lines)


_MDNS_NAME = "_services._dns-sd._udp.local"


def mdns_probe(ip: str, timeout: float = 2.0) -> List[str]:
    """Unicast-mDNS запрос списка сервисных типов (PTR _services._dns-sd._udp.local)."""
    query = _dns_query(_MDNS_NAME, qtype=12)
    reply = _udp_exchange(ip, 5353, query, timeout, repeats=2)
    if not reply:
        return []
    try:
        names = _dns_parse_names(reply)
    except struct.error:
        return []
    out: List[str] = []
    for name in names:
        if (name.endswith("._tcp.local") or name.endswith("._udp.local")) \
                and not name.startswith(_MDNS_NAME) and name not in out:
            out.append(name)
    return out[:24]


def snmp_probe(ip: str, timeout: float = 2.0, community: str = "public") -> str:
    """SNMPv2c GET sysDescr.0. Пустая строка — устройство не отвечает."""
    request = _snmp_get(community, "1.3.6.1.2.1.1.1.0")
    reply = _udp_exchange(ip, 161, request, timeout)
    if not reply:
        return ""
    return _snmp_parse_sysdescr(reply)


def nbns_probe(ip: str, timeout: float = 2.0) -> List[str]:
    """NetBIOS Name Service: узнавание имён Windows-машин/NAS (порт 137/UDP)."""
    # NBNS node status request: имя '*' (0x2A) в first-level encoding RFC 1001:
    # 16 байт ('*' + 14 пробелов + суффикс 0x00) -> 'CK' + 'CA'*14 + 'AA'
    encoded = b"CK" + b"CA" * 14 + b"AA"
    assert len(encoded) == 32
    query = (b"\x00\x00"                # ID
             b"\x00\x00"                # flags: question
             b"\x00\x01\x00\x00\x00\x00\x00\x00"
             + b"\x20" + encoded + b"\x00" + b"\x21\x00" + b"\x00\x01")
    reply = _udp_exchange(ip, 137, query, timeout, repeats=2)
    if not reply or len(reply) < 57:
        return []
    names: List[str] = []
    try:
        num = struct.unpack(">H", reply[56:58])[0]
        offset = 58
        for _ in range(min(num, 32)):
            if offset + 18 > len(reply):
                break
            raw = reply[offset:offset + 15]
            suffix = reply[offset + 15]
            flags = struct.unpack(">H", reply[offset + 16:offset + 18])[0]
            offset += 18
            if not (flags & 0x8000):     # только имена, зарегистрированные узлом
                text = raw.decode("ascii", "replace").strip()
                if text:
                    names.append(f"{text}<{suffix:02X}>")
        return names
    except struct.error:
        return []


def _udp_exchange(ip: str, port: int, payload: bytes, timeout: float,
                  repeats: int = 1) -> bytes:
    """UDP запрос-ответ с повторами. Возвращает первый ответ или b''."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            for _ in range(max(1, repeats)):
                try:
                    sock.sendto(payload, (ip, port))
                except OSError:
                    return b""
                try:
                    data, _addr = sock.recvfrom(8192)
                    return data
                except (socket.timeout, TimeoutError):
                    continue
                except OSError:
                    return b""
    except OSError:
        pass
    return b""


# --------------------------------------------------------- DNS/SNMP кодеки

def _dns_labels(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        raw = part.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _dns_query(name: str, qtype: int, qclass: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return header + _dns_labels(name) + struct.pack(">HH", qtype, qclass)


def _dns_read_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumps = 0
    pos = offset
    end = pos
    while True:
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumps:
                end = pos
            break
        if length & 0xC0 == 0xC0:                 # сжатие: указатель
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            if not jumps:
                end = pos + 2
            jumps += 1
            if jumps > 16:
                break
            pos = pointer
            continue
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    return ".".join(labels), end


def _dns_parse_names(reply: bytes) -> List[str]:
    """Все имена из секций Answer/Additional."""
    _id, _flags, _qd, an, _ns, ar = struct.unpack(">HHHHHH", reply[:12])
    offset = 12
    for _ in range(_qd):
        _, offset = _dns_read_name(reply, offset)
        offset += 4
    names: List[str] = []
    for _ in range(min(an + ar, 64)):
        if offset >= len(reply):
            break
        _owner, offset = _dns_read_name(reply, offset)
        if offset + 10 > len(reply):
            break
        rtype, _class, _ttl, rdlen = struct.unpack(">HHIH", reply[offset:offset + 10])
        offset += 10
        if rtype in (12, 33, 1, 16) and offset + rdlen <= len(reply):
            if rtype == 12:                        # PTR
                target, _ = _dns_read_name(reply, offset)
                names.append(target)
            elif rtype == 16:                      # TXT
                pass
        offset += rdlen
    return names


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(value: int) -> bytes:
    if value == 0:
        return _ber_tlv(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")
    return _ber_tlv(0x02, raw)


def _snmp_get(community: str, oid: str) -> bytes:
    """SNMPv2c GetRequest-PDU."""
    oid_bytes = b""
    parts = [int(p) for p in oid.split(".")]
    oid_bytes += bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            oid_bytes += bytes([p])
        else:
            body = b""
            while p:
                body = bytes([(p & 0x7F) | 0x80]) + body
                p >>= 7
            oid_bytes += body
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, oid_bytes) + _ber_tlv(0x05, b""))
    varbinds = _ber_tlv(0x30, varbind)
    pdu = _ber_tlv(0xA0, _ber_int(1) + _ber_int(0) + _ber_int(0) + varbinds)
    message = _ber_tlv(0x30, _ber_int(1)                       # версия v2c
                       + _ber_tlv(0x04, community.encode()) + pdu)
    return message


def _snmp_parse_sysdescr(reply: bytes) -> str:
    """Достаёт Octet String (sysDescr) из GetResponse."""
    try:
        tag, message, _ = _der_value(reply, 0)
        if tag != 0x30:
            return ""
        pos = 0
        # версия, community
        for _ in range(2):
            _tag, _value, pos = _der_value(message, pos)
        tag, pdu, _ = _der_value(message, pos)
        if tag != 0xA2:      # не GetResponse
            return ""
        pos = 0
        for _ in range(3):   # request-id, error-status, error-index
            _tag, _value, pos = _der_value(pdu, pos)
        tag, varbinds, _ = _der_value(pdu, pos)
        if tag != 0x30:
            return ""
        tag, varbind, _ = _der_value(varbinds, 0)
        if tag != 0x30:
            return ""
        pos = 0
        _tag, _oid, pos = _der_value(varbind, pos)
        tag, value, _ = _der_value(varbind, pos)
        if tag == 0x04:
            return value.decode("utf-8", "replace")[:300]
        return ""
    except (IndexError, struct.error):
        return ""
