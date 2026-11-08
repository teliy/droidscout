"""Сетевой движок DroidScout: ICMP-опрос, ARP, TCP-порты, mDNS, SSDP, HTTP-баннеры.

Работает в отдельном QThread и сообщает о находках сигналами.
"""

import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional, Set, Tuple

import psutil

from PySide6.QtCore import QThread, Signal

from . import fingerprint, netprobe, oui
from .fingerprint import Device

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Порты, значимые для обнаружения Android и служб
SCAN_PORTS: Tuple[Tuple[int, str], ...] = (
    (5555, "adb"), (22, "ssh"), (23, "telnet"), (80, "http"), (443, "https"),
    (445, "smb"), (21, "ftp"), (631, "ipp"), (3689, "airplay"), (5000, "upnp"),
    (6466, "http"), (7000, "airplay"), (7100, "airplay"), (8008, "cast"),
    (8009, "cast"), (8080, "http"), (8081, "http"), (8443, "https"),
    (8554, "rtsp"), (9000, "http"), (9100, "ipp"), (36669, "http"),
    (49152, "upnp"), (49153, "upnp"), (49154, "upnp"),
    (3389, "rdp"), (5900, "vnc"), (32400, "http"),
)

MDNS_TYPES: Tuple[str, ...] = (
    "_googlecast._tcp.local.",
    "_androidtvremote2._tcp.local.",
    "_androidtvremote._tcp.local.",
    "_adb-tls-connect._tcp.local.",
    "_adb-tls-pairing._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
)

SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_ST_LIST = ("ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:MediaRenderer:1")


# ---------------------------------------------------------------- сети хоста

def local_networks() -> List[Tuple[str, str]]:
    """[(имя интерфейса, 'a.b.c.d/nn')] для всех IPv4-подсетей хоста."""
    result: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    try:
        addrs = psutil.net_if_addrs()
    except (OSError, ValueError):
        return result
    for nic, addr_list in addrs.items():
        for addr in addr_list:
            family = getattr(addr, "family", None)
            if family not in (socket.AF_INET, 2):
                continue
            ip, mask = addr.address, addr.netmask
            if not ip or not mask or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            if net.num_addresses < 4 or net.num_addresses > 65536:
                continue
            if str(net) in seen:
                continue
            seen.add(str(net))
            result.append((nic, str(net)))
    return result


# ------------------------------------------------------------------- утилиты

def _ping(ip: str, timeout_ms: int) -> Tuple[bool, int]:
    """Один ICMP-запрос. Возвращает (жив, ttl из ответа; 0 — не разобрать)."""
    sysname = platform.system().lower()
    if sysname == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif sysname == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(max(1000, timeout_ms)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors="replace", timeout=timeout_ms / 1000 + 2.5,
                              creationflags=CREATE_NO_WINDOW)
        if proc.returncode != 0:
            return False, 0
        return True, netprobe.parse_ping_ttl(proc.stdout or "")
    except (subprocess.TimeoutExpired, OSError):
        return False, 0


def read_arp_table() -> Dict[str, str]:
    """Читает ARP-таблицу ОС: {ip: mac}."""
    table: Dict[str, str] = {}
    sysname = platform.system().lower()
    try:
        if sysname == "linux" and os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", encoding="utf-8") as f:
                for row in f.readlines()[1:]:
                    parts = row.split()
                    if len(parts) >= 6:
                        ip, mac = parts[0], parts[3]
                        if _valid_mac(mac):
                            table[ip] = oui.normalize_mac(mac)
        else:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                                 timeout=5, creationflags=CREATE_NO_WINDOW).stdout or ""
            for line in out.splitlines():
                ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                mac_m = re.search(r"([0-9a-fA-F]{1,2}[-:]){5}[0-9a-fA-F]{1,2}", line)
                if ip_m and mac_m:
                    mac = mac_m.group(0).replace("-", ":")
                    norm = oui.normalize_mac(mac)
                    if norm:
                        table[ip_m.group(1)] = norm
    except (OSError, subprocess.TimeoutExpired):
        pass
    if sysname == "linux":
        try:
            out = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True,
                                 timeout=5).stdout or ""
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[1] in ("lladdr", "") and _valid_mac(parts[4]):
                    table.setdefault(parts[0], oui.normalize_mac(parts[4]))
        except (OSError, subprocess.TimeoutExpired):
            pass
    return table


def _valid_mac(mac: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F:]{17}", mac)) and mac != "00:00:00:00:00:00"


def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def _http_banner(ip: str, port: int, timeout: float) -> str:
    """Заголовок Server и <title> со страницы http://ip:port/."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: DroidScout/1\r\n\r\n"
                         % ip.encode())
            chunks = []
            received = 0
            while received < 4096:
                part = sock.recv(1024)
                if not part:
                    break
                chunks.append(part)
                received += len(part)
            data = b"".join(chunks).decode("latin-1", "replace")
    except OSError:
        return ""
    server_m = re.search(r"^Server:\s*(.+)$", data, re.MULTILINE | re.IGNORECASE)
    title_m = re.search(r"<title[^>]*>(.*?)</title>", data, re.IGNORECASE | re.DOTALL)
    parts = []
    if server_m:
        parts.append("Server: " + server_m.group(1).strip()[:120])
    if title_m:
        title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:160]
        if title:
            parts.append("Title: " + title)
    return " | ".join(parts)


def _reverse_dns(ip: str) -> str:
    try:
        host, _aliases, _addr = socket.gethostbyaddr(ip)
        return host.split(".")[0] if host else ""
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------- mDNS

class _MDNSListener:
    """Собирает результаты ServiceBrowser по нескольким типам служб."""

    def __init__(self, store: Dict[str, Device], lock: threading.Lock):
        self.store = store
        self.lock = lock
        self.zc = None

    def add_service(self, zc, type_, name) -> None:  # noqa: ANN001
        try:
            info = zc.get_service_info(type_, name, timeout=2500)
        except Exception:  # noqa: BLE001
            return
        if info is None:
            return
        ips = [a for a in info.parsed_addresses() if ":" not in a]
        if not ips:
            return
        ip = ips[0]
        props = {}
        for key, value in (info.properties or {}).items():
            key_d = key.decode("latin-1", "replace") if isinstance(key, bytes) else str(key)
            val_d = value.decode("utf-8", "replace") if isinstance(value, bytes) else ("" if value is None else str(value))
            props[key_d.lower()] = val_d
        name_clean = name.split(".", 1)[0].replace("\\032", " ").replace("._", "")

        dev = Device(ip=ip)
        low = type_.lower()
        if "googlecast" in low:
            dev.services.add("cast")
            dev.model = props.get("md", "") or props.get("fn", "")
            dev.manufacturer = "Google"
            dev.hostname = props.get("fn", "") or name_clean
            dev.extras["cast_id"] = props.get("id", "")
        elif "androidtvremote" in low:
            dev.services.add("tvremote")
            dev.hostname = name_clean
        elif "adb-tls" in low:
            dev.services.add("adb_tls")
            dev.hostname = name_clean
        elif "airplay" in low or "raop" in low:
            dev.services.add("airplay")
            dev.model = props.get("am", "") or dev.model
            dev.hostname = props.get("fn", "") or name_clean
            if props.get("manufacturer"):
                dev.manufacturer = props["manufacturer"]
        with self.lock:
            existing = self.store.get(ip)
            if existing is None:
                self.store[ip] = dev
            else:
                existing.merge(dev)

    def update_service(self, zc, type_, name) -> None:  # noqa: ANN001
        self.add_service(zc, type_, name)

    def remove_service(self, zc, type_, name) -> None:  # noqa: ANN001
        pass


def _mdns_discovery(store: Dict[str, Device], lock: threading.Lock,
                    window_sec: float, stop: threading.Event) -> None:
    try:
        from zeroconf import ServiceBrowser, Zeroconf
    except ImportError:
        return
    zc = Zeroconf()
    listener = _MDNSListener(store, lock)
    listener.zc = zc
    browsers = []
    try:
        for mdns_type in MDNS_TYPES:
            browsers.append(ServiceBrowser(zc, mdns_type, listener))
        deadline = time.monotonic() + window_sec
        while time.monotonic() < deadline and not stop.is_set():
            stop.wait(0.2)
    finally:
        try:
            zc.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------- SSDP

def _ssdp_discovery(store: Dict[str, Device], lock: threading.Lock,
                    window_sec: float, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(0.5)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind(("", 0))
    except OSError:
        sock.close()
        return
    locations: Set[str] = set()
    try:
        for st in SSDP_ST_LIST:
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                   f"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n").encode()
            try:
                sock.sendto(msg, SSDP_ADDR)
            except OSError:
                continue
        deadline = time.monotonic() + window_sec
        while time.monotonic() < deadline and not stop.is_set():
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            head = data.decode("latin-1", "replace")
            loc_m = re.search(r"(?im)^LOCATION:\s*(\S+)", head)
            if loc_m:
                locations.add(loc_m.group(1).strip())
    finally:
        sock.close()

    # Скачиваем и разбираем XML-описания устройств
    for url in list(locations)[:60]:
        if stop.is_set():
            break
        dev = _fetch_ssdp_xml(url)
        if dev is None:
            continue
        with lock:
            existing = store.get(dev.ip)
            if existing is None:
                store[dev.ip] = dev
            else:
                existing.merge(dev)


def _fetch_ssdp_xml(url: str) -> Optional[Device]:
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            xml_text = resp.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError):
        return None
    host_m = re.match(r"https?://([^/:]+)", url)
    if not host_m or not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_m.group(1)):
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    device_el = root.find(".//{urn:schemas-upnp-org:device-1-0}device")
    if device_el is None:
        # поиск без учёта пространства имён
        for el in root.iter():
            if el.tag.endswith("}device") or el.tag == "device":
                device_el = el
                break
    if device_el is None:
        return None

    def text(tag: str) -> str:
        for el in device_el.iter():
            if el.tag.endswith("}" + tag) or el.tag == tag:
                return (el.text or "").strip()
        return ""

    dev = Device(ip=host_m.group(1))
    dev.services.add("upnp")
    friendly = text("friendlyName")
    manufacturer = text("manufacturer")
    model = text("modelName")
    dtype = text("deviceType")
    bits = [b for b in (manufacturer, model, friendly) if b]
    dev.ssdp_info = " / ".join(dict.fromkeys(bits))[:200]
    dev.manufacturer = manufacturer
    dev.model = model or friendly
    if friendly and not dev.hostname:
        dev.hostname = friendly
    if "mediarenderer" in dtype.lower() or "mediastreamer" in dtype.lower():
        dev.evidence.append("UPnP MediaRenderer")
    return dev


# --------------------------------------------------------------- сам движок

class ScanEngine(QThread):
    """Фоновое сканирование сети. Использование:

        engine = ScanEngine(["192.168.1.0/24"])
        engine.device_found.connect(on_device)
        engine.progress.connect(on_progress)
        engine.finished_scan.connect(on_done)
        engine.start()
    """

    device_found = Signal(object)            # Device
    progress = Signal(str, int, int)         # сообщение, готово, всего
    finished_scan = Signal(list)             # список Device

    def __init__(self, networks: List[str], deep: bool = True,
                 host_timeout_ms: int = 1500, parent=None):
        super().__init__(parent)
        self.networks = networks
        self.deep = deep
        self.host_timeout_ms = host_timeout_ms
        self._stop = threading.Event()

    # Управление -----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def targets(self) -> List[str]:
        ips: List[str] = []
        for net_str in self.networks:
            try:
                net = ipaddress.ip_network(net_str, strict=False)
            except ValueError:
                continue
            if net.num_addresses > 65536:
                continue
            for host in net.hosts():
                ips.append(str(host))
        return ips

    # Основной цикл --------------------------------------------------------
    def run(self) -> None:
        started = time.monotonic()
        store: Dict[str, Device] = {}
        lock = threading.Lock()

        targets = self.targets()
        if not targets:
            self.finished_scan.emit([])
            return

        # Проверяем, работает ли ICMP (нет прав/брандмауэр) — тогда зондируем
        # все адреса напрямую по TCP.
        ping_works = _ping("127.0.0.1", min(1000, self.host_timeout_ms))

        # 1. mDNS и SSDP параллельно с пинг-опросом
        if self.deep:
            stop_mdns = threading.Event()
            stop_ssdp = threading.Event()
            thread_mdns = threading.Thread(target=_mdns_discovery,
                                           args=(store, lock, 6.0, stop_mdns), daemon=True)
            thread_ssdp = threading.Thread(target=_ssdp_discovery,
                                           args=(store, lock, 5.0, stop_ssdp), daemon=True)
            thread_mdns.start()
            thread_ssdp.start()

        # 2. Ping-опрос подсети
        ttl_map: Dict[str, int] = {}
        if ping_works:
            alive: List[str] = []
            total = len(targets)
            done = 0
            with ThreadPoolExecutor(max_workers=min(128, total or 1)) as pool:
                futures = {pool.submit(_ping, ip, self.host_timeout_ms): ip for ip in targets}
                for future in as_completed(futures):
                    if self._stop.is_set():
                        break
                    done += 1
                    if done % 8 == 0 or done == total:
                        self.progress.emit("phase_ping", done, total)
                    ok, ttl = future.result()
                    if ok:
                        alive.append(futures[future])
                        if ttl:
                            ttl_map[futures[future]] = ttl
        else:
            # ICMP недоступен — проверяем порты у всех адресов подсети
            alive = list(targets)

        # hosts, найденные через mDNS/SSDP, но не ответившие на ping — тоже проверяем
        with lock:
            extra = [ip for ip in store if ip not in set(alive)]
        alive.extend(extra)

        if self._stop.is_set():
            self.progress.emit("scan_stopped", 0, 0)
            self.finished_scan.emit(self._collect(store, lock))
            return

        # 3. ARP-таблица после опроса
        arp = read_arp_table()

        # 4. Полное зондирование каждого живого хоста
        results: Dict[str, Device] = {}
        done = 0
        total_hosts = len(alive)
        self.progress.emit("phase_ports", 0, total_hosts)

        def probe(ip: str) -> Optional[Device]:
            return self._probe_host(ip, arp, ttl_map.get(ip, 0))

        with ThreadPoolExecutor(max_workers=min(64, total_hosts or 1)) as pool:
            futures = {pool.submit(probe, ip): ip for ip in alive}
            for future in as_completed(futures):
                done += 1
                self.progress.emit("phase_ports", done, total_hosts)
                if self._stop.is_set():
                    continue
                try:
                    device = future.result()
                except Exception:  # noqa: BLE001
                    continue
                if device is None:
                    continue
                results[device.ip] = device
                self.device_found.emit(device)

        # 5. Даём mDNS/SSDP собрать остатки и мерджим их результаты
        if self.deep:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not self._stop.is_set():
                self._stop.wait(0.2)
            with lock:
                for ip, mdns_dev in store.items():
                    base = results.get(ip) or Device(ip=ip)
                    base.merge(mdns_dev)
                    results[ip] = fingerprint.classify(base)
                    self.device_found.emit(results[ip])

        self.progress.emit("phase_finish", 0, 0)
        final = self._collect(store, lock, results)
        self.progress.emit("phase_done", int(time.monotonic() - started), 0)
        self.finished_scan.emit(final)

    # Зондирование одного хоста --------------------------------------------
    def _probe_host(self, ip: str, arp: Dict[str, str], ttl: int = 0) -> Optional[Device]:
        if self._stop.is_set():
            return None
        device = Device(ip=ip)
        port_timeout = 0.4

        with ThreadPoolExecutor(max_workers=len(SCAN_PORTS)) as pool:
            futures = {pool.submit(_tcp_connect, ip, port, port_timeout): (port, label)
                       for port, label in SCAN_PORTS}
            for future in as_completed(futures):
                port, label = futures[future]
                if future.result():
                    device.ports.add(port)
                    device.services.add(label)

        if not device.ports:
            # хост жив по ping, но порты закрыты — всё равно показываем
            device.evidence.append("Отвечает на ICMP ping")
        device.ttl = ttl

        device.mac = arp.get(ip, "")
        if device.mac:
            device.vendor = oui.lookup_vendor(device.mac)[1]

        if self._stop.is_set():
            return device

        # HTTP-баннер
        for port in (80, 8080, 8081, 6466, 36669, 9000):
            if port in device.ports:
                banner = _http_banner(ip, port, 1.5)
                if banner:
                    device.http_banner = banner
                    break

        # Обратный DNS
        device.hostname = _reverse_dns(ip)

        return fingerprint.classify(device)

    # Финальный список -------------------------------------------------------
    def _collect(self, store: Dict[str, Device], lock: threading.Lock,
                 results: Optional[Dict[str, Device]] = None) -> List[Device]:
        results = results or {}
        with lock:
            for ip, mdns_dev in store.items():
                base = results.get(ip) or Device(ip=ip)
                base.merge(mdns_dev)
                results[ip] = fingerprint.classify(base)
        devices = sorted(results.values(), key=lambda d: tuple(int(p) for p in d.ip.split(".")))
        return devices
