"""Модель устройства и эвристическая классификация Android-устройств."""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from . import i18n, netprobe, oui

# Пороги уверенности (0..100)
CONF_ANDROID = 60      # >= 60 — считается Android-устройством
CONF_LIKELY = 30       # >= 30 — вероятно Android


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""                # производитель по OUI
    hostname: str = ""
    model: str = ""                 # модель из mDNS/SSDP/ADB
    manufacturer: str = ""          # производитель из mDNS/SSDP/ADB
    device_type: str = "unknown"    # phone|tv|cast|box|pc|router|other|unknown
    confidence: int = 0             # 0..100
    verdict: str = "unknown"        # android|likely|no|unknown
    ports: Set[int] = field(default_factory=set)
    services: Set[str] = field(default_factory=set)   # adb, cast, tvremote, upnp, http...
    http_banner: str = ""
    ssdp_info: str = ""             # friendlyName/manufacturer/model из UPnP XML
    ttl: int = 0                    # TTL ping-ответа (признак ОС/класса устройства)
    evidence: List[str] = field(default_factory=list)
    extras: Dict[str, str] = field(default_factory=dict)
    seen_ts: float = field(default_factory=time.time)
    is_new: bool = False

    @property
    def ping_only(self) -> bool:
        """Хост доказал только отклик на ping: ни MAC, ни портов, ни имён,
        ни служб — идентифицировать нечего (строка-пустышка)."""
        return not (self.mac or self.ports or self.services or self.hostname
                    or self.model or self.manufacturer or self.ssdp_info
                    or self.extras)

    def merge(self, other: "Device") -> None:
        """Дополняет данные этого устройства данными из другого источника."""
        for src, dst in (("mac", "mac"), ("hostname", "hostname"),
                         ("model", "model"), ("manufacturer", "manufacturer"),
                         ("http_banner", "http_banner"), ("ssdp_info", "ssdp_info")):
            mine = getattr(self, dst)
            theirs = getattr(other, src)
            if not mine and theirs:
                setattr(self, dst, theirs)
        if not self.ttl and other.ttl:
            self.ttl = other.ttl
        self.ports |= other.ports
        self.services |= other.services
        for key, value in other.extras.items():
            self.extras.setdefault(key, value)
        for ev in other.evidence:
            if ev not in self.evidence:
                self.evidence.append(ev)


def mark_new(devices: List[Device], seen_macs: set, seen_ips: set) -> None:
    """Помечает устройства, которых не было в прошлых сканированиях.

    Пустышки «только ping» (нет ни MAC, ни портов, ни имён) новинками не
    считаются — иначе таблица после первого же скана становится сплошной
    зелёной.
    """
    for device in devices:
        if device.ping_only:
            device.is_new = False
            continue
        if device.mac and seen_macs:
            device.is_new = device.mac not in seen_macs
        else:
            device.is_new = bool(seen_ips) and device.ip not in seen_ips


def type_label(device_type: str) -> str:
    key = {
        "phone": "type_phone", "tv": "type_tv", "cast": "type_cast",
        "box": "type_box", "pc": "type_pc", "router": "type_router",
        "other": "type_other",
    }.get(device_type, "type_unknown")
    return i18n.tr(key)


def verdict_label(verdict: str) -> str:
    return i18n.tr({
        "android": "verdict_android", "likely": "verdict_likely",
        "no": "verdict_no", "unknown": "verdict_unknown",
    }.get(verdict, "verdict_unknown"))


def service_label(service: str) -> str:
    return i18n.tr("svc_" + service) if service else ""


# Ключевые слова в имени/модели, указывающие на телевизор или приставку
TV_KEYWORDS = (
    "tv", "chromecast", "bravia", "shield", "fire tv", "freetv", "aftbuild",
    "aft", "mi box", "mibox", "mibx", "redmi tv", "xiaomi tv", "google tv",
    "android tv", "adt-", "amlogic", "h96", "x96", "t95", "x88", "ugoos",
    "khadas", "odroid", "minix", "mecool", "homatics", "nokia streaming",
    "dune hd", "zidoo", "formuler", "mag ", "infomir", "el5200", "q7-",
)

# Производители, которые делают в основном телефоны/планшеты (без TV-портфеля)
PHONE_BRANDS = (
    "apple",  # для честного вердикта "не Android"
)
PHONE_ANDROID_BRANDS = (
    "oneplus", "realme", "vivo", "oppo", "honor", "meizu", "black shark",
    "nothing", "fairphone", "wiko", "alcatel", "google",
)


def _host_lower(device: Device) -> str:
    return " ".join(filter(None, (device.hostname, device.model,
                                  device.manufacturer, device.ssdp_info))).lower()


def classify(device: Device) -> Device:
    """Вычисляет confidence/verdict/device_type по собранным признакам."""
    evidence: List[str] = []
    score = 0
    host = _host_lower(device)

    # --- Службы и порты ---
    if "adb" in device.services or 5555 in device.ports:
        score += 45
        evidence.append("ADB 5555")
    if "adb_tls" in device.services:
        score += 45
        evidence.append("ADB TLS (mDNS)")
    if "cast" in device.services:
        score += 40
        evidence.append("Google Cast (mDNS)")
    if "tvremote" in device.services:
        score += 40
        evidence.append("Android TV Remote (mDNS)")
    if "airplay" in device.services:
        score += 5
        evidence.append("AirPlay")

    # --- mDNS/SSDP модель и производитель ---
    manuf = (device.manufacturer or "").lower()
    ssdp = (device.ssdp_info or "").lower()
    model = (device.model or "").lower()

    if any(k in manuf for k in ("google",)):
        score += 35
        evidence.append(f"UPnP/mDNS производитель: {device.manufacturer}")
    elif any(k in manuf for k in ("samsung", "xiaomi", "lg ", "tcl", "hisense",
                                  "sony", "philips", "skyworth", "amlogic")):
        score += 20
        evidence.append(f"UPnP/mDNS производитель: {device.manufacturer}")

    tv_hits = [k for k in TV_KEYWORDS if k in host]
    if tv_hits:
        score += 25
        evidence.append(f"Ключевые слова имени/модели: {', '.join(sorted(set(tv_hits))[:4])}")
    if model.startswith("aft") or "aftbuild" in model:
        score += 25  # Amazon Fire TV: модели AFT*, устройство представляется как AFTBuild
        evidence.append("Amazon Fire TV (модель AFT*)")

    # --- HTTP-баннер ---
    banner = (device.http_banner or "").lower()
    if "android" in banner:
        score += 35
        evidence.append("HTTP-баннер содержит 'Android'")
    elif "linux" in banner and ("upnp" in banner or "nanoservice" in banner or "busybox" in banner):
        score += 10
        evidence.append("HTTP-баннер: embedded Linux")

    # --- Имя хоста android-xxxx ---
    if device.hostname.lower().startswith("android-"):
        score += 30
        evidence.append("Имя хоста android-*")

    # --- Производитель MAC ---
    android_vendor = oui.android_vendor_match(device.mac)
    if android_vendor:
        score += 30
        evidence.append(f"MAC-производитель: {android_vendor}")
    elif device.mac and oui.is_randomized_mac(device.mac):
        evidence.append("Рандомизированный MAC (локальный бит)")
    elif device.mac and oui.lookup_vendor(device.mac)[0]:
        short, long_name = oui.lookup_vendor(device.mac)
        low = (short + " " + long_name).lower()
        if any(k in low for k in ("apple", "microsoft", "dell", "hp inc", "lenovo",
                                  "asustek com", "gigabyte", "micro-star", "intel ")):
            score -= 15
            evidence.append(f"MAC-производитель ПК: {long_name or short}")
        elif any(k in low for k in ("router", "cisco", "tplink", "tp-link", "mikrotik",
                                    "ubiquiti", "huawei technologies", "zte corp",
                                    "asustek", "netgear", "d-link", "xerox", "canon",
                                    " Brother".strip(), "kyocera", "ricoh")):
            score -= 5
            evidence.append(f"MAC-производитель: {long_name or short}")

    # --- ADB-детали (getprop) ---
    if device.extras.get("adb_version"):
        score += 50
        evidence.append("ADB getprop: Android " + device.extras["adb_version"])

    # --- TTL ping-ответа: класс ОС/устройства ---
    if device.ttl:
        evidence.append(netprobe.ttl_evidence(device.ttl, "ru"))

    device.confidence = max(0, min(100, score))

    if device.confidence >= CONF_ANDROID:
        device.verdict = "android"
    elif device.confidence >= CONF_LIKELY:
        device.verdict = "likely"
    else:
        device.verdict = "no" if device.confidence < 15 else "unknown"

    # --- Тип устройства ---
    is_tv_signal = bool(tv_hits) or "cast" in device.services or "tvremote" in device.services
    if "cast" in device.services and "chromecast" in host:
        device.device_type = "cast"
    elif is_tv_signal and (5555 in device.ports or "tvremote" in device.services
                           or "adb_tls" in device.services or device.extras.get("adb_version")):
        device.device_type = "tv"
    elif is_tv_signal or "amlogic" in host or "rockchip" in host or "allwinner" in host:
        device.device_type = "box"
    elif device.verdict in ("android", "likely") and not (445 in device.ports and 22 in device.ports):
        # Android-производитель без TV-признаков -> телефон/планшет
        vendor = (android_vendor or device.manufacturer or device.vendor).lower()
        if any(b in vendor for b in PHONE_ANDROID_BRANDS) or device.extras.get("adb_version"):
            device.device_type = "phone"
        elif device.vendor and not android_vendor:
            device.device_type = "other"
        else:
            device.device_type = "phone"
    elif 22 in device.ports or 3389 in device.ports or 445 in device.ports:
        device.device_type = "pc"
    elif 80 in device.ports or 443 in device.ports:
        device.device_type = "router"
    elif device.ttl:
        # нет других сигналов — грубая оценка по TTL
        guess = netprobe.ttl_guess(device.ttl)
        device.device_type = {"windows": "pc", "network": "router",
                              "linux": "other"}.get(guess, "other")
    else:
        device.device_type = "unknown" if device.verdict == "unknown" else "other"

    if device.verdict == "no" and device.device_type in ("phone", "tv", "box", "cast"):
        device.device_type = "other"

    # Заполняем vendor по OUI, если пусто
    if not device.vendor and device.mac:
        device.vendor = oui.lookup_vendor(device.mac)[1]
    # Локальные признаки classify переносим в устройство (раньше терялись)
    for ev in evidence:
        if ev not in device.evidence:
            device.evidence.append(ev)
    return device
