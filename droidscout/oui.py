"""Загрузка сжатой базы IEEE OUI (производители MAC-адресов)."""

import csv
import gzip
import os
import threading
from typing import Dict, Optional, Tuple

_DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "manuf.tsv.gz")

_lock = threading.Lock()
_db: Dict[str, Tuple[str, str]] = {}
_android_prefixes: Dict[str, set] = {}

# Подстроки (без учёта регистра) длинных имён производителей из реестра IEEE,
# которые массово выпускают Android-устройства.
ANDROID_VENDOR_KEYS = (
    "samsung", "xiaomi", "redmi", "poco", "huawei", "hisilicon", "honor",
    "google", "oneplus", "oppo", "vivo", "realme", "motorola", "tcl",
    "sony", "lg electronics", "htc", "asustek", "asus", "zte", "nokia",
    "amazon", "nvidia", "amlogic", "rockchip", "allwinner", "skyworth",
    "hisense", "lenovo", "meizu", "leeco", "black shark", "nothing",
    "fairphone", "wiko", "alcatel", "tinnovation", "jolla", "general mobile",
    "bq ", "electrolux", "arcadyan", "actiontec", "pandora", "cachefly",
)


def _ensure_loaded() -> None:
    if _db:
        return
    with _lock:
        if _db:
            return
        try:
            with gzip.open(_DATA_FILE, "rt", encoding="utf-8", newline="") as gz:
                reader = csv.DictReader(gz, delimiter="\t")
                for row in reader:
                    prefix = (row.get("prefix") or "").strip().upper()
                    short = (row.get("short") or "").strip()
                    long_name = (row.get("long") or "").strip()
                    if len(prefix) == 8:
                        _db[prefix] = (short, long_name)
        except OSError:
            return
        # Индекс Android-релевантных вендоров: ключ -> множество префиксов
        for prefix, (_short, long_name) in _db.items():
            hay = long_name.lower()
            for key in ANDROID_VENDOR_KEYS:
                if key in hay:
                    _android_prefixes.setdefault(key, set()).add(prefix)
                    break


def normalize_mac(mac: str) -> str:
    """Приводит MAC к виду XX:XX:XX:XX:XX:XX (верхний регистр, ':')."""
    clean = "".join(ch for ch in mac if ch.isalnum()).upper()
    if len(clean) != 12 or not all(c in "0123456789ABCDEF" for c in clean):
        return ""
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def lookup_vendor(mac: str) -> Tuple[str, str]:
    """(short_name, long_name) по MAC; пустые строки, если MAC неизвестен."""
    _ensure_loaded()
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        return "", ""
    info = _db.get(mac_norm[:8])
    if not info:
        return "", ""
    return info[0], info[1] or info[0]


def android_vendor_match(mac: str) -> str:
    """Возвращает имя Android-производителя, если MAC ему принадлежит, иначе ''."""
    _ensure_loaded()
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        return ""
    prefix = mac_norm[:8]
    for key, prefixes in _android_prefixes.items():
        if prefix in prefixes:
            short, long_name = _db.get(prefix, ("", ""))
            return long_name or short or key
    return ""


def is_randomized_mac(mac: str) -> bool:
    """Локально администрируемый адрес (часто рандомизация Wi-Fi на телефонах)."""
    mac_norm = normalize_mac(mac)
    if not mac_norm:
        return False
    second_octet = int(mac_norm[3:5], 16)
    return bool(second_octet & 0x02)
