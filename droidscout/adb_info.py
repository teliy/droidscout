"""Опрос Android-устройства через ADB: встроенный клиент + внешний adb.

Приоритет источников (настраивается ключом adb_native в settings):
  1. Встроенный клиент (pure_adb): прямое TCP-соединение с adbd на порту
     5555. Не требует установленного Platform-Tools.
  2. Внешний adb (Platform-Tools): путь ищется adb_manager.find_adb() —
     настройка adb_path, каталог автоустановки или PATH.

Возвращает свойства в единых ключах UI: model, brand, android_version…
Коды ошибок: '' — успех; 'unauthorized' — устройство не подтвердило ключ;
'conn:<детали>' — не подключились; 'adb_missing' — нет ни клиента, ни adb.
"""

import re
import subprocess
from typing import Dict, Tuple

from . import adb_manager, config

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

PROP_RE = re.compile(r"^\[([^\]]+)\]:\s+\[(.*)\]$", re.M)

# Ключи UI -> свойства getprop (используются и встроенным клиентом,
# и резервным поштучным опросом внешнего adb)
GETPROP_KEYS = (
    ("ro.product.brand", "brand"),
    ("ro.product.manufacturer", "manufacturer"),
    ("ro.product.model", "model"),
    ("ro.product.name", "name"),
    ("ro.product.device", "device"),
    ("ro.build.version.release", "android_version"),
    ("ro.build.version.sdk", "sdk"),
    ("ro.build.version.security_patch", "security_patch"),
    ("ro.serialno", "serial"),
    ("ro.boot.serialno", "serial_boot"),
)

_PROP_MAP = {src: dst for src, dst in GETPROP_KEYS}


def normalize(raw: Dict[str, str]) -> Dict[str, str]:
    """[k]: [v]-словарь getprop -> словарь ключей UI."""
    props: Dict[str, str] = {}
    for src, dst in _PROP_MAP.items():
        value = (raw.get(src) or "").strip()
        if not value and src.startswith("ro.product."):
            # Старые Android: ro.product.<suffix>.<device_name>
            suffix = src.rsplit(".", 1)[-1]
            for key, val in raw.items():
                if key.startswith("ro.product.") and key.endswith("." + suffix) \
                        and val.strip():
                    value = val.strip()
                    break
        if value and len(value) <= 120:
            props[dst] = value
    return props


def find_adb():
    """Путь к внешнему adb или None."""
    return adb_manager.find_adb()


def adb_available() -> bool:
    return find_adb() is not None


def native_enabled() -> bool:
    return bool(config.get("adb_native", True))


def query_device(ip: str, adb_port: int = 5555, timeout: int = 20) -> Tuple[Dict[str, str], str]:
    """Возвращает (словарь свойств, код ошибки). Ошибка пуста при успехе."""
    errors = []
    if native_enabled():
        from . import pure_adb  # локальный импорт: модуль тяжёлый только при auth
        props, error = pure_adb.query_device(ip, port=adb_port, timeout=min(timeout, 12))
        if props:
            props["adb_source"] = "native"
            return props, ""
        errors.append(error)

    adb = find_adb()
    if not adb:
        return {}, "adb_missing" if not errors else errors[0]
    try:
        target = f"{ip}:{adb_port}"
        # Если ADB слушает на 5555 — сначала подключаемся
        subprocess.run([adb, "connect", target], capture_output=True, text=True,
                       timeout=timeout, creationflags=CREATE_NO_WINDOW)
        props = _getprop_batch(adb, target, timeout)
        if not props:
            props = _getprop(adb, target, timeout)
        if props:
            props["adb_source"] = "adb"
            return props, ""
        # Возможно, устройство уже в списке по TLS или USB
        props = _try_existing_serial(adb, ip, timeout)
        if props:
            props["adb_source"] = "adb"
            return props, ""
        return {}, "unauthorized"
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {}, f"conn:{exc}"


# ------------------------------------------------------------ внешний adb
def _clean_output(text: str) -> str:
    return (text or "").replace("\r\n", "\n").replace("\r", "\n")


def _getprop_batch(adb: str, target: str, timeout: int) -> Dict[str, str]:
    """Один запуск 'adb shell getprop' — сразу все свойства."""
    try:
        proc = subprocess.run([adb, "-s", target, "shell", "getprop"],
                              capture_output=True, text=True, timeout=timeout,
                              creationflags=CREATE_NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    if proc.returncode != 0 and not proc.stdout:
        return {}
    raw = dict(PROP_RE.findall(_clean_output(proc.stdout)))
    return normalize(raw)


def _getprop(adb: str, target: str, timeout: int) -> Dict[str, str]:
    """Поштучный опрос (резерв для нестандартных сборок adb)."""
    props: Dict[str, str] = {}
    for prop_key, out_key in GETPROP_KEYS:
        try:
            proc = subprocess.run([adb, "-s", target, "shell", "getprop", prop_key],
                                  capture_output=True, text=True, timeout=timeout,
                                  creationflags=CREATE_NO_WINDOW)
            value = _clean_output(proc.stdout).strip()
            if value and "[ ]" not in value:
                props[out_key] = value[:120]
        except (subprocess.TimeoutExpired, OSError):
            continue
    return props


def _try_existing_serial(adb: str, ip: str, timeout: int) -> Dict[str, str]:
    """Ищет среди уже подключённых adb-устройств устройство с данным IP."""
    try:
        proc = subprocess.run([adb, "devices", "-l"], capture_output=True, text=True,
                              timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    for line in _clean_output(proc.stdout).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and ip in parts[0]:
            props = _getprop_batch(adb, parts[0], timeout) or _getprop(adb, parts[0], timeout)
            if props:
                return props
    return {}
