"""Углублённый опрос устройства через adb (Android Platform-Tools).

Используется только по кнопке в GUI: если adb установлен и включён
«ADB по сети» (порт 5555), можно получить модель, версию Android и серийник.
"""

import shutil
import subprocess
from typing import Dict, Tuple

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

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


def adb_available() -> bool:
    return shutil.which("adb") is not None


def query_device(ip: str, adb_port: int = 5555, timeout: int = 20) -> Tuple[Dict[str, str], str]:
    """Возвращает (словарь свойств, текст ошибки). Ошибка пуста при успехе."""
    adb = shutil.which("adb")
    if not adb:
        return {}, "adb not found"
    target = f"{ip}:{adb_port}"
    try:
        # Если ADB слушает на 5555 — сначала подключаемся
        subprocess.run([adb, "connect", target], capture_output=True, text=True,
                       timeout=timeout, creationflags=CREATE_NO_WINDOW)
        props = _getprop(adb, target, timeout)
        if props:
            return props, ""
        # Возможно, устройство уже в списке по TLS или USB
        props = _try_existing_serial(adb, ip, timeout)
        if props:
            return props, ""
        return {}, "unauthorized or not connected"
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {}, str(exc)


def _getprop(adb: str, target: str, timeout: int) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for prop_key, out_key in GETPROP_KEYS:
        try:
            proc = subprocess.run([adb, "-s", target, "shell", "getprop", prop_key],
                                  capture_output=True, text=True, timeout=timeout,
                                  creationflags=CREATE_NO_WINDOW)
            value = (proc.stdout or "").strip()
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
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device" and ip in parts[0]:
            return _getprop(adb, parts[0], timeout)
    return {}
