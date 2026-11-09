"""Загрузка и сохранение настроек DroidScout (JSON в каталоге конфигурации ОС)."""

import json
import os
import threading
from typing import Any, Dict

APP_DIR_NAME = "DroidScout"

DEFAULTS: Dict[str, Any] = {
    "language": "auto",          # auto | ru | en
    "theme": "dark",             # dark | light
    "check_updates_on_start": True,
    "repo_owner": "",            # пусто -> берётся из _repo.json / значения по умолчанию
    "repo_name": "droidscout",
    "github_token": "",          # нужен, пока репозиторий приватный
    "last_update_check": 0,      # unix ts
    "deep_scan": True,
    "scan_timeout_ms": 1500,
    "adb_native": True,          # встроенный ADB-клиент (без platform-tools)
    "adb_path": "",              # путь к внешнему adb; пусто -> автопоиск
    "fav_devices": [],           # избранные устройства (MAC, либо IP без MAC)
    "fav_apps": [],              # избранные приложения (имена пакетов)
}

_lock = threading.Lock()
_cache: Dict[str, Any] = {}


def config_dir() -> str:
    """Каталог конфигурации с учётом ОС."""
    if os.name == "nt":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        path = os.path.join(base, APP_DIR_NAME)
    elif sys_platform() == "darwin":
        path = os.path.join(os.path.expanduser("~"), "Library", "Application Support", APP_DIR_NAME)
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.join(os.path.expanduser("~"), ".config"))
        path = os.path.join(base, APP_DIR_NAME.lower())
    os.makedirs(path, exist_ok=True)
    return path


def sys_platform() -> str:
    import platform
    return platform.system().lower()


def config_path() -> str:
    return os.path.join(config_dir(), "settings.json")


def load() -> Dict[str, Any]:
    global _cache
    with _lock:
        if _cache:
            return dict(_cache)
        data = dict(DEFAULTS)
        try:
            with open(config_path(), encoding="utf-8") as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                for key in DEFAULTS:
                    if key in stored:
                        data[key] = stored[key]
        except (OSError, ValueError):
            pass
        _cache = data
        return dict(data)


def save(values: Dict[str, Any]) -> None:
    global _cache
    with _lock:
        _cache.update(values)
        tmp = config_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, config_path())


def get(key: str, default: Any = None) -> Any:
    return load().get(key, DEFAULTS.get(key, default))


def set_key(key: str, value: Any) -> None:
    save({key: value})
