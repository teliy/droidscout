"""Избранное: устройства (главная таблица) и приложения (вкладка «Приложения»).

Хранится в settings.json через config (ключи fav_devices/fav_apps,
поэтому обязательно объявлены в config.DEFAULTS — иначе load() молча
теряет незнакомые ключи при старте). Модуль чистый, без Qt — покрыт
тестами scripts/test_model_utils.py.

Для устройства ключ — MAC, а без MAC (хост «только ping») — IP.
Звёздочка считается поставленной, если в списке есть И mac, И ip:
MAC часто появляется позже (ARP/deep scan), и избранное не должно
теряться из-за этого.
"""

import threading

from . import config

DEVICES_KEY = "fav_devices"
APPS_KEY = "fav_apps"

_lock = threading.Lock()


def _clean(item) -> str:
    return str(item or "").strip()


def load(key: str) -> list:
    """Список избранного по ключу (строки без дублей и пустых)."""
    value = config.get(key, [])
    if not isinstance(value, list):
        return []
    seen, result = set(), []
    for item in value:
        item = _clean(item)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def save(key: str, items) -> None:
    """Перезаписывает список избранного (с очисткой и без дублей)."""
    seen, result = set(), []
    for item in items or ():
        item = _clean(item)
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    config.set_key(key, result)


def is_favorite(key: str, item: str) -> bool:
    return _clean(item) in set(load(key))


def toggle(key: str, item: str) -> bool:
    """Добавляет/убирает элемент; True — теперь в избранном."""
    with _lock:
        items = load(key)
        item = _clean(item)
        if item in items:
            items.remove(item)
            result = False
        else:
            items.insert(0, item)
            result = True
        save(key, items)
        return result


def device_key(device) -> str:
    """Стабильный ключ устройства: MAC, а без MAC — IP."""
    mac = _clean(getattr(device, "mac", "") or "")
    return mac or _clean(getattr(device, "ip", "") or "")


def device_hit(favs, device) -> bool:
    """Есть ли устройство в избранном: совпадение по MAC или по IP."""
    favs = set(favs or ())
    mac = _clean(getattr(device, "mac", "") or "")
    ip = _clean(getattr(device, "ip", "") or "")
    return (bool(mac) and mac in favs) or (bool(ip) and ip in favs)


def device_remove_both(key: str, device) -> None:
    """Убирает устройство по обоим возможным ключам (MAC и IP)."""
    mac = _clean(getattr(device, "mac", "") or "")
    ip = _clean(getattr(device, "ip", "") or "")
    items = [item for item in load(key) if item not in (mac, ip)]
    save(key, items)
