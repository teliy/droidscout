"""Экспорт результатов сканирования в CSV и JSON."""

import csv
import json
from typing import List

from .fingerprint import Device


def _rows(devices: List[Device]) -> List[dict]:
    return [{
        "ip": d.ip,
        "mac": d.mac,
        "vendor_mac": d.vendor,
        "hostname": d.hostname,
        "device_type": d.device_type,
        "model": d.model,
        "manufacturer": d.manufacturer,
        "verdict": d.verdict,
        "confidence": d.confidence,
        "ports": ";".join(str(p) for p in sorted(d.ports)),
        "services": ";".join(sorted(d.services)),
        "ttl": d.ttl or "",
        "http_banner": d.http_banner,
        "upnp": d.ssdp_info,
        "is_new": d.is_new,
    } for d in devices]


def export_csv(path: str, devices: List[Device]) -> None:
    """CSV с разделителем ';' и BOM — корректно открывается в Excel."""
    rows = _rows(devices)
    fieldnames = list(rows[0].keys()) if rows else ["ip"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def export_json(path: str, devices: List[Device]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"devices": _rows(devices)}, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------- приложения
# Выгрузка списка установленных приложений — для разбора «нужности» и
# безопасности вручную или в ИИ. Имена полей машинные (латиница) — их
# удобно скармливать модели без пояснений.
APPS_FIELDS = ["package", "origin", "version", "version_code", "min_sdk",
               "target_sdk", "enabled", "apk_path", "first_install",
               "last_update", "permissions"]


def _app_rows(apps: List[dict]) -> List[dict]:
    """dict из adb_actions.collect_apps -> плоская строка для CSV/JSON."""
    return [{
        "package": a.get("package", ""),
        "origin": a.get("origin", ""),          # system | third | ''
        "version": a.get("version", ""),
        "version_code": a.get("code", ""),
        "min_sdk": a.get("min_sdk", ""),
        "target_sdk": a.get("target_sdk", ""),
        "enabled": a.get("enabled", ""),        # yes | no | ''
        "apk_path": a.get("path", ""),
        "first_install": a.get("installed", ""),
        "last_update": a.get("updated", ""),
        "permissions": "|".join(a.get("permissions") or []),
    } for a in apps]


def export_apps_csv(path: str, apps: List[dict]) -> None:
    """CSV с разделителем ';' и BOM — корректно открывается в Excel."""
    rows = _app_rows(apps)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=APPS_FIELDS, delimiter=";")
        writer.writeheader()
        writer.writerows(rows)


def export_apps_json(path: str, apps: List[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"apps": _app_rows(apps)}, f, ensure_ascii=False, indent=2)
