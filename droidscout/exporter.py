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
