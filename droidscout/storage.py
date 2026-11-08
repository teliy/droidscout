"""SQLite-хранилище истории сканирований."""

import os
import sqlite3
import time
from typing import Dict, List, Tuple

from . import config

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    network TEXT NOT NULL,
    total INTEGER NOT NULL,
    android INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT, mac TEXT, hostname TEXT, vendor TEXT,
    device_type TEXT, model TEXT, manufacturer TEXT,
    is_android INTEGER, confidence INTEGER,
    ports TEXT, services TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);
"""


def db_path() -> str:
    return os.path.join(config.config_dir(), "history.db")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def save_scan(network: str, devices: List) -> int:
    """Сохраняет результаты сканирования, возвращает id сканирования."""
    android = sum(1 for d in devices if d.verdict == "android")
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (ts, network, total, android) VALUES (?, ?, ?, ?)",
            (time.time(), network, len(devices), android))
        scan_id = int(cur.lastrowid)
        conn.executemany(
            "INSERT INTO devices (scan_id, ip, mac, hostname, vendor, device_type,"
            " model, manufacturer, is_android, confidence, ports, services)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, d.ip, d.mac, d.hostname, d.vendor, d.device_type, d.model,
              d.manufacturer, 1 if d.verdict == "android" else 0, d.confidence,
              ",".join(str(p) for p in sorted(d.ports)),
              ",".join(sorted(d.services))) for d in devices])
    return scan_id


def seen_macs_and_ips() -> Tuple[set, set]:
    """MAC- и IP-адреса из всех прошлых сканирований (для пометки новых устройств)."""
    macs, ips = set(), set()
    if not os.path.exists(db_path()):
        return macs, ips
    try:
        with _connect() as conn:
            for mac, ip in conn.execute("SELECT DISTINCT mac, ip FROM devices"):
                if mac:
                    macs.add(mac)
                if ip:
                    ips.add(ip)
    except sqlite3.Error:
        pass
    return macs, ips


def list_scans(limit: int = 200) -> List[Dict]:
    if not os.path.exists(db_path()):
        return []
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, ts, network, total, android FROM scans ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error:
        return []


def scan_devices(scan_id: int) -> List[Dict]:
    try:
        with _connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM devices WHERE scan_id = ? ORDER BY ip", (scan_id,)).fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error:
        return []


def clear() -> None:
    with _connect() as conn:
        conn.executescript("DELETE FROM devices; DELETE FROM scans;")
