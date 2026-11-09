"""Диалог глубокого опроса: все 65535 TCP-портов + распознавание сервисов.

Стратегия «сначала быстрое», чтобы результаты были видны сразу:
  1. быстрый проход по QUICK_PORTS (1–1024 + популярные высокие) — секунды;
  2. распознавание найденных портов параллельно — строки появляются по мере
     готовности, каждая кликабельна и показывает сырой ответ (текст + hex);
  3. полный проход по оставшимся портам с процентами, скоростью и ETA;
  4. UDP-разведка по шагам: mDNS → SSDP → SNMP → NetBIOS — видно, какая проба
     выполняется прямо сейчас.

Найденное переносится в Device и в карточку устройства; отчёт можно
сохранить в текстовый файл, а ответы всех портов разом — скопировать
в буфер обмена одним текстом.
"""

import datetime
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from PySide6.QtCore import Qt, QThread, QTimer, Signal, QUrl
from PySide6.QtGui import QDesktopServices, QFont, QColor
from PySide6.QtWidgets import (QDialog, QFileDialog, QGridLayout, QHBoxLayout,
                               QHeaderView, QLabel, QPlainTextEdit, QProgressBar,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QVBoxLayout, QApplication, QGroupBox)

from .. import i18n, netprobe, repl_probe

# Протоколы, которые попадают в device.services (осмысленные службы)
_SERVICE_KEYS = {"http", "https", "ssh", "ftp", "smtp", "pop3", "imap",
                 "rtsp", "vnc", "telnet", "redis", "irc", "repl", "adb"}

# Цвета сервисов в таблице (подходят и для тёмной, и для светлой темы)
SERVICE_COLORS = {
    "http": "#3b82f6", "https": "#14b8a6", "ssh": "#22c55e", "ftp": "#f97316",
    "smtp": "#ec4899", "pop3": "#ec4899", "imap": "#ec4899", "rtsp": "#8b5cf6",
    "vnc": "#ef4444", "telnet": "#f43f5e", "redis": "#d97706", "irc": "#64748b",
    "repl": "#d946ef", "adb": "#06b6d4", "binary": "#64748b", "tcp": "#64748b",
}

_UDP_PROBES = (("mdns", "mDNS", netprobe.mdns_probe),
               ("ssdp", "SSDP", netprobe.ssdp_probe),
               ("snmp", "SNMP", netprobe.snmp_probe),
               ("nbns", "NetBIOS", netprobe.nbns_probe))


class DeepScanWorker(QThread):
    stage = Signal(str)                  # ключ фазы: quick/probe/full/udp
    progress = Signal(str, int, int)     # фаза, готово, всего
    port_result = Signal(object)         # dict из netprobe.probe_port
    udp_step = Signal(str, bool)         # ключ пробы, началась(True)/кончилась
    udp_result = Signal(str, object)     # ключ пробы, результат
    done = Signal(float, int)            # секунд, открытых портов
    failed = Signal(str)

    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    # -------------------------------------------------------------- пробы
    def _probe_one(self, port: int) -> dict:
        try:
            return netprobe.probe_port(self.ip, port)
        except Exception as exc:  # noqa: BLE001 — порт не должен ронять опрос
            return {"port": port, "proto": "", "detail": str(exc)[:120],
                    "raw": b"", "tls": False, "cert_cn": "", "cert_issuer": ""}

    def _probe_all(self, ports) -> None:
        """Распознаёт порты параллельно; результаты летят по мере готовности."""
        ports = list(ports)
        total = len(ports)
        if not total:
            return
        self.progress.emit("probe", 0, total)
        counter = [0]
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=min(12, total)) as pool:
            futures = [pool.submit(self._probe_one, port) for port in ports]
            for future in as_completed(futures):
                info = future.result()
                with lock:
                    counter[0] += 1
                    self.port_result.emit(info)
                    self.progress.emit("probe", counter[0], total)

    # ------------------------------------------------------------- главный
    def run(self):
        started = time.monotonic()
        try:
            # Фаза 1: быстрый проход — секунды, сразу видны типичные службы
            self.stage.emit("quick")
            quick_open = netprobe.scan_ports(
                self.ip, netprobe.QUICK_PORTS, timeout=0.3, workers=800,
                progress=lambda d, t: self.progress.emit("quick", d, t),
                stop=self._stop)
            if not self._stop.is_set():
                self._probe_all(quick_open)

            # Фаза 2: полный проход по оставшимся портам
            if not self._stop.is_set():
                self.stage.emit("full")
                quick_set = set(netprobe.QUICK_PORTS)
                rest = [p for p in range(1, 65536) if p not in quick_set]
                rest_open = netprobe.scan_ports(
                    self.ip, rest, timeout=0.3, workers=800,
                    progress=lambda d, t: self.progress.emit("full", d, t),
                    stop=self._stop)
                fresh = [p for p in rest_open if p not in set(quick_open)]
                if not self._stop.is_set():
                    self._probe_all(fresh)
            else:
                rest_open = []

            # Фаза 3: UDP-разведка — по шагам, с индикацией текущей пробы
            self.stage.emit("udp")
            udp: dict = {}
            for key, _label, fn in _UDP_PROBES:
                if self._stop.is_set():
                    break
                self.udp_step.emit(key, True)
                try:
                    udp[key] = fn(self.ip)
                except Exception as exc:  # noqa: BLE001
                    udp[key] = str(exc)[:120]
                self.udp_step.emit(key, False)
                self.udp_result.emit(key, udp[key])
            self.done.emit(time.monotonic() - started,
                           len(set(quick_open) | set(rest_open)))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


def _device_context(device) -> str:
    """Строка контекста устройства для журнала: IP, MAC, имя, производитель.

    Журнал опроса часто копируют или сохраняют отдельно, поэтому без IP/MAC
    он бесполезен — добавляем их в каждую выдачу (запрос пользователя).
    """
    parts = [f"IP: {device.ip}"]
    if device.mac:
        parts.append(f"MAC: {device.mac}")
    if device.hostname:
        parts.append(str(device.hostname))
    if device.vendor:
        parts.append(str(device.vendor))
    return " · ".join(parts)


def _hexdump(data: bytes, limit: int = 512) -> str:
    lines = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}  {hexpart:<47}  {text}")
    if len(data) > limit:
        lines.append(f"… ({len(data) - limit} байт показано первые {limit})")
    return "\n".join(lines)


def _answer_body(raw: bytes, limit: int = 4096) -> str:
    """Текст ответа для агрегата: UTF-8, почти-текст или пометка о бинарке.

    Бинарные протоколы (ADB CNXN, TLS, …) узнаём по управляющим байтам:
    NUL-байты — «валидный UTF-8», без этой проверки в буфер попадает каша.
    Для бинарных ответов — короткая пометка и компактный hexdump.
    """
    if not raw:
        return ""
    if any(b < 32 and b not in (9, 10, 13) or b == 127 for b in raw):
        return (i18n.tr("ds_bin_reply", n=len(raw)) + "\n"
                + _hexdump(raw, limit=128))
    try:
        return raw.decode("utf-8")[:limit]
    except UnicodeDecodeError:
        text = raw.decode("latin-1", "replace")
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if printable / max(len(text), 1) >= 0.85:
            return text[:limit]
    return (i18n.tr("ds_bin_reply", n=len(raw)) + "\n" + _hexdump(raw, limit=128))


def aggregate_answers(device, results, udp_lines=None) -> str:
    """Ответы всех портов одним текстом — для кнопки «Скопировать все ответы».

    Чистая функция (без self) — тестируется без Qt. По каждому порту:
    служба, TLS-сертификат (если есть), краткий разбор, текст ответа;
    REPL-порты получают итог опроса, молчащие — строку «нет ответа».
    В конце — UDP-разведка, если хоть одна проба что-то услышала.
    """
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [f"{i18n.tr('ds_copy_all_title')} — {stamp}",
             _device_context(device)]
    for info in sorted(results, key=lambda i: int(i["port"])):
        proto = str(info.get("proto") or "")
        head = f"tcp/{info['port']}"
        if info.get("tls"):
            head += " · TLS"
        if proto:
            head += f" · {proto.upper()}"
        lines.append("")
        lines.append(head)
        if info.get("cert_cn") or info.get("cert_issuer"):
            lines.append(f"cert CN: {info.get('cert_cn') or '—'}"
                         f" | issuer: {info.get('cert_issuer') or '—'}")
        detail = str(info.get("detail") or "").strip()
        if detail:
            lines.append(detail[:200])
        body = _answer_body(info.get("raw") or b"").strip()
        if body:
            lines.append(body)
        elif not detail:
            lines.append(i18n.tr("ds_no_reply"))
        repl = str(info.get("repl_text") or "").strip()
        if repl:
            lines.append("")
            lines.append(repl)
    udp = udp_lines or {}
    udp_vals = [f"{label}: {str(udp.get(key))[:200]}"
                for key, label, _fn in _UDP_PROBES if udp.get(key)]
    if udp_vals:
        lines += ["", i18n.tr("ds_udp_gb")] + udp_vals
    return "\n".join(lines)


class ReplWorker(QThread):
    """Опрашивает найденную REPL-консоль читающими командами (без Qt-логики)."""

    repl_done = Signal(object)          # dict из repl_probe.interview

    def __init__(self, ip: str, port: int, stop_event: threading.Event,
                 parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self._stop_event = stop_event

    def stop(self):
        self._stop_event.set()

    def run(self):
        try:
            res = repl_probe.interview(self.ip, self.port,
                                       should_stop=self._stop_event.is_set)
        except Exception as exc:  # noqa: BLE001 — ошибка не должна ронять диалог
            res = {"port": self.port, "ok": False, "transcript": "",
                   "answers": {}, "error": str(exc)[:160], "seconds": 0.0,
                   "pseudo": False}
        res["port"] = self.port
        self.repl_done.emit(res)


class DeepScanDialog(QDialog):
    """Немодальное окно глубокого опроса одного устройства.

    Именно QDialog, а не QWidget: в теме фон задан правилом
    `QMainWindow, QDialog { background-color: ... }`, а окно на голом QWidget
    получается прозрачным — сквозь него просвечивает главное окно и кажется,
    что элементы накладываются друг на друга (баг v1.3.0–v1.3.2).
    """

    def __init__(self, device, parent=None):
        super().__init__(parent)
        # немодальное окно с обычной рамкой, поверх главного
        self.setModal(False)
        self.device = device
        self._results = []                       # list[dict] в порядке прихода
        self._by_port = {}                       # порт -> dict
        self._udp = {}
        self._udp_lines = {key: "" for key, _l, _f in _UDP_PROBES}
        self._udp_running = set()
        self._merged = False
        self._phase_t0 = time.monotonic()
        self._phase_key = ""
        self._t_start = time.monotonic()
        self._open_count = 0
        self._tls_count = 0
        self._repl_ports = set()             # порты, опознанные как REPL
        self._repl_done_ports = set()        # уже опрошенные (для автоопроса)
        self._repl_worker: "ReplWorker | None" = None
        self._repl_running_port = 0
        self._repl_stop = threading.Event()

        self.setWindowTitle(i18n.tr("ds_title", ip=device.ip))
        self.resize(900, 660)
        self.setMinimumSize(760, 540)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 10)
        layout.setSpacing(8)

        # -- шапка: адрес + подсказка слева, статус справа -----------------
        head = QHBoxLayout()
        hint = device.vendor or device.hostname or ""
        title = QLabel(f"<b style='font-size:15px'>{device.ip}</b>"
                       + (f" <span style='color:#8a90a0'>· {hint}</span>" if hint else ""))
        head.addWidget(title, 1)
        self.chip = QLabel(i18n.tr("ds_chip_scan"))
        self._chip_style("#8a90a0")
        head.addWidget(self.chip)
        layout.addLayout(head)

        # -- прогресс: бар + скорость + ETA --------------------------------
        prog_row = QHBoxLayout()
        prog_row.setSpacing(10)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress.setFormat("%p%")
        prog_row.addWidget(self.progress, 1)
        self.rate_label = QLabel("")
        self.rate_label.setStyleSheet("color:#8a90a0;")
        prog_row.addWidget(self.rate_label)
        self.eta_label = QLabel("")
        self.eta_label.setStyleSheet("color:#8a90a0;")
        prog_row.addWidget(self.eta_label)
        layout.addLayout(prog_row)

        # -- фаза + сводка --------------------------------------------------
        self.phase_label = QLabel("")
        f = QFont()
        f.setBold(True)
        self.phase_label.setFont(f)
        layout.addWidget(self.phase_label)
        self.summary = QLabel("")
        layout.addWidget(self.summary)

        # -- таблица результатов --------------------------------------------
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([i18n.tr("ds_col_port"),
                                              i18n.tr("ds_col_svc"),
                                              i18n.tr("ds_col_detail")])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(1, 150)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.selectionModel().selectionChanged.connect(self._show_raw)
        layout.addWidget(self.table, 5)

        # -- сырой ответ ------------------------------------------------------
        raw_head = QHBoxLayout()
        raw_label = QLabel(i18n.tr("ds_raw"))
        raw_label.setFont(f)
        raw_head.addWidget(raw_label)
        raw_head.addStretch(1)
        hint_label = QLabel(i18n.tr("ds_hint_click"))
        hint_label.setStyleSheet("color:#8a90a0;")
        raw_head.addWidget(hint_label)
        layout.addLayout(raw_head)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        mono = QFont()
        mono.setStyleHint(QFont.Monospace)
        mono.setFamily("Consolas")
        self.raw.setFont(mono)
        layout.addWidget(self.raw, 3)

        # -- UDP-разведка: по одной строке на пробу ----------------------------
        udp_box = QGroupBox(i18n.tr("ds_udp_gb"))
        udp_grid = QGridLayout(udp_box)
        udp_grid.setContentsMargins(10, 4, 10, 6)
        udp_grid.setHorizontalSpacing(12)
        udp_grid.setVerticalSpacing(2)
        self.udp_labels = {}
        for col, (key, label, _fn) in enumerate(_UDP_PROBES):
            name = QLabel(f"<b>{label}:</b>")
            value = QLabel("—")
            value.setStyleSheet("color:#8a90a0;")
            udp_grid.addWidget(name, 0, col * 2)
            udp_grid.addWidget(value, 0, col * 2 + 1)
            udp_grid.setColumnStretch(col * 2 + 1, 1)
            self.udp_labels[key] = value
        layout.addWidget(udp_box)

        # -- кнопки -------------------------------------------------------------
        actions = QHBoxLayout()
        self.browser_btn = QPushButton(i18n.tr("ds_open_browser"))
        self.browser_btn.setEnabled(False)
        self.browser_btn.clicked.connect(self._open_browser)
        actions.addWidget(self.browser_btn)
        self.repl_btn = QPushButton(i18n.tr("ds_repl_btn"))
        self.repl_btn.setEnabled(False)
        self.repl_btn.clicked.connect(self._on_repl_btn)
        actions.addWidget(self.repl_btn)
        copy_btn = QPushButton(i18n.tr("ds_copy"))
        copy_btn.clicked.connect(self._copy_raw)
        actions.addWidget(copy_btn)
        self.copy_all_btn = QPushButton(i18n.tr("ds_copy_all"))
        self.copy_all_btn.setToolTip(i18n.tr("ds_copy_all_hint"))
        self.copy_all_btn.setEnabled(False)   # включится с первым ответом
        self.copy_all_btn.clicked.connect(self._copy_all_answers)
        actions.addWidget(self.copy_all_btn)
        self.save_btn = QPushButton(i18n.tr("ds_save"))
        self.save_btn.clicked.connect(self._save_report)
        actions.addWidget(self.save_btn)
        actions.addStretch(1)
        self.stop_btn = QPushButton(i18n.tr("ds_stop"))
        self.stop_btn.clicked.connect(self._stop_scan)
        actions.addWidget(self.stop_btn)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.close)
        actions.addWidget(close_btn)
        layout.addLayout(actions)

        # -- работник и таймер прошедшего времени --------------------------------
        self.worker = DeepScanWorker(device.ip, self)
        self.worker.stage.connect(self._on_stage)
        self.worker.progress.connect(self._on_progress)
        self.worker.port_result.connect(self._on_port)
        self.worker.udp_step.connect(self._on_udp_step)
        self.worker.udp_result.connect(self._on_udp_result)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

        self.tick = QTimer(self)
        self.tick.timeout.connect(self._refresh_summary)
        self.tick.start(1000)
        self._refresh_summary()

    # ------------------------------------------------------------ состояние
    def _chip_style(self, color: str):
        self.chip.setStyleSheet(
            f"color:{color}; border:1px solid {color}; border-radius:9px;"
            "padding:2px 10px; font-weight:600;")

    def _phase_name(self, key: str) -> str:
        names = {"quick": "ds_phase_name_quick", "probe": "ds_phase_name_probe",
                 "full": "ds_phase_name_full", "udp": "ds_phase_name_udp"}
        return i18n.tr(names.get(key, "ds_phase_name_quick"))

    def _on_stage(self, key: str):
        self._phase_key = key
        self._phase_t0 = time.monotonic()
        self.rate_label.setText("")
        self.eta_label.setText("")
        if key == "udp":
            self.progress.setRange(0, 0)          # «занят» на время UDP
            self.rate_label.setText("")
            self.eta_label.setText("")
        else:
            self.progress.setRange(0, 1)
            self.progress.setValue(0)

    def _on_progress(self, key: str, done: int, total: int):
        if key != self._phase_key:
            self._phase_key = key
            self._phase_t0 = time.monotonic()
        total = max(int(total), 1)
        done = max(0, min(int(done), total))
        if key == "udp":
            self.progress.setRange(0, 0)
            self.phase_label.setText(self._phase_name(key))
            return
        self.progress.setRange(0, total)
        self.progress.setValue(done)
        pct = int(done * 100 / total)
        self.phase_label.setText(
            i18n.tr("ds_phase_" + key, done=done, total=total, pct=pct))
        # скорость и ETA по текущей фазе
        elapsed = time.monotonic() - self._phase_t0
        if elapsed >= 0.6 and key in ("quick", "full"):
            rate = done / elapsed
            self.rate_label.setText(i18n.tr("ds_rate", rate=int(rate)))
            remaining = total - done
            eta = int(remaining / rate) if rate > 0.5 else 0
            self.eta_label.setText(i18n.tr("ds_eta", sec=eta) if done else "")
        else:
            self.rate_label.setText("")
            self.eta_label.setText("")

    def _on_port(self, info: dict):
        port = int(info["port"])
        if port in self._by_port:
            return
        self._by_port[port] = info
        self._results.append(info)
        self._open_count += 1
        if info.get("tls"):
            self._tls_count += 1
        self.copy_all_btn.setEnabled(True)   # уже есть что копировать

        proto = str(info.get("proto") or "")
        proto_text = proto.upper() if proto else i18n.tr("ds_no_reply")
        if info.get("tls"):
            proto_text += " · TLS"
        detail = str(info.get("detail") or "")

        row = self.table.rowCount()
        self.table.insertRow(row)
        item_port = QTableWidgetItem(str(port))
        item_port.setData(Qt.UserRole, port)
        item_port.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.table.setItem(row, 0, item_port)
        item_svc = QTableWidgetItem(proto_text)
        color = QColor(SERVICE_COLORS.get(proto, "#64748b"))
        item_svc.setForeground(color)
        font = QFont()
        font.setBold(True)
        item_svc.setFont(font)
        self.table.setItem(row, 1, item_svc)
        self.table.setItem(row, 2, QTableWidgetItem(detail[:220]))
        self.table.sortByColumn(0, Qt.AscendingOrder)
        if self.table.currentRow() < 0:
            self.table.selectRow(0)
        if proto in ("http", "https"):
            self.browser_btn.setEnabled(True)
        if proto == "repl":
            # консоль найдена — сразу сами спрашиваем её, кто она (только чтение)
            self._repl_ports.add(port)
            if (port not in self._repl_done_ports
                    and self._repl_worker is None):
                self._start_repl(port)
        self._update_repl_btn()
        self._refresh_summary()

    def _on_udp_step(self, key: str, running: bool):
        label = self.udp_labels.get(key)
        if not label:
            return
        if running:
            self._udp_running.add(key)
            label.setText(i18n.tr("ds_udp_probing"))
            label.setStyleSheet("color:#8a90a0; font-style:italic;")
        else:
            self._udp_running.discard(key)

    def _on_udp_result(self, key: str, value):
        label = self.udp_labels.get(key)
        if not label:
            return
        if isinstance(value, list):
            text = ", ".join(str(v) for v in value) if value else ""
        else:
            text = str(value or "").strip()
        self._udp_lines[key] = text
        label.setText(text[:80] if text else "—")
        label.setStyleSheet("color:#8a90a0;" if not text else "")
        if text:
            self.copy_all_btn.setEnabled(True)

    def _refresh_summary(self):
        sec = int(time.monotonic() - self._t_start)
        parts = [i18n.tr("ds_elapsed", sec=sec),
                 i18n.tr("ds_stat_open", n=self._open_count),
                 i18n.tr("ds_stat_svc",
                         n=len({str(i.get("proto")) for i in self._results}
                               - {"", "tcp", "binary"})),
                 i18n.tr("ds_stat_tls", n=self._tls_count)]
        self.summary.setText(" · ".join(parts))

    def _on_done(self, seconds: float, count: int):
        self.tick.stop()
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.rate_label.setText("")
        self.eta_label.setText("")
        if count:
            self.phase_label.setText(i18n.tr("ds_done", sec=int(seconds), n=count))
        else:
            self.phase_label.setText(i18n.tr("ds_no_open", sec=int(seconds)))
        self.chip.setText(i18n.tr("ds_chip_done"))
        self._chip_style("#2ecc71")
        self.stop_btn.setEnabled(False)
        self._merge_device()

    def _on_failed(self, error: str):
        self.tick.stop()
        self.phase_label.setText(i18n.tr("ds_error", error=error[:200]))
        self.chip.setText(i18n.tr("ds_chip_error"))
        self._chip_style("#e74c3c")
        self.stop_btn.setEnabled(False)

    # -------------------------------------------------------------- действия
    def _stop_scan(self):
        self.worker.stop()
        self.stop_btn.setEnabled(False)
        self.chip.setText(i18n.tr("ds_chip_stopped"))
        self._chip_style("#f59e0b")

    def _selected(self) -> "dict | None":
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        if not item:
            return None
        return self._by_port.get(item.data(Qt.UserRole))

    # -------------------------------------------------------- REPL-опрос
    def _update_repl_btn(self):
        """Кнопка REPL: активна, когда выбран REPL-порт и опрос не идёт."""
        if self._repl_worker is not None:
            self.repl_btn.setEnabled(False)
            self.repl_btn.setText(i18n.tr("ds_repl_running"))
            return
        info = self._selected()
        is_repl = bool(info) and info.get("proto") == "repl"
        self.repl_btn.setEnabled(is_repl)
        if is_repl and int(info.get("port") or 0) in self._repl_done_ports:
            self.repl_btn.setText(i18n.tr("ds_repl_again"))
        else:
            self.repl_btn.setText(i18n.tr("ds_repl_btn"))

    def _on_repl_btn(self):
        info = self._selected()
        if not info or info.get("proto") != "repl":
            return
        self._start_repl(int(info["port"]))

    def _start_repl(self, port: int):
        if self._repl_worker is not None:
            return
        self._repl_stop = threading.Event()
        self._repl_running_port = port
        self._repl_worker = ReplWorker(self.device.ip, port,
                                       self._repl_stop, self)
        self._repl_worker.repl_done.connect(self._on_repl_result)
        self._repl_worker.start()
        self._update_repl_btn()
        info = self._selected()
        if info and int(info.get("port") or 0) == port:
            self._show_raw()

    def _format_repl(self, result: dict) -> str:
        """Текст REPL-опроса для панели «Сырой ответ» и отчёта."""
        lines = [i18n.tr("ds_repl_title", sec=max(1, int(result.get("seconds") or 0))),
                 "-" * 60]
        if result.get("pseudo"):
            # не MicroPython: поясняем, почему в транскрипте «Bad command …»
            lines.append(i18n.tr("ds_repl_pseudo"))
            lines.append("-" * 60)
        transcript = str(result.get("transcript") or "").strip()
        if transcript:
            lines.append(transcript)
            lines.append("-" * 60)
        facts = repl_probe.facts_block(result.get("answers") or {})
        if facts:
            lines.append(i18n.tr("ds_repl_facts"))
            lines.append(facts)
        if not result.get("ok"):
            lines.append(i18n.tr("ds_repl_fail",
                                 err=str(result.get("error") or "?")[:160]))
        return "\n".join(lines)

    def _on_repl_result(self, result: dict):
        port = int(result.get("port") or 0)
        self._repl_done_ports.add(port)
        self._repl_worker = None
        self._repl_running_port = 0
        info = self._by_port.get(port)
        if info is not None:
            info["repl_result"] = result
            info["repl_text"] = self._format_repl(result)
            summary = repl_probe.summary_line(result.get("answers") or {})
            info["repl_summary"] = summary
            # признак добавляем один раз и только с реальной сводкой: иначе
            # неудавшийся первый опрос заблокирует признак успешного повтора
            if summary and not info.get("repl_evidenced"):
                info["repl_evidenced"] = True
                self.device.evidence.append(
                    i18n.tr("ds_repl_evidence", info=summary))
        self._update_repl_btn()
        if self._selected() is info:
            self._show_raw()
        self._refresh_summary()

    def _show_raw(self, *_):
        info = self._selected()
        if not info:
            self.raw.setPlainText("")
            return
        raw = info.get("raw") or b""
        lines = [_device_context(self.device),
                 "",
                 f"tcp/{info['port']}" + (" TLS" if info.get("tls") else "")]
        if info.get("cert_cn") or info.get("cert_issuer"):
            lines.append(f"cert CN: {info.get('cert_cn') or '—'}"
                         f" | issuer: {info.get('cert_issuer') or '—'}")
        lines.append("-" * 60)
        if raw:
            try:
                lines.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                lines.append(raw.decode("latin-1", "replace"))
            lines.append("-" * 60)
            lines.append(_hexdump(raw))
        else:
            lines.append(i18n.tr("ds_no_reply"))
        if info.get("repl_text"):
            lines.append("")
            lines.append(str(info.get("repl_text")))
        elif (self._repl_worker is not None
                and int(info.get("port") or 0) == self._repl_running_port):
            lines.append("")
            lines.append(i18n.tr("ds_repl_wait"))
        self.raw.setPlainText("\n".join(lines))

    def _open_browser(self):
        info = self._selected()
        if not info:
            return
        scheme = "https" if info.get("tls") or info["port"] in (443, 8443) else "http"
        QDesktopServices.openUrl(QUrl(f"{scheme}://{self.device.ip}:{info['port']}/"))

    def _copy_raw(self):
        QApplication.clipboard().setText(self.raw.toPlainText())

    def _copy_all_answers(self):
        """Агрегат ответов всех портов — в буфер обмена одним текстом."""
        QApplication.clipboard().setText(
            aggregate_answers(self.device, self._results, self._udp_lines))
        self.summary.setText(i18n.tr("ds_copied_all"))

    def _save_report(self):
        default = os.path.join(os.path.expanduser("~"),
                               f"droidscout_probe_{self.device.ip}.txt")
        path, _ = QFileDialog.getSaveFileName(self, i18n.tr("ds_save"), default,
                                              "Text (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"{i18n.tr('ds_report_title')}\n")
                fh.write(f"IP: {self.device.ip}\n")
                if self.device.mac:
                    fh.write(f"MAC: {self.device.mac}\n")
                if self.device.hostname:
                    fh.write(f"{i18n.tr('det_hostname')}: "
                             f"{self.device.hostname}\n")
                if self.device.vendor:
                    fh.write(f"{i18n.tr('det_vendor')}: "
                             f"{self.device.vendor}\n")
                if self.device.ttl:
                    fh.write(f"TTL: {self.device.ttl}\n")
                fh.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S\n"))
                fh.write(i18n.tr("ds_stat_open", n=len(self._results)) + "\n")
                fh.write("=" * 64 + "\n")
                for info in sorted(self._results, key=lambda i: int(i["port"])):
                    fh.write(f"\ntcp/{info['port']}  "
                             f"{str(info.get('proto') or '—').upper()}"
                             + (" · TLS" if info.get("tls") else "") + "\n")
                    if info.get("cert_cn") or info.get("cert_issuer"):
                        fh.write(f"cert CN: {info.get('cert_cn') or '—'} | "
                                 f"issuer: {info.get('cert_issuer') or '—'}\n")
                    fh.write(str(info.get("detail") or "") + "\n")
                    raw = info.get("raw") or b""
                    if raw:
                        try:
                            text = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            text = raw.decode("latin-1", "replace")
                        fh.write("-" * 64 + "\n" + text[:4096] + "\n")
                        fh.write("-" * 64 + "\n" + _hexdump(raw, limit=1024) + "\n")
                    else:
                        fh.write(i18n.tr("ds_no_reply") + "\n")
                    if info.get("repl_text"):
                        fh.write("\n" + str(info.get("repl_text")) + "\n")
                udp_lines = [f"  {label}: {self._udp_lines.get(key) or '—'}"
                             for key, label, _fn in _UDP_PROBES]
                fh.write("\n" + i18n.tr("ds_udp_gb") + "\n" + "\n".join(udp_lines) + "\n")
        except OSError as exc:
            self.phase_label.setText(i18n.tr("ds_error", error=str(exc)[:160]))
            return
        self.summary.setText(i18n.tr("ds_saved", path=path))

    # -------------------------------------------------------------- перенос
    def _merge_device(self):
        """Найденное — в модель устройства (карточка и вердикт обновятся)."""
        if self._merged:
            return
        self._merged = True
        device = self.device
        device.ports.update(self._by_port)
        for info in self._results:
            proto = str(info.get("proto") or "")
            if proto in _SERVICE_KEYS:
                device.services.add(proto)
            if proto == "http" and not device.http_banner:
                device.http_banner = str(info.get("detail") or "")[:200]
            # ADB-рукопожатие (CNXN) не требует авторизации — из него можно
            # достать модель даже без полного ADB-доступа
            if proto == "adb" and not device.model:
                model = str(info.get("adb_model") or "")
                if model:
                    device.model = model
                    device.evidence.append(
                        i18n.tr("ds_evidence_adb_model", model=model))
        if self._by_port:
            device.evidence.append(i18n.tr("ds_evidence", n=len(self._by_port)))
        for key, label, _fn in _UDP_PROBES:
            value = self._udp_lines.get(key) or ""
            if value:
                device.evidence.append(f"{label}: {value[:160]}")

    def closeEvent(self, event):
        self.tick.stop()
        self.worker.stop()
        if not self.worker.wait(3000):
            self.worker.terminate()
        if self._repl_worker is not None:
            self._repl_worker.stop()
            if not self._repl_worker.wait(2000):
                self._repl_worker.terminate()
            self._repl_worker = None
        # даже при досрочном закрытии переносим то, что успели собрать
        self._merge_device()
        super().closeEvent(event)
