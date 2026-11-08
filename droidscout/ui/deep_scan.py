"""Диалог глубокого опроса: все 65535 TCP-портов + распознавание сервисов.

Три фазы в фоновом QThread:
  1. скан портов 1–65535 (netprobe.scan_all_ports);
  2. «разговор» с каждым открытым портом (netprobe.probe_port) — баннеры,
     HTTP/RTSP/Redis-зонды, TLS-сертификаты;
  3. UDP-разведка: mDNS, SSDP, SNMP sysDescr, NetBIOS-имена.

Сырые ответы показываются целиком (текст + hex) — для ручного анализа.
По завершении найденное переносится в Device и в карточку устройства.
"""

import threading
import time

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit,
                               QProgressBar, QPushButton, QTableWidget,
                               QTableWidgetItem, QVBoxLayout, QWidget)

from .. import i18n, netprobe

# Протоколы, которые попадают в device.services (осмысленные службы)
_SERVICE_KEYS = {"http", "https", "ssh", "ftp", "smtp", "pop3", "imap",
                 "rtsp", "vnc", "telnet", "redis", "irc"}


class DeepScanWorker(QThread):
    stage = Signal(str, int, int)        # ключ фазы, готово, всего
    port_result = Signal(object)         # dict из netprobe.probe_port
    udp_done = Signal(object)            # dict {ssdp, mdns, snmp, nbns}
    done = Signal(float, int)            # секунд, открытых портов
    failed = Signal(str)

    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        started = time.monotonic()
        try:
            self.stage.emit("ds_phase_ports", 0, 65535)
            opened = netprobe.scan_all_ports(
                self.ip,
                progress=lambda d, t: self.stage.emit("ds_phase_ports", d, t),
                stop=self._stop)
            self.stage.emit("ds_phase_probe", 0, len(opened))
            for index, port in enumerate(opened, 1):
                if self._stop.is_set():
                    break
                try:
                    info = netprobe.probe_port(self.ip, port)
                except Exception as exc:  # noqa: BLE001 — порт не должен ронять опрос
                    info = {"port": port, "proto": "", "detail": str(exc)[:120],
                            "raw": b"", "tls": False, "cert_cn": "", "cert_issuer": ""}
                self.port_result.emit(info)
                self.stage.emit("ds_phase_probe", index, len(opened))
            self.stage.emit("ds_phase_udp", 0, 0)
            udp = {}
            for key, fn in (("mdns", netprobe.mdns_probe),
                            ("ssdp", netprobe.ssdp_probe),
                            ("snmp", netprobe.snmp_probe),
                            ("nbns", netprobe.nbns_probe)):
                if self._stop.is_set():
                    break
                try:
                    udp[key] = fn(self.ip)
                except Exception as exc:  # noqa: BLE001
                    udp[key] = str(exc)[:120]
            self.udp_done.emit(udp)
            self.done.emit(time.monotonic() - started, len(opened))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


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


class DeepScanDialog(QWidget):
    """Немодальное окно глубокого опроса одного устройства."""

    def __init__(self, device, parent=None):
        super().__init__(parent)
        self.device = device
        self._results = []                      # list[dict] в порядке поступления
        self._open_ports = []
        self._udp = {}
        self._merged = False
        self.setWindowTitle(i18n.tr("ds_title", ip=device.ip))
        self.resize(780, 560)

        layout = QVBoxLayout(self)
        head = QHBoxLayout()
        title = QLabel(f"<b>{device.ip}</b>")
        head.addWidget(title, 1)
        self.stop_btn = QPushButton(i18n.tr("ds_stop"))
        self.stop_btn.clicked.connect(self._stop_scan)
        head.addWidget(self.stop_btn)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.close)
        head.addWidget(close_btn)
        layout.addLayout(head)

        self.progress = QProgressBar()
        self.progress.setRange(0, 65535)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        self.status = QLabel(i18n.tr("ds_phase_ports", done=0, total=65535))
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels([i18n.tr("ds_col_port"),
                                              i18n.tr("ds_col_svc"),
                                              i18n.tr("ds_col_detail")])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.selectionModel().selectionChanged.connect(self._show_raw)
        layout.addWidget(self.table, 3)

        raw_label = QLabel(i18n.tr("ds_raw"))
        font = QFont()
        font.setBold(True)
        raw_label.setFont(font)
        layout.addWidget(raw_label)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        mono = QFont()
        mono.setStyleHint(QFont.Monospace)
        self.raw.setFont(mono)
        layout.addWidget(self.raw, 2)

        self.udp_text = QPlainTextEdit()
        self.udp_text.setReadOnly(True)
        self.udp_text.setMaximumHeight(64)
        self.udp_text.setPlaceholderText(i18n.tr("ds_udp_wait"))
        layout.addWidget(self.udp_text)

        actions = QHBoxLayout()
        self.browser_btn = QPushButton(i18n.tr("ds_open_browser"))
        self.browser_btn.setEnabled(False)
        self.browser_btn.clicked.connect(self._open_browser)
        actions.addWidget(self.browser_btn)
        copy_btn = QPushButton(i18n.tr("ds_copy"))
        copy_btn.clicked.connect(self._copy_raw)
        actions.addWidget(copy_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.worker = DeepScanWorker(device.ip, self)
        self.worker.stage.connect(self._on_stage)
        self.worker.port_result.connect(self._on_port)
        self.worker.udp_done.connect(self._on_udp)
        self.worker.done.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    # ------------------------------------------------------------- колбэки
    def _on_stage(self, key: str, done: int, total: int):
        self.status.setText(i18n.tr(key, done=done, total=total))
        if key == "ds_phase_ports":
            self.progress.setRange(0, max(total, 1))
            self.progress.setValue(done)
        elif key == "ds_phase_probe":
            self.progress.setRange(0, max(total, 1))
            self.progress.setValue(done)
        else:
            self.progress.setRange(0, 0)          # «занят» для UDP-фазы

    def _on_port(self, info: dict):
        self._results.append(info)
        port = int(info["port"])
        self._open_ports.append(port)
        proto = str(info.get("proto") or "")
        proto_text = proto.upper() if proto else i18n.tr("ds_no_reply")
        detail = str(info.get("detail") or "")
        if info.get("tls"):
            proto_text += " (TLS)"
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(port)))
        self.table.setItem(row, 1, QTableWidgetItem(proto_text))
        self.table.setItem(row, 2, QTableWidgetItem(detail[:200]))
        if proto in ("http", "https"):
            self.browser_btn.setEnabled(True)

    def _on_udp(self, udp: dict):
        self._udp = udp
        lines = []
        labels = {"mdns": "mDNS", "ssdp": "SSDP", "snmp": "SNMP", "nbns": "NetBIOS"}
        for key, label in labels.items():
            value = udp.get(key)
            if isinstance(value, list):
                value = ", ".join(value) if value else ""
            elif value is None:
                value = ""
            value = str(value).strip()
            if value:
                lines.append(f"{label}: {value}")
        self.udp_text.setPlainText("\n".join(lines) or i18n.tr("ds_udp_empty"))

    def _on_done(self, seconds: float, count: int):
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        if count:
            self.status.setText(i18n.tr("ds_done", sec=int(seconds), n=count))
        else:
            self.status.setText(i18n.tr("ds_no_open", sec=int(seconds)))
        self._merge_device()
        self.stop_btn.setEnabled(False)

    def _on_failed(self, error: str):
        self.status.setText(i18n.tr("ds_error", error=error[:200]))
        self.stop_btn.setEnabled(False)

    # ------------------------------------------------------------- действия
    def _stop_scan(self):
        self.worker.stop()
        self.stop_btn.setEnabled(False)
        self.status.setText(i18n.tr("ds_stopping"))

    def _selected(self) -> "dict | None":
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def _show_raw(self, *_):
        info = self._selected()
        if not info:
            self.raw.setPlainText("")
            return
        raw = info.get("raw") or b""
        lines = [f"tcp/{info['port']}" + (" TLS" if info.get("tls") else "")]
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
        self.raw.setPlainText("\n".join(lines))

    def _open_browser(self):
        info = self._selected()
        if not info:
            return
        scheme = "https" if info.get("tls") or info["port"] in (443, 8443) else "http"
        QDesktopServices.openUrl(QUrl(f"{scheme}://{self.device.ip}:{info['port']}/"))

    def _copy_raw(self):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.raw.toPlainText())

    def _merge_device(self):
        """Найденное — в модель устройства (карточка и вердикт обновятся)."""
        if self._merged:
            return
        self._merged = True
        device = self.device
        device.ports.update(self._open_ports)
        for info in self._results:
            proto = str(info.get("proto") or "")
            if proto in _SERVICE_KEYS:
                device.services.add(proto)
            if proto == "http" and not device.http_banner:
                device.http_banner = str(info.get("detail") or "")[:200]
        if self._open_ports:
            device.evidence.append(i18n.tr("ds_evidence", n=len(self._open_ports)))
        labels = {"mdns": "mDNS", "ssdp": "SSDP", "snmp": "SNMP", "nbns": "NetBIOS"}
        for key, label in labels.items():
            value = self._udp.get(key)
            if isinstance(value, list):
                value = ", ".join(value)
            value = str(value or "").strip()
            if value:
                device.evidence.append(f"{label}: {value[:160]}")

    def closeEvent(self, event):
        self.worker.stop()
        if not self.worker.wait(3000):
            self.worker.terminate()
        # даже при досрочном закрытии переносим то, что успели собрать
        self._merge_device()
        super().closeEvent(event)
