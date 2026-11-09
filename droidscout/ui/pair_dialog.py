"""Диалог «Телефон Wi-Fi»: сопряжение (Android 11+) и подключение.

Шаги для пользователя отражены в подсказке внутри диалога:
сопряжение (порт + код с экрана «Сопряжение устройства с кодом»),
затем подключение (порт adb с экрана «Отладка по Wi-Fi»).

Вся сеть — в фоновом потоке, интерфейс не блокируется.
"""

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (QDialog, QFormLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QVBoxLayout)

from .. import adb_actions, i18n, wifi_pair
from ..fingerprint import Device


class _PairWorker(QObject):
    """Сеть для диалога: сопряжение или подключение."""
    done = Signal(dict)

    def __init__(self, mode, ip, pair_port, code, conn_port):
        super().__init__()
        self.mode = mode
        self.ip = ip
        self.pair_port = pair_port
        self.code = code
        self.conn_port = conn_port

    def run(self):
        try:
            if self.mode == "pair":
                guid = wifi_pair.pair(self.ip, self.pair_port, self.code,
                                      timeout=15.0)
                self.done.emit({"stage": "pair", "ok": True, "guid": guid})
            else:
                wifi_pair.register_secure(self.ip, self.conn_port)
                model = adb_actions.shell(self.ip, "getprop ro.product.model",
                                          timeout=12.0).strip()
                self.done.emit({"stage": "connect", "ok": True,
                                "model": model})
        except wifi_pair.PairError as exc:
            self.done.emit({"stage": self.mode, "ok": False,
                            "code": exc.code, "detail": exc.detail})
        except adb_actions.ActionError as exc:
            code = {"unauthorized": "unauth"}.get(exc.code, "adbconn")
            self.done.emit({"stage": self.mode, "ok": False,
                            "code": code, "detail": str(exc)})
        except Exception as exc:  # noqa: BLE001 — последняя линия обороны
            self.done.emit({"stage": self.mode, "ok": False,
                            "code": "generic", "detail": str(exc)})


class PairDialog(QDialog):
    """Сопряжение с телефоном по «Отладке по Wi-Fi» и подключение."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("wifi_title"))
        self.setMinimumWidth(460)
        self.device = None                     # Device при успешном подключении
        self._thread = None
        self._worker = None

        layout = QVBoxLayout(self)

        hint = QLabel(i18n.tr("wifi_hint"))
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("192.168.1.120")
        form.addRow(i18n.tr("wifi_ip"), self.ip_edit)
        self.pair_port_edit = QLineEdit()
        self.pair_port_edit.setPlaceholderText("39461")
        form.addRow(i18n.tr("wifi_pair_port"), self.pair_port_edit)
        self.code_edit = QLineEdit()
        self.code_edit.setPlaceholderText("123456")
        self.code_edit.setMaxLength(6)
        form.addRow(i18n.tr("wifi_code"), self.code_edit)
        self.conn_port_edit = QLineEdit()
        self.conn_port_edit.setPlaceholderText("37521")
        form.addRow(i18n.tr("wifi_conn_port"), self.conn_port_edit)
        layout.addLayout(form)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        btns = QHBoxLayout()
        self.pair_btn = QPushButton(i18n.tr("wifi_pair"))
        self.pair_btn.clicked.connect(lambda: self._start("pair"))
        btns.addWidget(self.pair_btn)
        self.conn_btn = QPushButton(i18n.tr("wifi_connect"))
        self.conn_btn.clicked.connect(lambda: self._start("connect"))
        btns.addWidget(self.conn_btn)
        btns.addStretch(1)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        btns.addWidget(close_btn)
        layout.addLayout(btns)

        self.ip_edit.setFocus()

    # ------------------------------------------------------------- запуск
    def _start(self, mode: str):
        ip = self.ip_edit.text().strip()
        if not ip:
            self.status.setText(i18n.tr("wifi_fail",
                                        err=i18n.tr("wifi_err_connect")))
            return
        pair_port = self._port(self.pair_port_edit)
        conn_port = self._port(self.conn_port_edit)
        code = self.code_edit.text().strip()
        if mode == "pair":
            if pair_port is None or len(code) != 6 or not code.isdigit():
                self.status.setText(i18n.tr("wifi_fail",
                                            err=i18n.tr("wifi_err_code")))
                return
        elif conn_port is None:
            self.status.setText(i18n.tr("wifi_fail",
                                        err=i18n.tr("wifi_err_connect")))
            return

        self.pair_btn.setEnabled(False)
        self.conn_btn.setEnabled(False)
        self.status.setText(i18n.tr("wifi_working"))
        self._thread = QThread(self)
        self._worker = _PairWorker(mode, ip, pair_port, code, conn_port)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_done)
        self._thread.start()

    @staticmethod
    def _port(edit) -> "int | None":
        try:
            value = int(edit.text().strip())
        except ValueError:
            return None
        return value if 1 <= value <= 65535 else None

    def _on_done(self, result: dict):
        self._thread.quit()
        self._thread.wait(2000)
        self._thread = None
        self._worker = None
        self.pair_btn.setEnabled(True)
        self.conn_btn.setEnabled(True)

        if not result["ok"]:
            key = f"wifi_err_{result['code']}"
            text = i18n.tr(key, err=result.get("detail", ""))
            if text == key:                    # нет перевода — общий формат
                text = i18n.tr("wifi_err_generic", err=result.get("detail", ""))
            self.status.setText(i18n.tr("wifi_fail", err=text))
            return

        if result["stage"] == "pair":
            self.status.setText(i18n.tr("wifi_pair_ok",
                                        guid=result["guid"]))
            self.conn_port_edit.setFocus()
            return

        # Подключение удалось — добавляем устройство в таблицу
        ip = self.ip_edit.text().strip()
        port = self._port(self.conn_port_edit) or 0
        device = Device(ip=ip, device_type="phone", confidence=90,
                        ports={port} if port else set(),
                        services={"adb"},
                        model=result.get("model", ""),
                        is_new=True)
        self.device = device
        self.status.setText(i18n.tr("wifi_conn_ok",
                                    model=result.get("model") or ip))
        self.accept()
