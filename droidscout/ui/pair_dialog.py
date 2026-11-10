"""Мастер «Телефон Wi-Fi»: шаг 1 — сопряжение, шаг 2 — подключение.

Шаг 1: IP + порт сопряжения + 6-значный код с экрана телефона
«Сопряжение устройства с кодом». Кнопка «Найти телефон» подставит IP
и порт сопряжения сама — пока на телефоне открыт экран с кодом, тот
объявляет себя по mDNS (_adb-tls-pairing._tcp.local).

Шаг 2: порт подключения с главного экрана «Отладка по Wi-Fi» (строка
«IP-адрес и порт»); IP переносится из шага 1. Код на этом шаге не
нужен: после сопряжения телефон авторизует компьютер по сохранённому
ключу. Для повторного подключения (порт сменился после перезагрузки)
есть кнопка «Уже сопряжено →» — она пропускает шаг 1.

Вся сеть — в фоновом потоке, интерфейс не блокируется.
"""

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (QDialog, QFormLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from .. import adb_actions, config, i18n, wifi_pair
from ..fingerprint import Device

_STATUS_OK = "color:#7bd88f;"
_STATUS_ERR = "color:#f45b69;"


def _error_hint(detail: str, code: str) -> str:
    """Человеческая подсказка по характеру ошибки подключения.

    Два типовых случая: не тот порт (он меняется при каждом включении
    «Отладки по Wi-Fi», порт сопряжения не подходит) и телефон отклонил
    ключ (сопряжение делали давно/другим приложением — повторить шаг 1).
    """
    low = (detail or "").lower()
    if (code in ("connect", "timeout", "adbconn")
            or any(w in low for w in ("refused", "timed out", "timeout",
                                      "unreachable", "no route", "network is",
                                      "wrong version number",
                                      "instead of stls"))):
        return i18n.tr("wifi_hint_port")
    if any(w in low for w in ("certificate", "alert", "handshake",
                              "closed by device", "unexpected packet",
                              "tls")):
        return i18n.tr("wifi_hint_trust")
    return ""


class _PairWorker(QObject):
    """Сеть для мастера: поиск телефона, сопряжение или подключение."""
    done = Signal(dict)

    def __init__(self, mode, ip="", pair_port=0, code="", conn_port=0):
        super().__init__()
        self.mode = mode
        self.ip = ip
        self.pair_port = pair_port
        self.code = code
        self.conn_port = conn_port

    def run(self):
        try:
            if self.mode == "discover":
                found = wifi_pair.discover_pairing(timeout=6.0)
                self.done.emit({"stage": "discover", "ok": bool(found),
                                "found": found})
                return
            if self.mode == "discover_conn":
                found = wifi_pair.discover_connect(timeout=6.0,
                                                   ip=self.ip or "")
                self.done.emit({"stage": "discover_conn", "ok": bool(found),
                                "found": found})
                return
            if self.mode == "pair":
                guid = wifi_pair.pair(self.ip, self.pair_port, self.code,
                                      timeout=15.0)
                self.done.emit({"stage": "pair", "ok": True, "guid": guid})
                return
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
    """Визард: сопряжение с телефоном по «Отладке по Wi-Fi» и подключение."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("wifi_title"))
        self.setMinimumWidth(520)
        self.device = None                     # Device при успешном подключении
        self._thread = None
        self._worker = None

        layout = QVBoxLayout(self)

        self.step_label = QLabel("")
        self.step_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.step_label)

        self.hint = QLabel("")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack)
        self.stack.addWidget(self._make_page_pair())
        self.stack.addWidget(self._make_page_connect())

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        btns = QHBoxLayout()
        btns.addStretch(1)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        btns.addWidget(close_btn)
        layout.addLayout(btns)

        self._show_step(0)
        last_ip = str(config.get("wifi_last_ip", "") or "")
        if last_ip:
            self.ip_edit.setText(last_ip)
        self.ip_edit.setFocus()

    # ----------------------------------------------------------- страницы
    def _make_page_pair(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
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
        v.addLayout(form)

        btns = QHBoxLayout()
        self.find_btn = QPushButton(i18n.tr("wifi_find"))
        self.find_btn.clicked.connect(self._start_find)
        btns.addWidget(self.find_btn)
        self.pair_btn = QPushButton(i18n.tr("wifi_pair_next"))
        self.pair_btn.setDefault(True)
        self.pair_btn.clicked.connect(self._start_pair)
        btns.addWidget(self.pair_btn)
        self.skip_btn = QPushButton(i18n.tr("wifi_skip"))
        self.skip_btn.clicked.connect(self._skip_pair)
        btns.addWidget(self.skip_btn)
        v.addLayout(btns)

        self.code_edit.returnPressed.connect(self._start_pair)
        return page

    def _make_page_connect(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        form = QFormLayout()
        self.ip2_edit = QLineEdit()
        self.ip2_edit.setPlaceholderText("192.168.1.120")
        form.addRow(i18n.tr("wifi_ip"), self.ip2_edit)
        self.conn_port_edit = QLineEdit()
        self.conn_port_edit.setPlaceholderText("37521")
        form.addRow(i18n.tr("wifi_conn_port"), self.conn_port_edit)
        v.addLayout(form)

        btns = QHBoxLayout()
        self.back_btn = QPushButton(i18n.tr("wifi_back"))
        self.back_btn.clicked.connect(self._go_step1)
        btns.addWidget(self.back_btn)
        self.find_port_btn = QPushButton(i18n.tr("wifi_find_port"))
        self.find_port_btn.clicked.connect(self._start_find_port)
        btns.addWidget(self.find_port_btn)
        self.conn_btn = QPushButton(i18n.tr("wifi_connect"))
        self.conn_btn.setDefault(True)
        self.conn_btn.clicked.connect(self._start_connect)
        btns.addWidget(self.conn_btn)
        btns.addStretch(1)
        v.addLayout(btns)

        self.conn_port_edit.returnPressed.connect(self._start_connect)
        return page

    # ------------------------------------------------------ переключение
    def _show_step(self, idx: int):
        self.stack.setCurrentIndex(idx)
        if idx == 0:
            self.step_label.setText(i18n.tr("wifi_step1"))
            self.hint.setText(i18n.tr("wifi_hint1"))
        else:
            self.step_label.setText(i18n.tr("wifi_step2"))
            self.hint.setText(i18n.tr("wifi_hint2"))

    def _go_step1(self):
        self._show_step(0)
        self.ip_edit.setFocus()

    def _go_step2(self):
        ip = self.ip_edit.text().strip()
        if ip:
            self.ip2_edit.setText(ip)
            remembered = wifi_pair.get_secure_port(ip)
            if remembered and not self.conn_port_edit.text().strip():
                self.conn_port_edit.setText(str(remembered))
        self._show_step(1)
        self.conn_port_edit.setFocus()

    def _skip_pair(self):
        """«Уже сопряжено» — сразу к шагу 2 (повторное подключение)."""
        if not self.ip_edit.text().strip():
            self._set_status(i18n.tr("wifi_fail",
                                     err=i18n.tr("wifi_err_input")))
            return
        self._go_step2()

    # ------------------------------------------------------------- запуск
    def _start_find(self):
        self._begin(i18n.tr("wifi_finding"))
        self._spawn(_PairWorker("discover"))

    def _start_find_port(self):
        ip = self.ip2_edit.text().strip() or self.ip_edit.text().strip()
        self._begin(i18n.tr("wifi_finding_port"))
        self._spawn(_PairWorker("discover_conn", ip=ip))

    def _start_pair(self):
        ip = self.ip_edit.text().strip()
        pair_port = self._port(self.pair_port_edit)
        code = self.code_edit.text().strip()
        if not ip or pair_port is None or len(code) != 6 or not code.isdigit():
            self._set_status(i18n.tr("wifi_fail",
                                     err=i18n.tr("wifi_err_input")))
            return
        self._begin(i18n.tr("wifi_working"))
        self._spawn(_PairWorker("pair", ip=ip, pair_port=pair_port, code=code))

    def _start_connect(self):
        ip = self.ip2_edit.text().strip() or self.ip_edit.text().strip()
        conn_port = self._port(self.conn_port_edit)
        if not ip or conn_port is None:
            self._set_status(i18n.tr("wifi_fail",
                                     err=i18n.tr("wifi_err_conn_input")))
            return
        self.ip2_edit.setText(ip)
        self._begin(i18n.tr("wifi_working"))
        self._spawn(_PairWorker("connect", ip=ip, conn_port=conn_port))

    # ------------------------------------------------------------ служебное
    def _begin(self, text: str):
        for btn in (self.find_btn, self.pair_btn, self.skip_btn,
                    self.back_btn, self.find_port_btn, self.conn_btn):
            btn.setEnabled(False)
        self._set_status(text)

    @staticmethod
    def _port(edit) -> "int | None":
        try:
            value = int(edit.text().strip())
        except ValueError:
            return None
        return value if 1 <= value <= 65535 else None

    def _spawn(self, worker: _PairWorker):
        self._thread = QThread(self)
        self._worker = worker
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)
        worker.done.connect(self._on_done)
        self._thread.start()

    def _set_status(self, text: str, ok: bool = False):
        self.status.setText(text)
        self.status.setStyleSheet(_STATUS_OK if ok else _STATUS_ERR)

    # ------------------------------------------------------------- ответ
    def _on_done(self, result: dict):
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
            self._thread = None
            self._worker = None
        for btn in (self.find_btn, self.pair_btn, self.skip_btn,
                    self.back_btn, self.find_port_btn, self.conn_btn):
            btn.setEnabled(True)

        stage = result.get("stage")

        if stage == "discover":
            if result["ok"]:
                ip, port = sorted(result["found"].items())[0]
                self.ip_edit.setText(ip)
                self.pair_port_edit.setText(str(port))
                self._set_status(i18n.tr("wifi_find_ok", ip=ip, port=port),
                                 ok=True)
                self.code_edit.setFocus()
            else:
                self._set_status(i18n.tr("wifi_find_fail"))
            return

        if stage == "discover_conn":
            if result["ok"]:
                found = result["found"]
                wanted = (self.ip2_edit.text().strip()
                          or self.ip_edit.text().strip())
                if wanted in found:
                    ip, port = wanted, found[wanted]
                else:
                    ip, port = sorted(found.items())[0]
                if not self.ip2_edit.text().strip():
                    self.ip2_edit.setText(ip)
                self.conn_port_edit.setText(str(port))
                self._set_status(i18n.tr("wifi_find_port_ok", ip=ip,
                                         port=port), ok=True)
                self.conn_btn.setFocus()
            else:
                self._set_status(i18n.tr("wifi_find_port_fail"))
            return

        if not result["ok"]:
            key = f"wifi_err_{result['code']}"
            text = i18n.tr(key, err=result.get("detail", ""))
            if text == key:                    # нет перевода — общий формат
                text = i18n.tr("wifi_err_generic", err=result.get("detail", ""))
            hint = _error_hint(result.get("detail", ""), result.get("code", ""))
            if hint:
                text = f"{text}. {hint}"
            self._set_status(i18n.tr("wifi_fail", err=text))
            return

        if stage == "pair":
            config.set_key("wifi_last_ip", self.ip_edit.text().strip())
            self._go_step2()
            self._set_status(i18n.tr("wifi_pair_ok", guid=result["guid"]),
                             ok=True)
            return

        # Подключение удалось — добавляем устройство в таблицу
        ip = self.ip2_edit.text().strip()
        port = self._port(self.conn_port_edit) or 0
        config.set_key("wifi_last_ip", ip)
        device = Device(ip=ip, device_type="phone", confidence=90,
                        ports={port} if port else set(),
                        services={"adb"},
                        model=result.get("model", ""),
                        is_new=True)
        self.device = device
        self._set_status(i18n.tr("wifi_conn_ok",
                                 model=result.get("model") or ip), ok=True)
        self.accept()
