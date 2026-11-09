"""ADB-инструментарий: диалог с вкладками поверх adb_actions.

Вкладки: Инфо (батарея/память/диск/экран/риск), Приложения (запуск, остановка,
удаление, отключение, очистка, установка APK), Пульт (D-pad, звук, питание,
ввод текста), Скриншот, Консоль (shell) и Логкат.

Каждая операция выполняется в фоновом потоке (ActionWorker) — интерфейс
не блокируется. Ошибки ActionError переводятся на язык интерфейса.
"""

import datetime
import hashlib
import os
import re

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QImage, QPixmap
from PySide6.QtWidgets import (QApplication, QComboBox, QDialog,
                               QFileDialog, QFormLayout, QGridLayout,
                               QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import adb_actions, exporter, i18n, journal
from .journal_dialog import JournalDialog
from .theme import is_dark_theme

RISK_COLORS = {"low": "#43a047", "medium": "#fb8c00",
               "high": "#f4511e", "critical": "#e53935"}

APPS_COLUMNS = ("pkg", "version", "path")

# Ошибки транспорта на уровне протокола: обычно это кривая/зависшая прошивка,
# а не выключенный ADB — нужна другая подсказка, чем для "connect: ..."
_PROTO_ERR_RE = re.compile(r"corrupted|closed by device|handshake|unexpected packet", re.I)

VT_URL = "https://www.virustotal.com/gui/search/"


def _local_sha256(path: str) -> str:
    """SHA-256 файла на ПК (для проверки пакета на VirusTotal)."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _friendly_error(exc: Exception, ip: str) -> str:
    """ActionError -> понятный локализованный текст."""
    if isinstance(exc, adb_actions.ActionError):
        if exc.code == "unauthorized":
            return i18n.tr("adb_unauthorized")
        if exc.code == "conn":
            key = "adb_conn_protocol" if _PROTO_ERR_RE.search(str(exc)) else "adb_conn"
            return i18n.tr(key, ip=ip, port=5555, error=str(exc)[:150])
        if exc.code == "denied":
            return i18n.tr("files_denied",
                           path=str(exc).rsplit(": ", 1)[-1])
        if exc.code == "nopath":
            return i18n.tr("files_nopath", path=str(exc).rsplit(": ", 1)[-1])
    return str(exc)[:250]


class ActionWorker(QThread):
    """Выполняет fn() в фоне; результат или исключение — сигналом."""

    result = Signal(object, object)          # значение | None, Exception | None

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            self.result.emit(self._fn(), None)
        except Exception as exc:  # noqa: BLE001 — показываем в UI
            self.result.emit(None, exc)


class AdbToolkitDialog(QDialog):
    """Инструментарий ADB для одного устройства."""

    def __init__(self, device, parent=None):
        super().__init__(parent)
        self.device = device
        self.ip = device.ip
        self._workers = []
        self._shell_history = []
        self._shell_index = -1
        self._shot_png = b""
        self._root_info = {}
        self._dev_loaded = False

        self.setWindowTitle(i18n.tr("toolkit_title", ip=self.ip))
        self.resize(760, 600)

        root = QVBoxLayout(self)
        header = QLabel(f"<b>{self.device.model or self.device.hostname or 'Android'}</b>"
                        f" — {self.ip}:5555")
        root.addWidget(header)

        self.risk_label = QLabel(i18n.tr("toolkit_checking"))
        self.risk_label.setWordWrap(True)
        root.addWidget(self.risk_label)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_info(), i18n.tr("tab_adb_info"))
        self._settings_page = self._tab_settings()
        self.tabs.addTab(self._settings_page, i18n.tr("tab_adb_settings"))
        self.tabs.currentChanged.connect(self._maybe_load_settings)
        self.tabs.addTab(self._tab_apps(), i18n.tr("tab_adb_apps"))
        self.tabs.addTab(self._tab_remote(), i18n.tr("tab_adb_remote"))
        self.tabs.addTab(self._tab_screenshot(), i18n.tr("tab_adb_shot"))
        self.tabs.addTab(self._tab_files(), i18n.tr("tab_adb_files"))
        self.tabs.addTab(self._tab_shell(), i18n.tr("tab_adb_shell"))
        self.tabs.addTab(self._tab_logcat(), i18n.tr("tab_adb_logcat"))
        root.addWidget(self.tabs, 1)

        bottom = QHBoxLayout()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        bottom.addWidget(self.status, 1)
        journal_btn = QPushButton(i18n.tr("journal_btn"))
        journal_btn.clicked.connect(self._open_journal)
        bottom.addWidget(journal_btn)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        bottom.addWidget(close_btn)
        root.addLayout(bottom)

        # при открытии: live-проверка root/secure + статистика
        self._run(self._on_root_info, adb_actions.check_root, self.ip)
        self.refresh_stats()

    # ------------------------------------------------------------ инфраструктура
    def _run(self, callback, fn, *args, **kwargs):
        # Отметка действия пользователя в журнале: видно, какую кнопку нажали
        journal.action(getattr(fn, "__name__", "action") or "action", args)
        worker = ActionWorker(lambda: fn(*args, **kwargs), self)
        worker.result.connect(callback)
        self._workers.append(worker)
        worker.start()
        return worker

    def _open_journal(self):
        JournalDialog(self).show()

    def _busy(self, text_key="toolkit_busy"):
        self.status.setText(i18n.tr(text_key))

    def _idle(self):
        self.status.setText("")

    def _failed(self, exc):
        self.status.setText(i18n.tr("toolkit_error", error=_friendly_error(exc, self.ip)))

    # ---------------------------------------------------------------- таб: Инфо
    def _tab_info(self):
        page = QWidget()
        form = QFormLayout(page)
        self.stat_labels = {}
        for key in ("stat_battery", "stat_memory", "stat_disk", "stat_display",
                    "stat_uptime", "stat_device_ip", "stat_root"):
            label = QLabel("—")
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.stat_labels[key] = label
            form.addRow(i18n.tr(key), label)

        btn_row = QHBoxLayout()
        refresh_btn = QPushButton(i18n.tr("stat_refresh"))
        refresh_btn.clicked.connect(self.refresh_stats)
        btn_row.addWidget(refresh_btn)
        btn_row.addStretch(1)
        form.addRow(btn_row)

        reboot_box = QGroupBox(i18n.tr("reboot_group"))
        reboot_row = QHBoxLayout(reboot_box)
        for mode, key in (("", "reboot_normal"), ("recovery", "reboot_recovery"),
                          ("bootloader", "reboot_bootloader")):
            btn = QPushButton(i18n.tr(key))
            btn.clicked.connect(lambda _=False, m=mode: self._reboot(m))
            reboot_row.addWidget(btn)
        form.addRow(reboot_box)
        return page

    # ------------------------------------------------------------ таб: Настройки
    def _tab_settings(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        dev_box = QGroupBox(i18n.tr("dev_group"))
        dev_form = QVBoxLayout(dev_box)
        cur_row = QHBoxLayout()
        cur_row.addWidget(QLabel(i18n.tr("dev_current")))
        self.dev_value_label = QLabel("—")
        self.dev_value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cur_row.addWidget(self.dev_value_label, 1)
        dev_form.addLayout(cur_row)
        hint = QLabel(i18n.tr("dev_hint"))
        hint.setWordWrap(True)
        dev_form.addWidget(hint)
        btn_row = QHBoxLayout()
        self.dev_enable_btn = QPushButton(i18n.tr("dev_enable"))
        self.dev_enable_btn.clicked.connect(lambda: self._toggle_dev(True))
        btn_row.addWidget(self.dev_enable_btn)
        self.dev_disable_btn = QPushButton(i18n.tr("dev_disable"))
        self.dev_disable_btn.clicked.connect(lambda: self._toggle_dev(False))
        btn_row.addWidget(self.dev_disable_btn)
        self.dev_refresh_btn = QPushButton(i18n.tr("dev_refresh"))
        self.dev_refresh_btn.clicked.connect(self.refresh_dev_mode)
        btn_row.addWidget(self.dev_refresh_btn)
        self.dev_open_btn = QPushButton(i18n.tr("dev_open_menu"))
        self.dev_open_btn.clicked.connect(self._open_dev_menu)
        btn_row.addWidget(self.dev_open_btn)
        btn_row.addStretch(1)
        dev_form.addLayout(btn_row)
        layout.addWidget(dev_box)

        set_box = QGroupBox(i18n.tr("set_group"))
        set_form = QVBoxLayout(set_box)
        ns_row = QHBoxLayout()
        ns_row.addWidget(QLabel(i18n.tr("set_ns")))
        self.set_ns = QComboBox()
        for ns in adb_actions.SETTING_NAMESPACES:
            self.set_ns.addItem(ns, ns)
        ns_row.addWidget(self.set_ns)
        ns_row.addWidget(QLabel(i18n.tr("set_key")))
        self.set_key_input = QLineEdit()
        self.set_key_input.setPlaceholderText(adb_actions.DEV_SETTINGS_KEY)
        ns_row.addWidget(self.set_key_input, 1)
        set_form.addLayout(ns_row)

        val_row = QHBoxLayout()
        val_row.addWidget(QLabel(i18n.tr("set_value")))
        self.set_value_input = QLineEdit()
        self.set_value_input.setPlaceholderText("1")
        val_row.addWidget(self.set_value_input, 1)
        self.set_get_btn = QPushButton(i18n.tr("set_get_btn"))
        self.set_get_btn.clicked.connect(self._setting_get)
        val_row.addWidget(self.set_get_btn)
        self.set_put_btn = QPushButton(i18n.tr("set_put_btn"))
        self.set_put_btn.clicked.connect(self._setting_put)
        val_row.addWidget(self.set_put_btn)
        set_form.addLayout(val_row)

        self.settings_output = QPlainTextEdit()
        self.settings_output.setReadOnly(True)
        self.settings_output.setPlaceholderText(i18n.tr("set_placeholder"))
        set_form.addWidget(self.settings_output, 1)
        layout.addWidget(set_box)
        layout.addStretch(1)
        return page

    def _maybe_load_settings(self, index):
        """Значение флага читается при первом открытии вкладки, а не при
        старте диалога — лишнее соединение только по запросу."""
        if not self._dev_loaded and self.tabs.widget(index) is self._settings_page:
            self.refresh_dev_mode()

    def refresh_dev_mode(self):
        self._busy()
        self._run(self._on_dev_value, adb_actions.get_setting,
                  self.ip, "global", adb_actions.DEV_SETTINGS_KEY)

    def _on_dev_value(self, value, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self._dev_loaded = True
        text = (value or "").strip()
        if text == "null":
            shown = i18n.tr("dev_value_null")
        elif text == "1":
            shown = i18n.tr("dev_value_on")
        elif text == "0":
            shown = i18n.tr("dev_value_off")
        else:
            shown = text or "—"
        self.dev_value_label.setText(shown)

    def _toggle_dev(self, enable):
        self.dev_enable_btn.setEnabled(False)
        self.dev_disable_btn.setEnabled(False)
        self._busy()
        self._run(lambda value, exc: self._on_dev_toggled(enable, value, exc),
                  adb_actions.set_developer_mode, self.ip, enable)

    def _on_dev_toggled(self, enable, value, exc):
        self.dev_enable_btn.setEnabled(True)
        self.dev_disable_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._on_dev_value(value, None)
        self.status.setText(i18n.tr("dev_enable_ok" if enable
                                    else "dev_disable_ok"))

    def _open_dev_menu(self):
        self.dev_open_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_dev_menu(out, exc),
                  adb_actions.open_developer_settings, self.ip)

    def _on_dev_menu(self, output, exc):
        self.dev_open_btn.setEnabled(True)
        self._append_settings("$ am start -a " + adb_actions.DEV_SETTINGS_ACTION,
                              "" if exc else (output or ""))
        if exc:
            self._failed(exc)
            return
        self.status.setText(i18n.tr("dev_opened"))

    def _setting_get(self):
        key = self.set_key_input.text().strip()
        if not key:
            self.status.setText(i18n.tr("set_key_required"))
            return
        ns = self.set_ns.currentData()
        self.set_get_btn.setEnabled(False)
        self._busy()
        self._run(lambda value, exc: self._on_setting_get(ns, key, value, exc),
                  adb_actions.get_setting, self.ip, ns, key)

    def _on_setting_get(self, ns, key, value, exc):
        self.set_get_btn.setEnabled(True)
        command = f"$ settings get {ns} {key}"
        if exc:
            self._append_settings(command, "")
            self._failed(exc)
            return
        self._idle()
        self._append_settings(command, (value or "").strip())
        self.status.setText(i18n.tr("set_get_done", ns=ns, name=key,
                                    value=(value or "").strip() or "—"))
        if ns == "global" and key == adb_actions.DEV_SETTINGS_KEY:
            self._on_dev_value(value, None)

    def _setting_put(self):
        key = self.set_key_input.text().strip()
        if not key:
            self.status.setText(i18n.tr("set_key_required"))
            return
        ns = self.set_ns.currentData()
        value = self.set_value_input.text()
        self.set_put_btn.setEnabled(False)
        self._busy()
        self._run(lambda shown, exc: self._on_setting_put(ns, key, value,
                                                          shown, exc),
                  self._put_and_verify, ns, key, value)

    def _put_and_verify(self, ns, key, value):
        """Запись + контрольное чтение (в фоновом потоке)."""
        adb_actions.put_setting(self.ip, ns, key, value)
        return adb_actions.get_setting(self.ip, ns, key)

    def _on_setting_put(self, ns, key, value, shown, exc):
        self.set_put_btn.setEnabled(True)
        command = f"$ settings put {ns} {key} {value}".rstrip()
        if exc:
            self._append_settings(command, "")
            self._failed(exc)
            return
        self._idle()
        self._append_settings(
            command,
            i18n.tr("set_put_done", ns=ns, name=key,
                    value=(shown or "").strip() or "—"))
        self.status.setText(i18n.tr("set_put_done", ns=ns, name=key,
                                    value=(shown or "").strip() or "—"))
        if ns == "global" and key == adb_actions.DEV_SETTINGS_KEY:
            self._on_dev_value(shown, None)

    def _append_settings(self, command, output):
        """Транскрипт команды в поле вывода вкладки настроек."""
        box = self.settings_output
        box.appendPlainText(command)
        box.appendPlainText(output.rstrip() or i18n.tr("shell_empty"))
        box.appendPlainText("")

    def refresh_stats(self):
        self._busy()
        self._run(self._on_stats, adb_actions.read_stats, self.ip)

    def _on_stats(self, stats, exc):
        if exc:
            self._failed(exc)
            for label in self.stat_labels.values():
                label.setText("—")
            return
        self._idle()
        stats = stats or {}
        battery = stats.get("battery") or {}
        if battery.get("level") is not None:
            charging = i18n.tr("stat_charging") if battery.get("charging") \
                else i18n.tr("stat_discharging")
            temp = battery.get("temp_c")
            temp_text = f", {temp} °C" if temp is not None else ""
            self.stat_labels["stat_battery"].setText(
                i18n.tr("stat_battery_fmt", level=battery["level"],
                        charging=charging, extra=temp_text))
        else:
            self.stat_labels["stat_battery"].setText("—")
        memory = stats.get("memory") or {}
        self.stat_labels["stat_memory"].setText(
            i18n.tr("stat_memory_fmt", total=memory.get("total_mb", "?"),
                    used=memory.get("used_pct", "?")) if memory else "—")
        disk = stats.get("disk") or {}
        self.stat_labels["stat_disk"].setText(
            i18n.tr("stat_disk_fmt", total=disk.get("total_mb", "?"),
                    used=disk.get("used_pct", "?"),
                    mount=disk.get("mount", "?")) if disk else "—")
        display = stats.get("display") or {}
        self.stat_labels["stat_display"].setText(
            i18n.tr("stat_display_fmt", size=display.get("size", "?"),
                    density=display.get("density", "?")) if display else "—")
        uptime = stats.get("uptime_sec")
        if uptime:
            days, rest = divmod(int(uptime), 86400)
            hours, minutes = divmod(rest // 60, 60)
            self.stat_labels["stat_uptime"].setText(
                i18n.tr("stat_uptime_fmt", days=days, hours=hours, minutes=minutes))
        else:
            self.stat_labels["stat_uptime"].setText("—")
        self.stat_labels["stat_device_ip"].setText(stats.get("device_ip") or "—")
        self._update_root_label()

    def _on_root_info(self, info, exc):
        if exc:
            self._failed(exc)
            return
        self._root_info = info or {}
        self._update_root_label()
        self._update_risk()

    def _update_root_label(self):
        if not self._root_info:
            return
        uid = self._root_info.get("uid")
        user = self._root_info.get("user", "?")
        if uid is not None:
            root_note = " — ROOT!" if uid == 0 else ""
            self.stat_labels["stat_root"].setText(
                f"uid={uid} ({user}){root_note} | su: "
                + (self._root_info.get("su_path") or "—"))

    def _update_risk(self):
        """Риск-бейдж: live-данные + свойства из последнего опроса."""
        info = self._root_info
        risk = adb_actions.assess_risk(
            self.device.extras,
            uid=info.get("uid"),
            adb_secure=info.get("adb_secure", ""),
            su_found=bool(info.get("su_found")),
            security_patch=info.get("security_patch", ""),
            sdk=info.get("sdk", ""),
            android_version=info.get("android_version", ""))
        color = RISK_COLORS.get(risk["level"], "#888888")
        level_text = i18n.tr("risk_level_" + risk["level"])
        self.risk_label.setStyleSheet(
            f"color: {color}; font-weight: 600;"
            if is_dark_theme() else f"color: {color}; font-weight: 600;")
        lines = [i18n.tr("risk_line", level=level_text, score=risk["score"])]
        lines += ["• " + i18n.tr(key) for key in risk["findings"]]
        if risk["recommendations"]:
            lines.append("")
            lines += ["→ " + i18n.tr(key) for key in risk["recommendations"]]
        self.risk_label.setText("\n".join(lines))

    def _reboot(self, mode):
        answer = QMessageBox.question(
            self, i18n.tr("confirm_title"),
            i18n.tr("reboot_question", ip=self.ip,
                    mode=i18n.tr("reboot_" + (mode or "normal"))),
            QMessageBox.Yes | QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        self._busy()
        self._run(lambda ok, exc: self._on_reboot(exc),
                  adb_actions.reboot, self.ip, mode)

    def _on_reboot(self, exc):
        if exc:
            self._failed(exc)
        else:
            self.status.setText(i18n.tr("reboot_sent"))

    # ------------------------------------------------------------ таб: Приложения
    def _tab_apps(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.addWidget(QLabel(i18n.tr("apps_kind")))
        self.apps_kind = QComboBox()
        self.apps_kind.addItem(i18n.tr("apps_kind_third"), "third")
        self.apps_kind.addItem(i18n.tr("apps_kind_system"), "system")
        self.apps_kind.addItem(i18n.tr("apps_kind_all"), "all")
        top.addWidget(self.apps_kind)
        self.apps_refresh_btn = QPushButton(i18n.tr("apps_refresh"))
        self.apps_refresh_btn.clicked.connect(self.refresh_apps)
        top.addWidget(self.apps_refresh_btn)
        top.addSpacing(12)
        top.addWidget(QLabel(i18n.tr("apps_search")))
        self.apps_search = QLineEdit()
        self.apps_search.setPlaceholderText(i18n.tr("apps_search_hint"))
        self.apps_search.setClearButtonEnabled(True)
        self.apps_search.textChanged.connect(self._filter_apps)
        top.addWidget(self.apps_search, 1)
        layout.addLayout(top)

        self.apps_tree = QTreeWidget()
        self.apps_tree.setHeaderLabels([i18n.tr("apps_col_pkg"),
                                        i18n.tr("apps_col_ver"),
                                        i18n.tr("apps_col_origin"),
                                        i18n.tr("apps_col_path")])
        self.apps_tree.setRootIsDecorated(False)
        self.apps_tree.setAlternatingRowColors(True)
        self.apps_tree.header().resizeSection(0, 210)
        self.apps_tree.header().resizeSection(2, 90)
        self.apps_tree.itemDoubleClicked.connect(lambda *_: self._app_details())
        layout.addWidget(self.apps_tree, 1)

        actions = QHBoxLayout()
        for attr, handler in (("apps_run", self._app_launch),
                              ("apps_stop", self._app_stop),
                              ("apps_uninstall", self._app_uninstall),
                              ("apps_disable", self._app_disable),
                              ("apps_enable", self._app_enable),
                              ("apps_clear", self._app_clear)):
            btn = QPushButton(i18n.tr(attr))
            btn.clicked.connect(handler)
            actions.addWidget(btn)
        layout.addLayout(actions)

        actions2 = QHBoxLayout()
        details_btn = QPushButton(i18n.tr("apps_info"))
        details_btn.clicked.connect(self._app_details)
        actions2.addWidget(details_btn)
        self.apk_btn = QPushButton(i18n.tr("apps_apk_dl"))
        self.apk_btn.clicked.connect(self._app_apk)
        actions2.addWidget(self.apk_btn)
        self.install_btn = QPushButton(i18n.tr("apps_install"))
        self.install_btn.clicked.connect(self._install_apk)
        actions2.addWidget(self.install_btn)
        self.export_btn = QPushButton(i18n.tr("apps_export"))
        self.export_btn.clicked.connect(self._export_apps)
        self.export_btn.setToolTip(i18n.tr("apps_export_saving"))
        actions2.addWidget(self.export_btn)
        actions2.addStretch(1)
        layout.addLayout(actions2)
        return page

    def _apps_status_text(self, total: int) -> str:
        text = i18n.tr("apps_found", count=total)
        if not total:
            # Пусто — часто у pm на кривых прошивках: подсказываем, где
            # посмотреть сырой ответ (журнал) и что попробовать ещё раз
            text += " " + i18n.tr("apps_none_hint")
        return text

    def _filter_apps(self, _text=""):
        """Прячет строки, где поиск не встречается ни в одной колонке."""
        needle = self.apps_search.text().strip().lower()
        shown = 0
        total = self.apps_tree.topLevelItemCount()
        for index in range(total):
            item = self.apps_tree.topLevelItem(index)
            match = not needle or any(
                needle in (item.text(col) or "").lower()
                for col in range(self.apps_tree.columnCount()))
            item.setHidden(not match)
            shown += match
        if needle:
            self.status.setText(i18n.tr("apps_filter_found",
                                        shown=shown, total=total))
        elif getattr(self, "_apps_total", None) is not None:
            # поиск очищен — возвращаем статус последнего обновления списка
            self.status.setText(self._apps_status_text(self._apps_total))

    def refresh_apps(self):
        kind = self.apps_kind.currentData() or "third"
        self._busy()
        self.apps_refresh_btn.setEnabled(False)
        self._run(self._on_apps, adb_actions.list_apps, self.ip, kind)

    def _on_apps(self, apps, exc):
        self.apps_refresh_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.apps_tree.clear()
        origin_keys = {"system": "apps_origin_system",
                       "third": "apps_origin_third"}
        for app in apps or []:
            # version/path/origin пустые, если обогащение не добрало данных
            origin_key = origin_keys.get(app.get("origin", ""),
                                         "apps_origin_unknown")
            item = QTreeWidgetItem([app["package"], app.get("version") or "",
                                    i18n.tr(origin_key), app.get("path", "")])
            item.setData(0, Qt.UserRole, app["package"])
            self.apps_tree.addTopLevelItem(item)
        self._apps_total = len(apps or [])
        self.status.setText(self._apps_status_text(self._apps_total))
        self._filter_apps()          # применяем активный поиск к новому списку

    # ------------------------------------------------------- выгрузка для ИИ
    def _export_apps(self):
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("apps_export"), "droidscout_apps.csv",
            "CSV (*.csv);;JSON (*.json)")
        if not path:
            return
        self.export_btn.setEnabled(False)
        self._busy("apps_export_saving")
        self._run(lambda count, exc: self._on_export(path, count, exc),
                  self._collect_and_export, self.ip, path)

    @staticmethod
    def _collect_and_export(host, path):
        """Полный список с устройства -> файл на ПК. Возвращает число пакетов.

        Выполняется в ActionWorker: подключений несколько, на кривых
        прошивках это может занять до минуты.
        """
        apps = adb_actions.collect_apps(host)
        if not apps:
            raise adb_actions.ActionError(
                "pm list вернул ноль пакетов (сырые ответы — в журнале)", "")
        if path.lower().endswith(".json"):
            exporter.export_apps_json(path, apps)
        else:
            exporter.export_apps_csv(path, apps)
        return len(apps)

    def _on_export(self, path, count, exc):
        self.export_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self.status.setText(i18n.tr("apps_export_saved", path=path, count=count))

    def _app_apk(self):
        """APK выбранного приложения -> файл на ПК (base + сплиты)."""
        item = self.apps_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("apps_select"))
            return
        package = item.data(0, Qt.UserRole) or item.text(0)
        # колонка «APK» — запасной путь на случай, если pm path молчит
        fallback = item.text(3)
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("apps_apk_dl"), f"{package}.apk",
            "APK (*.apk);;All files (*)")
        if not path:
            return
        self.apk_btn.setEnabled(False)
        self._busy("apps_apk_saving")
        self._run(lambda saved, exc: self._on_app_apk(path, saved, exc),
                  adb_actions.download_app_apk, self.ip, package, path,
                  fallback)

    def _on_app_apk(self, dest, saved, exc):
        self.apk_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        saved = saved or [dest]
        self.status.setText(i18n.tr("apps_apk_saved",
                                    count=len(saved), path=saved[0]))
        sha = _local_sha256(saved[0])
        if not sha:
            return
        QApplication.clipboard().setText(sha)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle(i18n.tr("apps_apk_dl"))
        box.setText(i18n.tr("apps_sha256_line", count=len(saved),
                            path=saved[0], sha=sha))
        vt_btn = box.addButton(i18n.tr("apps_vt_open"), QMessageBox.ActionRole)
        box.addButton(QMessageBox.Ok)
        box.exec()
        if box.clickedButton() is vt_btn:
            QDesktopServices.openUrl(QUrl(VT_URL + sha))

    def _selected_package(self):
        item = self.apps_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("apps_select"))
            return ""
        return item.data(0, Qt.UserRole)

    def _app_act(self, action, confirm_key=None):
        package = self._selected_package()
        if not package:
            return
        if confirm_key:
            answer = QMessageBox.question(
                self, i18n.tr("confirm_title"),
                i18n.tr(confirm_key, pkg=package),
                QMessageBox.Yes | QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        self._busy()
        self._run(lambda out, exc: self._on_app_action(out, exc),
                  adb_actions.app_action, self.ip, package, action)

    def _on_app_action(self, output, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.status.setText(i18n.tr("apps_done",
                                    output=(output or "").strip().splitlines()[-1]
                                    if (output or "").strip() else "OK"))

    def _app_launch(self):
        self._app_act("launch")

    def _app_stop(self):
        self._app_act("stop")

    def _app_uninstall(self):
        self._app_act("uninstall", "apps_confirm_uninstall")

    def _app_disable(self):
        self._app_act("disable", "apps_confirm_disable")

    def _app_enable(self):
        self._app_act("enable")

    def _app_clear(self):
        self._app_act("clear", "apps_confirm_clear")

    def _app_details(self):
        package = self._selected_package()
        if not package:
            return
        item = self.apps_tree.currentItem()
        fallback = item.text(3) if item else ""
        self._busy()
        self._run(lambda out, exc: self._on_app_details(package, out, exc),
                  adb_actions.app_details, self.ip, package,
                  fallback_path=fallback)

    def _on_app_details(self, package, details, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        details = details or {}
        state = i18n.tr("apps_stopped")
        if details.get("running"):
            state = i18n.tr("apps_running", pid=details.get("pid") or "?")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Information)
        box.setWindowTitle(i18n.tr("apps_details_title", pkg=package))
        box.setText(i18n.tr(
            "apps_details_fmt",
            version=details.get("version", "—"),
            code=details.get("code", "—"),
            installed=details.get("installed", "—"),
            updated=details.get("updated", "—"),
            sdk=details.get("target_sdk", "—"),
            path=details.get("path", "—"),
            state=state,
            sha256=details.get("sha256") or "—"))
        vt_btn = None
        if details.get("sha256"):
            vt_btn = box.addButton(i18n.tr("apps_vt_open"),
                                   QMessageBox.ActionRole)
        box.addButton(QMessageBox.Ok)
        box.exec()
        if vt_btn is not None and box.clickedButton() is vt_btn:
            QDesktopServices.openUrl(QUrl(VT_URL + details["sha256"]))

    def _install_apk(self):
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("apps_install"), os.path.expanduser("~"),
            "APK (*.apk);;All files (*)")
        if not path:
            return
        self.install_btn.setEnabled(False)
        self._busy("apps_installing")
        self._run(lambda out, exc: self._on_install(out, exc),
                  adb_actions.install_apk, self.ip, path)

    def _on_install(self, output, exc):
        self.install_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.status.setText(i18n.tr("apps_install_done",
                                    output=(output or "").strip()[:200] or "OK"))

    # ---------------------------------------------------------------- таб: Пульт
    def _tab_remote(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        grid_box = QGroupBox(i18n.tr("remote_group"))
        grid = QGridLayout(grid_box)
        grid.setSpacing(6)

        def key_button(text, key, min_width=0):
            btn = QPushButton(text)
            btn.setMinimumHeight(34)
            if min_width:
                btn.setMinimumWidth(min_width)
            btn.clicked.connect(lambda _=False, k=key: self._send_key(k))
            return btn

        grid.addWidget(key_button(i18n.tr("remote_power"), "power"), 0, 0)
        grid.addWidget(key_button("Vol +", "vol_up"), 0, 1)
        grid.addWidget(key_button("Vol −", "vol_down"), 0, 2)
        grid.addWidget(key_button(i18n.tr("remote_mute"), "mute"), 0, 3)

        grid.addWidget(QLabel(""), 1, 0)
        grid.addWidget(key_button("▲", "up"), 1, 1)
        grid.addWidget(QLabel(""), 1, 2)
        grid.addWidget(key_button(i18n.tr("remote_menu"), "menu"), 1, 3)

        grid.addWidget(key_button("◀", "left"), 2, 0)
        grid.addWidget(key_button("OK", "ok", min_width=56), 2, 1)
        grid.addWidget(key_button("▶", "right"), 2, 2)
        grid.addWidget(key_button(i18n.tr("remote_play"), "play_pause"), 2, 3)

        grid.addWidget(QLabel(""), 3, 0)
        grid.addWidget(key_button("▼", "down"), 3, 1)
        grid.addWidget(QLabel(""), 3, 2)
        grid.addWidget(key_button(i18n.tr("remote_stop"), "stop"), 3, 3)

        grid.addWidget(key_button(i18n.tr("remote_home"), "home"), 4, 0)
        grid.addWidget(key_button(i18n.tr("remote_back"), "back"), 4, 1)
        grid.addWidget(key_button("◀◀", "rewind"), 4, 2)
        grid.addWidget(key_button("▶▶", "forward"), 4, 3)
        outer.addWidget(grid_box)

        text_row = QHBoxLayout()
        self.remote_text = QLineEdit()
        self.remote_text.setPlaceholderText(i18n.tr("remote_text_hint"))
        self.remote_text.returnPressed.connect(self._send_text)
        text_row.addWidget(self.remote_text, 1)
        send_btn = QPushButton(i18n.tr("remote_send"))
        send_btn.clicked.connect(self._send_text)
        text_row.addWidget(send_btn)
        outer.addLayout(text_row)
        outer.addStretch(1)
        return page

    def _send_key(self, key):
        self._busy()
        self._run(lambda _out, exc: self._on_key(exc),
                  adb_actions.send_key, self.ip, key)

    def _on_key(self, exc):
        if exc:
            self._failed(exc)
        else:
            self._idle()

    def _send_text(self):
        text = self.remote_text.text().strip()
        if not text:
            return
        self._busy()
        self._run(lambda _out, exc: self._on_key(exc),
                  adb_actions.send_text, self.ip, text)

    # ------------------------------------------------------------- таб: Скриншот
    def _tab_screenshot(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.shot_label = QLabel(i18n.tr("shot_placeholder"))
        self.shot_label.setAlignment(Qt.AlignCenter)
        self.shot_label.setMinimumSize(420, 260)
        layout.addWidget(self.shot_label, 1)

        row = QHBoxLayout()
        self.shot_btn = QPushButton(i18n.tr("shot_take"))
        self.shot_btn.clicked.connect(self.take_screenshot)
        row.addWidget(self.shot_btn)
        self.shot_save_btn = QPushButton(i18n.tr("shot_save"))
        self.shot_save_btn.setEnabled(False)
        self.shot_save_btn.clicked.connect(self.save_screenshot)
        row.addWidget(self.shot_save_btn)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    def take_screenshot(self):
        self.shot_btn.setEnabled(False)
        self._busy("shot_saving")
        self._run(lambda png, exc: self._on_shot(png, exc),
                  adb_actions.screenshot, self.ip)

    def _on_shot(self, png, exc):
        self.shot_btn.setEnabled(True)
        if exc:
            self.shot_save_btn.setEnabled(False)
            self._failed(exc)
            return
        self._idle()
        self._shot_png = png or b""
        image = QImage.fromData(self._shot_png)
        if not image.isNull():
            self.shot_label.setPixmap(QPixmap.fromImage(image).scaled(
                self.shot_label.width() or 420, self.shot_label.height() or 260,
                Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.shot_save_btn.setEnabled(bool(self._shot_png))
        self.status.setText(i18n.tr("shot_done"))

    def save_screenshot(self):
        if not self._shot_png:
            return
        default = os.path.join(
            os.path.expanduser("~"), "droidscout_"
            + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".png")
        path, _ = QFileDialog.getSaveFileName(self, i18n.tr("shot_save"),
                                              default, "PNG (*.png)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self._shot_png)
            self.status.setText(i18n.tr("shot_saved", path=path))
        except OSError as exc:
            self.status.setText(i18n.tr("toolkit_error", error=str(exc)[:200]))

    # --------------------------------------------------------------- таб: Файлы
    QUICK_DIRS = ("/system", "/vendor", "/data", "/data/local/tmp", "/sdcard")

    def _tab_files(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        top = QHBoxLayout()
        top.addWidget(QLabel(i18n.tr("files_path")))
        self.files_path = QLineEdit("/")
        self.files_path.returnPressed.connect(self.refresh_files)
        top.addWidget(self.files_path, 1)
        self.files_up_btn = QPushButton(i18n.tr("files_up"))
        self.files_up_btn.clicked.connect(self._files_up)
        top.addWidget(self.files_up_btn)
        self.files_refresh_btn = QPushButton(i18n.tr("files_refresh"))
        self.files_refresh_btn.clicked.connect(self.refresh_files)
        top.addWidget(self.files_refresh_btn)
        layout.addLayout(top)

        quick = QHBoxLayout()
        quick.addWidget(QLabel(i18n.tr("files_quick")))
        for place in self.QUICK_DIRS:
            btn = QPushButton(place)
            btn.clicked.connect(lambda _=False, p=place: self._files_goto(p))
            quick.addWidget(btn)
        quick.addStretch(1)
        layout.addLayout(quick)

        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels([i18n.tr("files_col_name"),
                                         i18n.tr("files_col_perms"),
                                         i18n.tr("files_col_size"),
                                         i18n.tr("files_col_date")])
        self.files_tree.setRootIsDecorated(False)
        self.files_tree.setAlternatingRowColors(True)
        self.files_tree.header().resizeSection(0, 280)
        self.files_tree.header().resizeSection(1, 110)
        self.files_tree.header().resizeSection(2, 80)
        self.files_tree.itemDoubleClicked.connect(self._files_open)
        layout.addWidget(self.files_tree, 1)

        actions = QHBoxLayout()
        self.files_download_btn = QPushButton(i18n.tr("files_download"))
        self.files_download_btn.clicked.connect(self._file_download)
        actions.addWidget(self.files_download_btn)
        actions.addStretch(1)
        layout.addLayout(actions)
        return page

    def _files_join(self, name: str) -> str:
        base = self.files_path.text().strip() or "/"
        return base + name if base == "/" else base.rstrip("/") + "/" + name

    def refresh_files(self):
        self._busy()
        self.files_refresh_btn.setEnabled(False)
        self._run(self._on_files, adb_actions.list_dir, self.ip,
                  self.files_path.text().strip() or "/")

    def _on_files(self, listing, exc):
        self.files_refresh_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.files_tree.clear()
        entries = (listing or {}).get("entries", [])
        for entry in entries:
            label = entry["name"] + (f" -> {entry['target']}"
                                     if entry.get("target") else "")
            item = QTreeWidgetItem([label, entry.get("perms", ""),
                                    entry.get("size", ""),
                                    entry.get("date", "")])
            item.setData(0, Qt.UserRole, entry)
            self.files_tree.addTopLevelItem(item)
        self.status.setText(i18n.tr("files_listed",
                                    path=(listing or {}).get("path", ""),
                                    count=len(entries)))

    def _files_goto(self, path: str):
        self.files_path.setText(path or "/")
        self.refresh_files()

    def _files_up(self):
        path = self.files_path.text().strip() or "/"
        parent = os.path.dirname(path.rstrip("/")) if path != "/" else ""
        self._files_goto(parent or "/")

    def _files_open(self, item, _column):
        entry = item.data(0, Qt.UserRole) or {}
        name = entry.get("name", "")
        if not name:
            return
        if entry.get("target"):          # симлинк на абсолютный путь
            target = entry["target"]
            if target.startswith("/"):
                self._files_goto(target)
                return
        if not entry.get("is_dir"):
            return
        self._files_goto(self._files_join(name))

    def _file_download(self):
        item = self.files_tree.currentItem()
        if not item:
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("files_select"))
            return
        entry = item.data(0, Qt.UserRole) or {}
        if entry.get("is_dir"):
            QMessageBox.information(self, i18n.tr("adb_result"),
                                    i18n.tr("files_is_dir"))
            return
        remote = self._files_join(entry.get("name", "file"))
        path, _ = QFileDialog.getSaveFileName(
            self, i18n.tr("files_download"), entry.get("name", "file"),
            "All files (*)")
        if not path:
            return
        self.files_download_btn.setEnabled(False)
        self._busy("files_downloading")
        self._run(lambda data, exc: self._on_file_data(path, data, exc),
                  adb_actions.pull_file, self.ip, remote)

    def _on_file_data(self, path, data, exc):
        self.files_download_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        try:
            with open(path, "wb") as f:
                f.write(data or b"")
        except OSError as e:
            self._failed(adb_actions.ActionError(str(e), ""))
            return
        self.status.setText(i18n.tr("files_saved", path=path,
                                    count=len(data or b"")))

    # --------------------------------------------------------------- таб: Консоль
    def _tab_shell(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.shell_output = QPlainTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setPlaceholderText(i18n.tr("shell_placeholder_out"))
        layout.addWidget(self.shell_output, 1)

        row = QHBoxLayout()
        self.shell_input = QLineEdit()
        self.shell_input.setPlaceholderText(i18n.tr("shell_hint"))
        self.shell_input.returnPressed.connect(self.run_shell)
        row.addWidget(self.shell_input, 1)
        self.shell_run_btn = QPushButton(i18n.tr("shell_run"))
        self.shell_run_btn.clicked.connect(self.run_shell)
        row.addWidget(self.shell_run_btn)
        layout.addLayout(row)

        hint = QLabel(i18n.tr("shell_warning"))
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return page

    def run_shell(self):
        command = self.shell_input.text().strip()
        if not command:
            return
        self._shell_history.append(command)
        self._shell_index = len(self._shell_history)
        self.shell_run_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_shell(out, exc),
                  adb_actions.shell, self.ip, command)

    def _on_shell(self, output, exc):
        self.shell_run_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.shell_output.appendPlainText("$ " + (self._shell_history[-1]
                                                  if self._shell_history else ""))
        self.shell_output.appendPlainText(output.rstrip()
                                          or i18n.tr("shell_empty"))
        self.shell_output.appendPlainText("")

    def keyPressEvent(self, event):
        # история команд стрелками в консоли
        if self.tabs.currentWidget() is not None and \
                self.shell_input.hasFocus() and self._shell_history:
            if event.key() == Qt.Key_Up:
                self._shell_index = max(0, self._shell_index - 1)
                self.shell_input.setText(self._shell_history[self._shell_index])
                return
            if event.key() == Qt.Key_Down:
                self._shell_index = min(len(self._shell_history),
                                        self._shell_index + 1)
                text = (self._shell_history[self._shell_index]
                        if self._shell_index < len(self._shell_history) else "")
                self.shell_input.setText(text)
                return
        super().keyPressEvent(event)

    # --------------------------------------------------------------- таб: Логкат
    def _tab_logcat(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        row.addWidget(QLabel(i18n.tr("logcat_level")))
        self.logcat_level = QComboBox()
        for name, data in (("V", "V"), ("D", "D"), ("I", "I"),
                           ("W", "W"), ("E", "E")):
            self.logcat_level.addItem(name, data)
        self.logcat_level.setCurrentIndex(3)
        row.addWidget(self.logcat_level)
        row.addWidget(QLabel(i18n.tr("logcat_lines")))
        self.logcat_count = QSpinBox()
        self.logcat_count.setRange(50, 5000)
        self.logcat_count.setValue(300)
        self.logcat_count.setSingleStep(100)
        row.addWidget(self.logcat_count)
        self.logcat_refresh_btn = QPushButton(i18n.tr("logcat_refresh"))
        self.logcat_refresh_btn.clicked.connect(self.refresh_logcat)
        row.addWidget(self.logcat_refresh_btn)
        clear_btn = QPushButton(i18n.tr("logcat_clear"))
        clear_btn.clicked.connect(self.clear_logcat)
        row.addWidget(clear_btn)
        save_btn = QPushButton(i18n.tr("logcat_save"))
        save_btn.clicked.connect(self.save_logcat)
        row.addWidget(save_btn)
        row.addStretch(1)
        layout.addLayout(row)

        self.logcat_output = QPlainTextEdit()
        self.logcat_output.setReadOnly(True)
        layout.addWidget(self.logcat_output, 1)
        return page

    def refresh_logcat(self):
        self.logcat_refresh_btn.setEnabled(False)
        self._busy()
        self._run(lambda out, exc: self._on_logcat(out, exc),
                  adb_actions.logcat_dump, self.ip,
                  self.logcat_count.value(), self.logcat_level.currentData())

    def _on_logcat(self, output, exc):
        self.logcat_refresh_btn.setEnabled(True)
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.logcat_output.setPlainText(output or "")

    def clear_logcat(self):
        self._busy()
        self._run(lambda _out, exc: self._on_logcat_clear(exc),
                  adb_actions.logcat_clear, self.ip)

    def _on_logcat_clear(self, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        self.logcat_output.setPlainText("")

    def save_logcat(self):
        text = self.logcat_output.toPlainText()
        if not text:
            return
        default = os.path.join(
            os.path.expanduser("~"), "droidscout_logcat_"
            + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + ".log")
        path, _ = QFileDialog.getSaveFileName(self, i18n.tr("logcat_save"),
                                              default, "Log (*.log *.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            self.status.setText(i18n.tr("logcat_saved", path=path))
        except OSError as exc:
            self.status.setText(i18n.tr("toolkit_error", error=str(exc)[:200]))
