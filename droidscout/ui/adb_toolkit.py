"""ADB-инструментарий: диалог с вкладками поверх adb_actions.

Вкладки: Инфо (батарея/память/диск/экран/риск), Приложения (запуск, остановка,
удаление, отключение, очистка, установка APK), Пульт (D-pad, звук, питание,
ввод текста), Скриншот, Консоль (shell) и Логкат.

Каждая операция выполняется в фоновом потоке (ActionWorker) — интерфейс
не блокируется. Ошибки ActionError переводятся на язык интерфейса.
"""

import datetime
import os

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (QComboBox, QDialog, QFileDialog, QFormLayout,
                               QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QSpinBox, QTabWidget, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import adb_actions, i18n
from .theme import is_dark_theme

RISK_COLORS = {"low": "#43a047", "medium": "#fb8c00",
               "high": "#f4511e", "critical": "#e53935"}

APPS_COLUMNS = ("pkg", "version", "path")


def _friendly_error(exc: Exception, ip: str) -> str:
    """ActionError -> понятный локализованный текст."""
    if isinstance(exc, adb_actions.ActionError):
        if exc.code == "unauthorized":
            return i18n.tr("adb_unauthorized")
        if exc.code == "conn":
            return i18n.tr("adb_conn", ip=ip, port=5555, error=str(exc)[:150])
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
        self.tabs.addTab(self._tab_apps(), i18n.tr("tab_adb_apps"))
        self.tabs.addTab(self._tab_remote(), i18n.tr("tab_adb_remote"))
        self.tabs.addTab(self._tab_screenshot(), i18n.tr("tab_adb_shot"))
        self.tabs.addTab(self._tab_shell(), i18n.tr("tab_adb_shell"))
        self.tabs.addTab(self._tab_logcat(), i18n.tr("tab_adb_logcat"))
        root.addWidget(self.tabs, 1)

        bottom = QHBoxLayout()
        self.status = QLabel("")
        self.status.setWordWrap(True)
        bottom.addWidget(self.status, 1)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        bottom.addWidget(close_btn)
        root.addLayout(bottom)

        # при открытии: live-проверка root/secure + статистика
        self._run(self._on_root_info, adb_actions.check_root, self.ip)
        self.refresh_stats()

    # ------------------------------------------------------------ инфраструктура
    def _run(self, callback, fn, *args, **kwargs):
        worker = ActionWorker(lambda: fn(*args, **kwargs), self)
        worker.result.connect(callback)
        self._workers.append(worker)
        worker.start()
        return worker

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
        top.addStretch(1)
        layout.addLayout(top)

        self.apps_tree = QTreeWidget()
        self.apps_tree.setHeaderLabels([i18n.tr("apps_col_pkg"),
                                        i18n.tr("apps_col_ver"),
                                        i18n.tr("apps_col_path")])
        self.apps_tree.setRootIsDecorated(False)
        self.apps_tree.setAlternatingRowColors(True)
        self.apps_tree.header().resizeSection(0, 220)
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
        self.install_btn = QPushButton(i18n.tr("apps_install"))
        self.install_btn.clicked.connect(self._install_apk)
        actions2.addWidget(self.install_btn)
        actions2.addStretch(1)
        layout.addLayout(actions2)
        return page

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
        for app in apps or []:
            item = QTreeWidgetItem([app["package"], "", app.get("path", "")])
            item.setData(0, Qt.UserRole, app["package"])
            self.apps_tree.addTopLevelItem(item)
        self.status.setText(i18n.tr("apps_found", count=len(apps or [])))

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
        self._busy()
        self._run(lambda out, exc: self._on_app_details(package, out, exc),
                  adb_actions.app_details, self.ip, package)

    def _on_app_details(self, package, details, exc):
        if exc:
            self._failed(exc)
            return
        self._idle()
        details = details or {}
        QMessageBox.information(
            self, i18n.tr("apps_details_title", pkg=package),
            i18n.tr("apps_details_fmt",
                    version=details.get("version", "—"),
                    code=details.get("code", "—"),
                    installed=details.get("installed", "—"),
                    updated=details.get("updated", "—"),
                    sdk=details.get("target_sdk", "—"),
                    path=details.get("path", "—")))

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
        self.shell_output.appendPlainText(output.rstrip() or "(пусто)")
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
