"""Диалог обновления, установки ADB и диалог настроек."""

import os

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
                               QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QProgressBar, QPushButton, QVBoxLayout)

from .. import __version__, adb_info, adb_manager, config, i18n, updater


class UpdateWorker(QThread):
    """Фоновая проверка обновлений."""

    checked = Signal(object)      # dict | None
    failed = Signal(str)

    def run(self):
        try:
            info = updater.check_for_update()
            self.checked.emit(info)
        except RuntimeError as exc:
            self.failed.emit(str(exc))


class InstallWorker(QThread):
    """Фоновая установка обновления."""

    stage = Signal(str)
    done = Signal(bool)
    failed = Signal(str)

    def __init__(self, release: dict, parent=None):
        super().__init__(parent)
        self.release = release
        self.updater = updater.SelfUpdater(progress_cb=lambda key: self.stage.emit(key))

    def run(self):
        try:
            ok = self.updater.perform(self.release)
            self.done.emit(ok)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class UpdateDialog(QDialog):
    """Показывает найденный релиз и умеет его устанавливать."""

    def __init__(self, release: dict, parent=None):
        super().__init__(parent)
        self.release = release
        self.installer = None
        self.setWindowTitle(i18n.tr("update_available_title"))
        self.resize(520, 420)

        layout = QVBoxLayout(self)
        header = QLabel(i18n.tr("update_available", version=release.get("name")
                                or release.get("tag", "?"), current=__version__))
        header.setWordWrap(True)
        layout.addWidget(header)

        notes_label = QLabel(i18n.tr("update_notes"))
        notes_label.setStyleSheet("font-weight: 600;")
        layout.addWidget(notes_label)
        notes = QPlainTextEdit(release.get("notes") or "—")
        notes.setReadOnly(True)
        layout.addWidget(notes, 1)

        self.status = QLabel("")
        self.status.setVisible(False)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)

        buttons = QDialogButtonBox()
        self.install_btn = buttons.addButton(i18n.tr("update_install"),
                                             QDialogButtonBox.AcceptRole)
        close_btn = buttons.addButton(i18n.tr("close"), QDialogButtonBox.RejectRole)
        close_btn.clicked.connect(self.reject)
        self.install_btn.clicked.connect(self._install)
        layout.addWidget(buttons)

    def _install(self):
        self.install_btn.setEnabled(False)
        self.status.setText(i18n.tr("update_downloading"))
        self.status.setVisible(True)
        self.installer = InstallWorker(self.release, self)
        self.installer.stage.connect(
            lambda key: self.status.setText(i18n.tr(key, sec=0) if key in
                                            ("update_downloading", "update_installing") else key))
        self.installer.done.connect(self._done)
        self.installer.failed.connect(self._failed)
        self.installer.start()

    def _done(self, ok: bool):
        if ok:
            answer = QMessageBox.question(
                self, i18n.tr("update_available_title"),
                i18n.tr("update_done", version=self.release.get("tag", "")),
                QMessageBox.Yes | QMessageBox.No)
            self.accept()
            if answer == QMessageBox.Yes and self.installer:
                self.installer.updater.restart_app()
                QApplication_exit()
        else:
            self.status.setText(i18n.tr("update_fail_install", error="nothing copied"))

    def _failed(self, error: str):
        self.status.setText(i18n.tr("update_fail_install", error=error))
        self.install_btn.setEnabled(True)


class AdbQueryWorker(QThread):
    """Фоновый опрос Android-устройства (встроенный клиент / adb)."""

    result = Signal(dict, str)

    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip

    def run(self):
        props, error = adb_info.query_device(self.ip)
        self.result.emit(props, error)


class AdbInstallWorker(QThread):
    """Фоновое скачивание и распаковка Android Platform-Tools."""

    progress = Signal(int, int)      # байт загружено, всего (-1 если неизвестно)
    stage = Signal(str)              # 'download' | 'extract'
    done = Signal(str)               # путь к adb
    failed = Signal(str)

    def run(self):
        try:
            path = adb_manager.download_and_install(
                progress=lambda done, total: self.progress.emit(done, total),
                stage=lambda key: self.stage.emit(key))
            self.done.emit(path)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class AdbInstallDialog(QDialog):
    """Предлагает скачать Platform-Tools и показывает прогресс установки."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker = None
        self.adb_path = ""
        self.setWindowTitle(i18n.tr("adb_install_title"))
        self.resize(500, 230)

        layout = QVBoxLayout(self)
        offer = QLabel(i18n.tr("adb_install_offer"))
        offer.setWordWrap(True)
        layout.addWidget(offer)

        self.bar = QProgressBar()
        self.bar.setRange(0, 0)          # «неопределённый» до получения размера
        self.bar.setVisible(False)
        layout.addWidget(self.bar)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        layout.addStretch(1)

        buttons = QDialogButtonBox()
        self.download_btn = buttons.addButton(i18n.tr("adb_install_btn"),
                                              QDialogButtonBox.AcceptRole)
        pick_btn = buttons.addButton(i18n.tr("adb_pick"), QDialogButtonBox.ActionRole)
        cancel_btn = buttons.addButton(i18n.tr("cancel"), QDialogButtonBox.RejectRole)
        cancel_btn.clicked.connect(self.reject)
        self.download_btn.clicked.connect(self._start)
        pick_btn.clicked.connect(self._pick)
        layout.addWidget(buttons)

    def _pick(self):
        start = os.path.expanduser("~")
        path, _ = QFileDialog.getOpenFileName(
            self, i18n.tr("adb_pick"), start,
            "adb (*.exe *.adb);;All files (*)" if os.name == "nt" else "adb (adb);;All files (*)")
        if not path:
            return
        config.set_key("adb_path", path)
        self.adb_path = path
        self.accept()

    def _start(self):
        self.download_btn.setEnabled(False)
        self.bar.setVisible(True)
        self.status.setText(i18n.tr("adb_downloading"))
        self.worker = AdbInstallWorker(self)
        self.worker.stage.connect(self._stage)
        self.worker.progress.connect(self._progress)
        self.worker.done.connect(self._done)
        self.worker.failed.connect(self._failed)
        self.worker.start()

    def _stage(self, key: str):
        if key == "download":
            self.status.setText(i18n.tr("adb_downloading"))
        elif key == "extract":
            self.bar.setRange(0, 0)
            self.status.setText(i18n.tr("adb_extracting"))

    def _progress(self, done: int, total: int):
        if total > 0:
            self.bar.setRange(0, 100)
            self.bar.setValue(min(100, int(done * 100 / total)))
            self.status.setText(f"{i18n.tr('adb_downloading')} "
                                f"{done // (1024 * 1024)} / {max(1, total // (1024 * 1024))} "
                                f"{i18n.tr('mb')}")

    def _done(self, adb_path: str):
        self.adb_path = adb_path
        self.status.setText(i18n.tr("adb_install_done", path=adb_path))
        self.accept()

    def _failed(self, error: str):
        self.bar.setVisible(False)
        self.status.setText(i18n.tr("adb_install_fail", error=error[:200]))
        self.download_btn.setEnabled(True)


def QApplication_exit():
    """Закрывает приложение целиком (после перезапуска нового процесса)."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    QTimer.singleShot(200, QApplication.instance().quit)


class GitHubTestWorker(QThread):
    tested = Signal(bool, str)

    def run(self):
        try:
            info = updater.fetch_latest_release()
            self.tested.emit(True, info.get("tag", ""))
        except RuntimeError as exc:
            self.tested.emit(False, exc.args[0] if exc.args else "error")


class SettingsDialog(QDialog):
    """Настройки: язык, тема, обновления, ADB, репозиторий и токен."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("settings"))
        self.resize(560, 520)
        self.test_worker = None
        self.adb_worker = None

        layout = QVBoxLayout(self)

        # Внешний вид -------------------------------------------------------
        look_box = QGroupBox(i18n.tr("settings_theme"))
        look_form = QFormLayout(look_box)
        self.lang_combo = QComboBox()
        self.lang_combo.addItem(i18n.tr("lang_auto"), "auto")
        self.lang_combo.addItem("Русский", "ru")
        self.lang_combo.addItem("English", "en")
        current_lang = config.get("language", "auto")
        self.lang_combo.setCurrentIndex(max(0, self.lang_combo.findData(current_lang)))
        look_form.addRow(i18n.tr("settings_language"), self.lang_combo)

        self.theme_combo = QComboBox()
        self.theme_combo.addItem(i18n.tr("theme_dark"), "dark")
        self.theme_combo.addItem(i18n.tr("theme_light"), "light")
        self.theme_combo.setCurrentIndex(max(0, self.theme_combo.findData(
            config.get("theme", "dark"))))
        look_form.addRow(i18n.tr("settings_theme"), self.theme_combo)
        layout.addWidget(look_box)

        # Поведение ----------------------------------------------------------
        behav_box = QGroupBox(i18n.tr("check_updates"))
        behav_form = QFormLayout(behav_box)
        self.auto_check = QCheckBox(i18n.tr("settings_updates"))
        self.auto_check.setChecked(bool(config.get("check_updates_on_start", True)))
        behav_form.addRow(self.auto_check)
        self.deep_scan = QCheckBox(i18n.tr("settings_deep"))
        self.deep_scan.setChecked(bool(config.get("deep_scan", True)))
        behav_form.addRow(self.deep_scan)
        layout.addWidget(behav_box)

        # ADB ---------------------------------------------------------------
        adb_box = QGroupBox(i18n.tr("settings_adb_group"))
        adb_form = QFormLayout(adb_box)
        self.adb_native = QCheckBox(i18n.tr("settings_adb_native"))
        self.adb_native.setChecked(bool(config.get("adb_native", True)))
        adb_form.addRow(self.adb_native)
        self.adb_path_edit = QLineEdit(config.get("adb_path", ""))
        self.adb_path_edit.setPlaceholderText(i18n.tr("settings_adb_path"))
        adb_form.addRow(i18n.tr("settings_adb_path"), self.adb_path_edit)
        adb_row = QHBoxLayout()
        adb_pick_btn = QPushButton(i18n.tr("settings_adb_pick"))
        adb_pick_btn.clicked.connect(self._pick_adb)
        self.adb_install_btn = QPushButton(i18n.tr("settings_adb_install"))
        self.adb_install_btn.clicked.connect(self._install_adb)
        adb_row.addWidget(adb_pick_btn)
        adb_row.addWidget(self.adb_install_btn)
        adb_row.addStretch(1)
        adb_form.addRow(adb_row)
        self.adb_status = QLabel(self._adb_status_text())
        self.adb_status.setWordWrap(True)
        adb_form.addRow(self.adb_status)
        layout.addWidget(adb_box)

        # Репозиторий --------------------------------------------------------
        repo_box = QGroupBox(i18n.tr("settings_repo"))
        repo_form = QFormLayout(repo_box)
        info = updater.repo_info()
        self.owner_edit = QLineEdit(info.get("owner", ""))
        self.repo_edit = QLineEdit(info.get("repo", "droidscout"))
        repo_form.addRow(i18n.tr("settings_owner"), self.owner_edit)
        repo_form.addRow(i18n.tr("settings_repo_name"), self.repo_edit)
        self.token_edit = QLineEdit(config.get("github_token", ""))
        self.token_edit.setEchoMode(QLineEdit.Password)
        self.token_edit.setPlaceholderText(i18n.tr("settings_token_hint"))
        repo_form.addRow(i18n.tr("settings_token"), self.token_edit)
        self.test_label = QLabel("")
        self.test_label.setWordWrap(True)
        test_btn = QPushButton(i18n.tr("settings_test"))
        test_btn.clicked.connect(self._test_github)
        repo_form.addRow(test_btn, self.test_label)
        layout.addWidget(repo_box)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _pick_adb(self):
        start = os.path.dirname(self.adb_path_edit.text().strip() or os.path.expanduser("~"))
        if not os.path.isdir(start):
            start = os.path.expanduser("~")
        file_filter = "adb.exe (*.exe);;All files (*)" if os.name == "nt" \
            else "adb (adb);;All files (*)"
        path, _ = QFileDialog.getOpenFileName(self, i18n.tr("adb_pick"), start, file_filter)
        if path:
            self.adb_path_edit.setText(path)
            self.adb_status.setText(self._adb_status_text(path))

    def _adb_status_text(self, override_path: str = "") -> str:
        custom = (override_path or self.adb_path_edit.text()).strip()
        if custom:
            if os.path.isfile(custom):
                return i18n.tr("settings_adb_found", path=custom)
            return i18n.tr("settings_adb_missing")
        found = adb_manager.find_adb()
        if found:
            return i18n.tr("settings_adb_found", path=found)
        return i18n.tr("settings_adb_missing")

    def _install_adb(self):
        self.adb_install_btn.setEnabled(False)
        self.adb_status.setText(i18n.tr("adb_downloading"))
        self.adb_worker = AdbInstallWorker(self)
        self.adb_worker.stage.connect(self._adb_stage)
        self.adb_worker.progress.connect(self._adb_progress)
        self.adb_worker.done.connect(self._adb_done)
        self.adb_worker.failed.connect(self._adb_failed)
        self.adb_worker.start()

    def _adb_stage(self, key: str):
        if key == "download":
            self.adb_status.setText(i18n.tr("adb_downloading"))
        elif key == "extract":
            self.adb_status.setText(i18n.tr("adb_extracting"))

    def _adb_progress(self, done: int, total: int):
        if total > 0:
            self.adb_status.setText(
                f"{i18n.tr('adb_downloading')} "
                f"{done // (1024 * 1024)} / {max(1, total // (1024 * 1024))} "
                f"{i18n.tr('mb')}")

    def _adb_done(self, adb_path: str):
        self.adb_status.setText(i18n.tr("adb_install_done", path=adb_path))
        self.adb_install_btn.setEnabled(True)

    def _adb_failed(self, error: str):
        self.adb_status.setText(i18n.tr("adb_install_fail", error=error[:200]))
        self.adb_install_btn.setEnabled(True)

    def _test_github(self):
        self._apply_repo_to_config()
        self.test_label.setText(i18n.tr("update_checking"))
        self.test_worker = GitHubTestWorker(self)
        self.test_worker.tested.connect(self._test_result)
        self.test_worker.start()

    def _test_result(self, ok: bool, text: str):
        repo = f"{self.owner_edit.text().strip()}/{self.repo_edit.text().strip()}"
        if ok:
            self.test_label.setText(i18n.tr("test_ok", repo=repo) + f" ({text})")
        else:
            self.test_label.setText(i18n.tr("test_fail", error=text[:160]))

    def _apply_repo_to_config(self):
        config.save({
            "repo_owner": self.owner_edit.text().strip(),
            "repo_name": self.repo_edit.text().strip() or "droidscout",
            "github_token": self.token_edit.text().strip(),
        })

    def _save(self):
        self._apply_repo_to_config()
        changed_ui = (
            config.get("language") != self.lang_combo.currentData()
            or config.get("theme") != self.theme_combo.currentData()
            or config.get("deep_scan") != self.deep_scan.isChecked()
            or config.get("check_updates_on_start") != self.auto_check.isChecked()
        )
        config.save({
            "language": self.lang_combo.currentData() or "auto",
            "theme": self.theme_combo.currentData() or "dark",
            "check_updates_on_start": self.auto_check.isChecked(),
            "deep_scan": self.deep_scan.isChecked(),
            "adb_native": self.adb_native.isChecked(),
            "adb_path": self.adb_path_edit.text().strip(),
        })
        self.result_data = {"ui_changed": changed_ui}
        self.accept()
