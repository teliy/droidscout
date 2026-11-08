"""Диалог обновления и диалог настроек."""

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox,
                               QFormLayout, QGroupBox, QLabel, QLineEdit,
                               QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout)

from .. import __version__, config, i18n, updater


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
    """Настройки: язык, тема, обновления, репозиторий и токен."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("settings"))
        self.resize(560, 430)
        self.test_worker = None

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
        })
        self.result_data = {"ui_changed": changed_ui}
        self.accept()
