"""Диалог «Журнал действий»: просмотр, копирование, открытие файла.

Показывает хвост journal.log (последние строки сверху вниз). Отсюда
журнал удобно скопировать целиком и приложить к сообщению о проблеме —
по нему видно, какая команда ушла на устройство и что оно ответило.
"""

import os
import subprocess
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QDialog, QHBoxLayout, QLabel, QMessageBox,
                               QPlainTextEdit, QPushButton, QVBoxLayout)

from .. import i18n, journal


def _open_in_system(path: str) -> None:
    """Открывает файл средством ОС (Проводник/текстовый редактор)."""
    if sys.platform == "win32":
        os.startfile(path)  # noqa: S606 — только Windows API
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])  # noqa: S603,S607
    else:
        subprocess.Popen(["xdg-open", path])  # noqa: S603,S607


class JournalDialog(QDialog):
    """Хвост журнала + кнопки «Скопировать», «Открыть файл», «Очистить»."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(i18n.tr("journal_title"))
        self.resize(720, 520)
        layout = QVBoxLayout(self)

        path_label = QLabel(journal.path())
        path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path_label.setWordWrap(True)
        layout.addWidget(path_label)

        hint = QLabel(i18n.tr("journal_hint"))
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(i18n.tr("journal_empty"))
        layout.addWidget(self.output, 1)

        row = QHBoxLayout()
        refresh_btn = QPushButton(i18n.tr("journal_refresh"))
        refresh_btn.clicked.connect(self.reload)
        row.addWidget(refresh_btn)
        copy_btn = QPushButton(i18n.tr("journal_copy"))
        copy_btn.clicked.connect(self.copy_all)
        row.addWidget(copy_btn)
        open_btn = QPushButton(i18n.tr("journal_open"))
        open_btn.clicked.connect(self.open_file)
        row.addWidget(open_btn)
        clear_btn = QPushButton(i18n.tr("journal_clear"))
        clear_btn.clicked.connect(self.clear_journal)
        row.addWidget(clear_btn)
        row.addStretch(1)
        close_btn = QPushButton(i18n.tr("close"))
        close_btn.clicked.connect(self.reject)
        row.addWidget(close_btn)
        layout.addLayout(row)
        self.reload()

    def reload(self):
        text = journal.read_tail(800)
        self.output.setPlainText(text.rstrip() or i18n.tr("journal_empty"))

    def copy_all(self):
        text = journal.read_tail(6000).rstrip()
        if not text:
            return
        QGuiApplication.clipboard().setText(text)
        self.setWindowTitle(i18n.tr("journal_title") + " — "
                            + i18n.tr("journal_copied"))

    def open_file(self):
        try:
            _open_in_system(journal.path())
        except OSError as exc:
            QMessageBox.warning(self, i18n.tr("journal_title"),
                                i18n.tr("journal_open_failed", error=str(exc)))

    def clear_journal(self):
        answer = QMessageBox.question(
            self, i18n.tr("journal_title"), i18n.tr("journal_clear_question"),
            QMessageBox.Yes | QMessageBox.No)
        if answer != QMessageBox.Yes:
            return
        journal.clear()
        self.reload()
