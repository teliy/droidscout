"""Темы оформления DroidScout: тёмная и светлая (QSS) + иконка приложения."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QIcon, QPen, QPainter, QPixmap
from PySide6.QtWidgets import QApplication

ACCENT_DARK = "#2ecc71"
ACCENT_LIGHT = "#2563eb"

DARK_QSS = """
* { font-size: 13px; }
QMainWindow, QDialog { background-color: #14161b; }
QWidget { color: #d8dce4; }
QLabel { background-color: transparent; }
QMenuBar { background-color: #101218; color: #d8dce4; border-bottom: 1px solid #23262e; }
QMenuBar::item:selected { background-color: #23262e; }
QMenu { background-color: #1b1e26; border: 1px solid #2a2e38; padding: 4px; }
QMenu::item { padding: 6px 24px 6px 12px; border-radius: 4px; }
QMenu::item:selected { background-color: #2a2e38; }
QMenu::separator { height: 1px; background-color: #2a2e38; margin: 4px 8px; }
QToolBar { background-color: #101218; border-bottom: 1px solid #23262e; padding: 6px; spacing: 6px; }
QToolButton { background-color: #1e212a; color: #d8dce4; border: 1px solid #2a2e38;
              border-radius: 6px; padding: 6px 14px; }
QToolButton:hover { background-color: #262a35; border-color: #3a3f4d; }
QToolButton:pressed { background-color: #2a2e38; }
QToolButton:disabled { color: #5a5f6c; }
QToolButton#primary { background-color: #2ecc71; color: #0c1410; font-weight: 600; border: none; }
QToolButton#primary:hover { background-color: #3ddc82; }
QToolButton#primary:disabled { background-color: #24543a; color: #7ba98e; }
QToolButton#danger { background-color: #e74c3c; color: #fff; font-weight: 600; border: none; }
QPushButton { background-color: #1e212a; color: #d8dce4; border: 1px solid #2a2e38;
              border-radius: 6px; padding: 6px 16px; }
QPushButton:hover { background-color: #262a35; border-color: #3a3f4d; }
QPushButton:default { background-color: #2ecc71; color: #0c1410; font-weight: 600; border: none; }
QPushButton:disabled { color: #5a5f6c; }
QComboBox { background-color: #1e212a; border: 1px solid #2a2e38; border-radius: 6px;
            padding: 5px 10px; min-width: 160px; }
QComboBox:hover { border-color: #3a3f4d; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox::down-arrow { image: none; border-left: 5px solid transparent;
                        border-right: 5px solid transparent; border-top: 6px solid #8a90a0;
                        margin-right: 8px; }
QComboBox QAbstractItemView { background-color: #1b1e26; border: 1px solid #2a2e38;
                              selection-background-color: #2a2e38; }
QLineEdit, QPlainTextEdit, QTextEdit { background-color: #101218; border: 1px solid #2a2e38;
                                       border-radius: 6px; padding: 6px 8px;
                                       selection-background-color: #2ecc71; color: #d8dce4; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus { border-color: #2ecc71; }
QTabWidget::pane { border: 1px solid #23262e; border-radius: 0 0 6px 6px; background: #14161b; }
QTabBar::tab { background-color: #101218; color: #8a90a0; padding: 8px 22px;
               border: 1px solid #23262e; border-bottom: none;
               border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 3px; }
QTabBar::tab:selected { background-color: #14161b; color: #2ecc71; font-weight: 600; }
QTableView { background-color: #14161b; alternate-background-color: #171a21;
             gridline-color: #22252e; border: 1px solid #23262e; border-radius: 6px;
             selection-background-color: #24435c; selection-color: #ffffff; }
QHeaderView::section { background-color: #101218; color: #8a90a0; border: none;
                       border-right: 1px solid #22252e; border-bottom: 1px solid #2a2e38;
                       padding: 7px 8px; font-weight: 600; }
QTableCornerButton::section { background-color: #101218; border: none; }
QProgressBar { background-color: #101218; border: 1px solid #2a2e38; border-radius: 6px;
               text-align: center; color: #d8dce4; min-height: 16px; max-height: 16px; }
QProgressBar::chunk { background-color: #2ecc71; border-radius: 5px; }
QStatusBar { background-color: #101218; color: #8a90a0; border-top: 1px solid #23262e; }
QScrollBar:vertical { background: #14161b; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #2a2e38; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3a3f4d; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #14161b; height: 11px; margin: 0; }
QScrollBar::handle:horizontal { background: #2a2e38; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #3a3f4d; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QGroupBox { border: 1px solid #2a2e38; border-radius: 8px; margin-top: 12px;
            padding: 12px 8px 8px 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #2ecc71; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #2a2e38;
                       border-radius: 4px; background: #101218; }
QCheckBox::indicator:checked { background: #2ecc71; border-color: #2ecc71; }
QListWidget { background-color: #14161b; border: 1px solid #23262e; border-radius: 6px; }
QListWidget::item { padding: 8px; border-bottom: 1px solid #1d2029; }
QListWidget::item:selected { background-color: #24435c; color: #fff; }
QToolTip { background-color: #1b1e26; color: #d8dce4; border: 1px solid #2a2e38; padding: 4px; }
QDialogButtonBox QPushButton { min-width: 90px; }
"""

LIGHT_QSS = """
* { font-size: 13px; }
QMainWindow, QDialog { background-color: #f4f6fa; }
QWidget { color: #1c2430; }
QLabel { background-color: transparent; }
QMenuBar { background-color: #ffffff; color: #1c2430; border-bottom: 1px solid #e2e6ee; }
QMenuBar::item:selected { background-color: #eef1f7; }
QMenu { background-color: #ffffff; border: 1px solid #d9dee8; padding: 4px; }
QMenu::item { padding: 6px 24px 6px 12px; border-radius: 4px; }
QMenu::item:selected { background-color: #eef1f7; }
QMenu::separator { height: 1px; background-color: #e2e6ee; margin: 4px 8px; }
QToolBar { background-color: #ffffff; border-bottom: 1px solid #e2e6ee; padding: 6px; spacing: 6px; }
QToolButton { background-color: #eef1f7; color: #1c2430; border: 1px solid #d9dee8;
              border-radius: 6px; padding: 6px 14px; }
QToolButton:hover { background-color: #e4e9f2; border-color: #c2cadd; }
QToolButton:pressed { background-color: #d9dee8; }
QToolButton:disabled { color: #9aa3b2; }
QToolButton#primary { background-color: #2563eb; color: #fff; font-weight: 600; border: none; }
QToolButton#primary:hover { background-color: #1d4fd7; }
QToolButton#primary:disabled { background-color: #b8ccf5; color: #f0f4ff; }
QToolButton#danger { background-color: #dc2626; color: #fff; font-weight: 600; border: none; }
QPushButton { background-color: #eef1f7; color: #1c2430; border: 1px solid #d9dee8;
              border-radius: 6px; padding: 6px 16px; }
QPushButton:hover { background-color: #e4e9f2; border-color: #c2cadd; }
QPushButton:default { background-color: #2563eb; color: #fff; font-weight: 600; border: none; }
QPushButton:disabled { color: #9aa3b2; }
QComboBox { background-color: #ffffff; border: 1px solid #d9dee8; border-radius: 6px;
            padding: 5px 10px; min-width: 160px; }
QComboBox:hover { border-color: #c2cadd; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox::down-arrow { image: none; border-left: 5px solid transparent;
                        border-right: 5px solid transparent; border-top: 6px solid #5c6575;
                        margin-right: 8px; }
QComboBox QAbstractItemView { background-color: #ffffff; border: 1px solid #d9dee8;
                              selection-background-color: #eef1f7; selection-color: #1c2430; }
QLineEdit, QPlainTextEdit, QTextEdit { background-color: #ffffff; border: 1px solid #d9dee8;
                                       border-radius: 6px; padding: 6px 8px; color: #1c2430;
                                       selection-background-color: #2563eb; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus { border-color: #2563eb; }
QTabWidget::pane { border: 1px solid #e2e6ee; border-radius: 0 0 6px 6px; background: #f4f6fa; }
QTabBar::tab { background-color: #e9edf4; color: #5c6575; padding: 8px 22px;
               border: 1px solid #e2e6ee; border-bottom: none;
               border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 3px; }
QTabBar::tab:selected { background-color: #f4f6fa; color: #2563eb; font-weight: 600; }
QTableView { background-color: #ffffff; alternate-background-color: #f8fafd;
             gridline-color: #e8ecf3; border: 1px solid #e2e6ee; border-radius: 6px;
             selection-background-color: #dce7fb; selection-color: #10224a; }
QHeaderView::section { background-color: #f0f3f8; color: #5c6575; border: none;
                       border-right: 1px solid #e2e6ee; border-bottom: 1px solid #d9dee8;
                       padding: 7px 8px; font-weight: 600; }
QTableCornerButton::section { background-color: #f0f3f8; border: none; }
QProgressBar { background-color: #e9edf4; border: 1px solid #d9dee8; border-radius: 6px;
               text-align: center; color: #1c2430; min-height: 16px; max-height: 16px; }
QProgressBar::chunk { background-color: #2563eb; border-radius: 5px; }
QStatusBar { background-color: #ffffff; color: #5c6575; border-top: 1px solid #e2e6ee; }
QScrollBar:vertical { background: #f4f6fa; width: 11px; margin: 0; }
QScrollBar::handle:vertical { background: #c9d1de; border-radius: 5px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #aeb9ca; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #f4f6fa; height: 11px; margin: 0; }
QScrollBar::handle:horizontal { background: #c9d1de; border-radius: 5px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #aeb9ca; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QGroupBox { border: 1px solid #d9dee8; border-radius: 8px; margin-top: 12px;
            padding: 12px 8px 8px 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: #2563eb; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #c2cadd;
                       border-radius: 4px; background: #ffffff; }
QCheckBox::indicator:checked { background: #2563eb; border-color: #2563eb; }
QListWidget { background-color: #ffffff; border: 1px solid #e2e6ee; border-radius: 6px; }
QListWidget::item { padding: 8px; border-bottom: 1px solid #eef1f7; }
QListWidget::item:selected { background-color: #dce7fb; color: #10224a; }
QToolTip { background-color: #ffffff; color: #1c2430; border: 1px solid #d9dee8; padding: 4px; }
QDialogButtonBox QPushButton { min-width: 90px; }
"""


def theme_bg(theme: str = None) -> str:
    """Основной цвет фона темы (для заливки QTabWidget из кода)."""
    if theme is None:
        from .. import config
        theme = config.get("theme", "dark")
    return "#14161b" if theme == "dark" else "#f4f6fa"


def apply_theme(app: QApplication, theme: str = None) -> None:
    """Применяет тему из настроек (или указанную)."""
    from .. import config
    if theme is None:
        theme = config.get("theme", "dark")
    app.setStyleSheet(DARK_QSS if theme == "dark" else LIGHT_QSS)


def app_icon() -> QIcon:
    """Иконка приложения: зелёная голова «андроида-разведчика», рисуется кодом."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        dark = QColor("#14161b")
        accent = QColor("#2ecc71")
        painter.setPen(Qt.NoPen)
        painter.setBrush(dark)
        painter.drawRoundedRect(0, 0, size, size, size * 0.22, size * 0.22)
        # голова (полукруг)
        painter.setBrush(accent)
        painter.drawPie(int(size * 0.18), int(size * 0.30), int(size * 0.64),
                        int(size * 0.62), 180 * 16, 180 * 16)
        # антенны
        painter.setPen(QPen(accent, max(2, size // 16)))
        painter.drawLine(int(size * 0.30), int(size * 0.34), int(size * 0.22), int(size * 0.16))
        painter.drawLine(int(size * 0.70), int(size * 0.34), int(size * 0.78), int(size * 0.16))
        # глаза
        painter.setPen(Qt.NoPen)
        painter.setBrush(dark)
        eye = max(2, size // 12)
        painter.drawEllipse(int(size * 0.36), int(size * 0.46), eye, eye)
        painter.drawEllipse(int(size * 0.56), int(size * 0.46), eye, eye)
        painter.end()
        icon.addPixmap(pixmap)
    return icon
