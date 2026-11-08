"""Точка входа DroidScout: разбор аргументов, запуск GUI."""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="DroidScout",
                                     description="Сканер Android-устройств в локальной сети")
    parser.add_argument("--version", action="version", version=f"DroidScout {__version__()}")
    parser.add_argument("--selfcheck", action="store_true",
                        help="проверить запуск GUI и выйти (для тестов)")
    parser.add_argument("--lang", choices=("ru", "en"), default=None,
                        help="язык интерфейса (перекрывает настройки)")
    args = parser.parse_args()

    from PySide6.QtWidgets import QApplication

    from . import __version__ as version, APP_NAME
    from . import i18n
    from .ui.theme import apply_theme
    from .ui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_NAME)

    if args.lang:
        i18n.set_language(args.lang)

    apply_theme(app)
    window = MainWindow()
    window.show()

    if args.selfcheck:
        # Полный цикл создания интерфейса без погружения в event loop
        from PySide6.QtCore import QTimer
        QTimer.singleShot(300, app.quit)
        code = app.exec()
        window.close()
        return code

    window.after_start()
    return app.exec()


def __version__():
    from . import __version__ as v
    return v


if __name__ == "__main__":
    sys.exit(main())
