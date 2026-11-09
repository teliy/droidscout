"""Журнал действий пользователя и ответов устройства (файл journal.log).

Зачем: при разборе «в консоли работает, в утилите нет» нужен сырой обмен
— какая команда ушла на устройство, что именно вернулось и какие были
ошибки. Журнал пишет всё, что проходит через adb_actions (shell-команды,
скриншоты, установка APK, connect) и отметки UI-действий тулкита.

Формат — человекочитаемый, рассчитан на копирование в баг-репорт::

    ── 2026-11-09 14:32:11 ─ 192.168.1.168:5555 ─ shell ─ 1.8s ─ 4210 B
    $ pm list packages -f -3
    package:/data/app/com.tv/base.apk=com.tv
    …
    ── 2026-11-09 14:32:15 ─ 192.168.1.168:5555 ─ shell ─ ОШИБКА
    $ settings get global dev
    ! AdbTimeout('shell timeout')

Ограничения: один ответ обрезается до ~3000 Б (полную простыню не теряем —
видно размер), файл ротируется при 1,5 МБ (journal.log.1/.2). Все ошибки
записи глушатся: журнал не должен ронять приложение.
"""

import datetime
import os
import threading

from . import config

MAX_BYTES = 1_500_000          # порог ротации основного файла
KEEP = 3                       # journal.log + journal.log.1 + journal.log.2
CLIP = 3000                    # максимум байт ответа в одной записи
UI_CLIP = 160                  # максимум символов в отметке UI-действия

_lock = threading.Lock()
_path_override = ""


def path() -> str:
    """Полный путь к текущему файлу журнала."""
    if _path_override:
        return _path_override
    return os.path.join(config.config_dir(), "journal.log")


def set_path(value: str) -> None:
    """Подмена пути (для тестов)."""
    global _path_override
    _path_override = value or ""


def _rotate_locked() -> None:
    """Сдвигает journal.log -> .1 -> .2, если основной файл перерос лимит."""
    p = path()
    try:
        if os.path.getsize(p) < MAX_BYTES:
            return
        old2 = f"{p}.2"
        if os.path.exists(old2):
            os.remove(old2)
        old1 = f"{p}.1"
        if os.path.exists(old1):
            os.replace(old1, old2)
        os.replace(p, old1)
    except OSError:
        pass


def write(kind: str, text: str) -> None:
    """Одна строка журнала: '[дата] [kind] текст'. Ошибки записи глушатся."""
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] [{kind}] {text}\n"
    with _lock:
        try:
            _rotate_locked()
            target = path()
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass


def event(host: str, text: str) -> None:
    """Короткая однострочная отметка (connect, push, попытка pm…)."""
    write("info", f"{host} ─ {text}")


def action(name: str, args=None) -> None:
    """Отметка UI-действия пользователя (имя функции + краткие аргументы)."""
    tail = ""
    if args:
        try:
            tail = ", ".join(repr(a) for a in args)[:UI_CLIP]
        except Exception:  # noqa: BLE001 — repr экзотических объектов не важен
            tail = ""
    write("ui", f"{name}({tail})" if tail else f"{name}()")


def _clip(text: str) -> str:
    """Обрезает длинный ответ с пометкой, сколько байт не показано."""
    body = (text or "").rstrip()
    if len(body) <= CLIP:
        return body
    head = body[:CLIP].rstrip()
    return (head + "\n… [показано " + str(CLIP) + " из "
            + str(len(body)) + " символов]")


def command(host: str, command: str, output: str = "", duration: float = 0.0,
            error: str = "", size: int = None) -> None:
    """Блок «shell-команда → ответ устройства».

    duration — время выполнения на устройстве; error — repr исключения
    (тогда блок помечен ОШИБКА); size — фактический размер сырого ответа
    (для бинарных потоков, когда сам вывод в журнал не пишется).
    """
    parts = [host, "shell"]
    if duration:
        parts.append(f"{duration:.2f}s")
    if error:
        parts.append("ОШИБКА")
    elif size is not None:
        parts.append(f"{size} B")
    head = " ─ ".join(parts)
    lines = [f"── {head}", "$ " + command]
    if error:
        lines.append("! " + error[:1000])
    body = _clip(output)
    if body:
        lines.append(body)
    elif not error and size is None:
        lines.append("(пустой ответ)")
    write("cmd", "\n".join(lines))


def error(host: str, where: str, exc: BaseException) -> None:
    """Отметка об ошибке уровня соединения/действия (с типом исключения)."""
    write("err", f"── {host} ─ {where} ─ ОШИБКА\n! {exc!r}"[:2000])


def read_tail(max_lines: int = 600) -> str:
    """Последние max_lines строк журнала (старые сверху). Пусто, если нет."""
    p = path()
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-max_lines:])
    except OSError:
        return ""


def clear() -> None:
    """Стирает журнал (основной файл и ротации)."""
    with _lock:
        p = path()
        for suffix in ("", ".1", ".2"):
            try:
                os.remove(p + suffix)
            except OSError:
                pass
