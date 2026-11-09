"""Автоматический опрос Python/MicroPython REPL по TCP.

Когда глубокий скан находит порт с приглашением '>>> ' (открытая REPL-консоль),
DroidScout сам подключается к ней и задаёт серию БЕЗОПАСНЫХ читающих вопросов:
  * прошивка и реализация Python (sys.implementation, os.uname());
  * содержимое файловой системы (os.listdir('/') и '/flash');
  * исходник main.py — что устройство вообще делает при загрузке;
  * серийник и частота железа (machine.unique_id(), machine.freq());
  * сетевые настройки модуля (network.WLAN(0).ifconfig());
  * свободная память (gc.mem_free()).

Ничего не пишется, не удаляется, не перезапускается: только print и чтение
файлов. Каждая рискованная (для разбора) команда завёрнута в однострочный
exec("try: ... except: print(error)") — исключение на устройстве превращается
в строку 'DS_... error ...', а не в многострочный traceback, поэтому сессия
остаётся чистой и все вопросы выполняются до конца.

Модуль не зависит от Qt и покрыт тестами scripts/test_repl_probe.py.
"""

import ast
import re
import socket
import time
from typing import Callable, Dict, List, Optional, Tuple

# Метки ответов: выводим 'DS_<КЛЮЧ>' в начале строки, чтобы потом разобрать
# транскрипт даже с эхом команд (эхо начинается с '>>> ' или 'import/exec').


def _guarded(key: str, *lines: str) -> str:
    """Однострочный exec("try:…except:…"): ошибка -> print('DS_<KEY> error', e).

    Исключение на устройстве печатается строкой с меткой вопроса и не рвёт
    сессию REPL. Внутри разрешены только одинарные кавычки.
    """
    body = "\n".join(["try:"]
                     + ["    " + ln for ln in lines]
                     + ["except Exception as e:",
                        f"    print('DS_{key.upper()}', 'error', e)"])
    if '"' in body or "\\" in body:
        raise ValueError("guarded body must avoid double quotes and backslashes")
    return 'exec("' + body.replace("\n", "\\n") + '")'


# (ключ, команда без завершающего перевода строки). Порядок — от «кто ты»
# к «что у тебя внутри»: если устройство отваливается посередине, главное
# уже собрано.
REPL_QUESTIONS: List[Tuple[str, str]] = [
    # реализация и версия Python
    ("impl",
     "import sys; print('DS_IMPL', sys.implementation.name, "
     "getattr(sys.implementation, 'version', ''))"),
    # чип и прошивка модуля
    ("uname", _guarded("UNAME",
        "import os",
        "print('DS_UNAME', os.uname())",
    )),
    # содержимое файловой системы: скрипты производителя, конфиги
    ("root", _guarded("ROOT",
        "import os",
        "print('DS_ROOT', os.listdir('/'))",
    )),
    ("flash", _guarded("FLASH",
        "import os",
        "print('DS_FLASH', os.listdir('/flash'))",
    )),
    # что модуль делает при загрузке: читаем main.py с типичных путей
    ("main", _guarded("MAIN",
        "import os",
        "for p in ('/main.py', 'main.py', '/flash/main.py'):",
        "    try:",
        "        print('DS_MAIN', p, open(p).read()[:600])",
        "        break",
        "    except Exception as e:",
        "        print('DS_MAIN miss', p, e)",
    )),
    # серийник железа и класс чипа
    ("hw", _guarded("HW",
        "import machine",
        "print('DS_HW', machine.unique_id(), machine.freq())",
    )),
    # сетевые настройки модуля (только геттеры: ifconfig/isconnected)
    ("net", _guarded("NET",
        "import network",
        "w = network.WLAN(0)",
        "print('DS_NET', w.isconnected(), w.ifconfig())",
    )),
    # свободная память
    ("mem", _guarded("MEM",
        "import gc",
        "print('DS_MEM', gc.mem_free())",
    )),
]

_MARKER_RE = re.compile(r"^DS_([A-Z]+)[:,]?\s?(.*)$")
_UNAME_PAIR_RE = re.compile(r"(\w+)='([^']*)'")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _ends_with_prompt(buf: bytes) -> bool:
    """Заканчивается ли накопитель приглашением REPL ('>>> '/'... ')."""
    if not buf:
        return False
    tail = buf[-8:]
    if tail.endswith(b">>> ") or tail.endswith(b"... "):
        return True
    return buf.rstrip().endswith((b">>>", b"..."))


def _read_until_prompt(sock: socket.socket, wait: float, stop: Callable[[], bool],
                       limit: int = 8192) -> bytes:
    """Читает сокет, пока не придёт приглашение REPL или не выйдет окно."""
    chunks: List[bytes] = []
    size = 0
    deadline = time.monotonic() + max(0.2, wait)
    sock.settimeout(0.3)
    while size < limit and time.monotonic() < deadline:
        if stop():
            break
        try:
            part = sock.recv(512)
        except (socket.timeout, TimeoutError):
            continue
        except OSError:
            break
        if not part:
            break
        chunks.append(part)
        size += len(part)
        if _ends_with_prompt(b"".join(chunks)[-16:]):
            break
    return b"".join(chunks)


def interview(ip: str, port: int, *, cmd_wait: float = 2.5,
              overall: float = 30.0,
              should_stop: Optional[Callable[[], bool]] = None) -> Dict[str, object]:
    """Подключается к REPL и задаёт все вопросы. Ничего не меняет на устройстве.

    Возвращает: port, ok (есть хоть один ответ), transcript, answers
    (ключ -> текст), error, seconds. Приглашение REPL выдаётся один раз после
    загрузки, поэтому если консоль молчит — сначала «пинок» Enter.
    """
    started = time.monotonic()
    stop = should_stop or (lambda: False)
    result: Dict[str, object] = {"port": port, "ok": False, "transcript": "",
                                 "answers": {}, "error": "", "seconds": 0.0}
    try:
        sock = socket.create_connection((ip, port), timeout=min(3.0, overall))
    except OSError as exc:
        result["error"] = f"connect: {exc}"
        result["seconds"] = time.monotonic() - started
        return result
    parts: List[bytes] = []
    try:
        sock.settimeout(0.3)
        head = _read_until_prompt(sock, 2.0, stop)
        if not _ends_with_prompt(head):
            # приглашение уже могло быть «съедено» прошлым опросом — пинаем Enter
            try:
                sock.sendall(b"\r\n")
            except OSError:
                pass
            head += _read_until_prompt(sock, 1.8, stop)
        if not _ends_with_prompt(head):
            result["error"] = "REPL prompt (>>>) not seen"
            return result
        parts.append(head)
        for _key, cmd in REPL_QUESTIONS:
            if stop() or time.monotonic() - started > overall:
                break
            try:
                sock.sendall(cmd.encode("ascii", "replace") + b"\r\n")
            except OSError as exc:
                result["error"] = f"send: {exc}"
                break
            parts.append(_read_until_prompt(sock, cmd_wait, stop))
    finally:
        try:
            sock.close()
        except OSError:
            pass

    text = b"".join(parts).decode("utf-8", "replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    result["transcript"] = text[:16384]
    result["answers"] = parse_transcript(text)
    result["ok"] = bool(result["answers"])
    result["seconds"] = time.monotonic() - started
    return result


def parse_transcript(transcript: str) -> Dict[str, str]:
    """Чистая функция: транскрипт -> {ключ: ответ}.

    Ответ — текст после метки 'DS_КЛЮЧ' в начале строки до следующей метки
    или приглашения ('>>> ', '... ' — вместе с эхом следующей команды).
    """
    answers: Dict[str, str] = {}
    key: str | None = None
    lines: List[str] = []

    def flush():
        if key:
            answers[key] = "\n".join(lines).strip()

    for line in transcript.splitlines():
        if line.startswith((">>> ", "... ")) or line.strip() in (">>>", "..."):
            flush()
            key, lines = None, []
            continue
        m = _MARKER_RE.match(line)
        if m:
            flush()
            key = m.group(1).lower()
            lines = [m.group(2)]
        elif key:
            lines.append(line)
    flush()
    return answers


def _parse_uname(answer: str) -> Dict[str, str]:
    return dict(_UNAME_PAIR_RE.findall(answer))


def _parse_root(answer: str) -> Tuple[int, str]:
    """(сколько записей, короткое перечисление) из repr списка файлов."""
    try:
        value = ast.literal_eval(answer.strip())
    except (ValueError, SyntaxError):
        return 0, ""
    if isinstance(value, (list, tuple)):
        names = [str(v) for v in value]
        return len(names), ", ".join(names[:6])
    return 0, ""


def _parse_hw(answer: str) -> Tuple[str, str]:
    """(hex серийника, частота в МГц) из ответа machine."""
    uid, freq = "", ""
    m = re.search(r"b'([^']*)'", answer)
    if m:
        try:
            raw = ast.literal_eval("b'" + m.group(1) + "'")
            uid = raw.hex(":") if isinstance(raw, bytes) else ""
        except (ValueError, SyntaxError):
            uid = m.group(1)
    m = re.search(r"(\d{6,})", answer)
    if m:
        freq = f"{int(m.group(1)) // 1_000_000} MHz"
    return uid, freq


def bullets(answers: Dict[str, str]) -> List[str]:
    """Короткие факты из ответов (на английском — это данные устройства)."""
    out: List[str] = []
    try:
        if answers.get("impl"):
            out.append(f"Firmware: {answers['impl']}")
    except (KeyError, ValueError):
        pass
    try:
        pairs = _parse_uname(answers.get("uname", ""))
        if pairs:
            bits = [pairs.get(k, "") for k in ("sysname", "machine", "release")]
            bits = [b for b in bits if b]
            if bits:
                out.append("Board: " + " · ".join(bits))
    except (KeyError, ValueError):
        pass
    try:
        n, names = _parse_root(answers.get("root", ""))
        if n:
            out.append(f"Files /: {n}" + (f" ({names})" if names else ""))
    except (KeyError, ValueError):
        pass
    try:
        n, _names = _parse_root(answers.get("flash", ""))
        if n:
            out.append(f"Files /flash: {n}")
    except (KeyError, ValueError):
        pass
    try:
        main = answers.get("main", "")
        if main and not main.startswith("miss"):
            path, _, body = main.partition(" ")
            first = body.strip().splitlines()[0][:64] if body.strip() else ""
            out.append(f"main.py ({path}): {len(body)} B"
                       + (f" — {first}" if first else ""))
        elif main:
            out.append("main.py: not found")
    except (KeyError, ValueError):
        pass
    try:
        uid, freq = _parse_hw(answers.get("hw", ""))
        if uid or freq:
            out.append("Hardware: " + " · ".join(b for b in (uid, freq) if b))
    except (KeyError, ValueError):
        pass
    try:
        net = answers.get("net", "")
        if net:
            ips = _IP_RE.findall(net)
            connected = "connected" if net.startswith("True") else "not connected"
            if ips:
                out.append(f"Network: {ips[0]} · mask {ips[1] if len(ips) > 1 else '?'}"
                           f" · gw {ips[2] if len(ips) > 2 else '?'} · {connected}")
            else:
                out.append(f"Network: {net[:80]} ({connected})")
    except (KeyError, ValueError):
        pass
    try:
        if answers.get("mem", "").strip().isdigit():
            out.append(f"Free RAM: {answers['mem'].strip()} B")
    except (KeyError, ValueError):
        pass
    return out


def facts_block(answers: Dict[str, str]) -> str:
    """Блок фактов для журнала: '- Firmware: …' построчно. '' — пусто."""
    return "\n".join("- " + b for b in bullets(answers))


def summary_line(answers: Dict[str, str]) -> str:
    """Однострочная сводка для карточки устройства/еvidence. '' — не выяснили."""
    for text in bullets(answers):
        if text.startswith(("Firmware:", "Board:", "Network:")):
            return text[:160]
    return ""
