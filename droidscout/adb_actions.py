"""Высокоуровневые действия над Android-устройством через встроенный ADB.

Слой над pure_adb: скриншоты, установка/удаление приложений, «пульт»
(input keyevent), статистика (батарея/память/диск/экран), проверка root
и оценка безопасности. Все парсеры — чистые функции, покрыты тестами
(scripts/test_adb_actions.py).

Каждая функция открывает собственное соединение с adbd — это медленнее
на миллисекунды, зато не оставляет «висящих» потоков и безопасно для
последовательных вызовов из разных QThread.

Коды ошибок ActionError.code: 'unauthorized', 'conn', '' (ошибка команды).
"""

import base64
import datetime
import re
import time

from . import journal
from . import pure_adb
from .pure_adb import (AdbError, AdbTimeout, AdbUnauthorized,  # noqa: F401
                       AdbDevice, shlex_quote)

TMP_DIR = "/data/local/tmp"
SHOT_PATH = TMP_DIR + "/droidscout_shot.png"
APK_PATH = TMP_DIR + "/droidscout_install.apk"

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

# Android-ключи для «пульта» (см. android.view.KeyEvent)
KEYCODES = {
    "up": 19, "down": 20, "left": 21, "right": 22, "ok": 23,
    "back": 4, "home": 3, "menu": 82,
    "vol_up": 24, "vol_down": 25, "mute": 164,
    "power": 26, "play_pause": 85, "stop": 86, "rewind": 89, "forward": 90,
    "ch_up": 166, "ch_down": 167, "sleep": 223, "wakeup": 224,
}

# Соответствие SDK -> версия Android (для выявления поддельных прошивок)
SDK_RELEASE = {23: "6", 24: "7", 25: "7", 26: "8", 27: "8", 28: "9",
               29: "10", 30: "11", 31: "12", 32: "12", 33: "13",
               34: "14", 35: "15"}


class ActionError(Exception):
    """Ошибка действия ADB. code: 'unauthorized' | 'conn' | ''."""

    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------- соединение
def _open(host: str, port: int = 5555, timeout: float = 8.0) -> AdbDevice:
    """Подключается к adbd, ошибки оборачивает в ActionError с кодами i18n.

    Одна повторная попытка, если TCP установился, но рукопожатие сорвалось:
    ТВ-приставки часто держат «полуоткрытые» соединения после предыдущей
    сессии и сбрасывают первый контакт. Если хост недоступен («connect: …»)
    — повтор бессмыслен, падаем сразу.
    """
    try:
        keypair = pure_adb.load_or_create_keys()
    except Exception as exc:  # noqa: BLE001
        journal.error(f"{host}:{port}", "keygen", exc)
        raise ActionError(f"keygen: {exc}", "conn") from exc
    last = None
    for attempt in (1, 2):
        device = AdbDevice(host, port, timeout=timeout, keypair=keypair)
        started = time.monotonic()
        try:
            device.connect(auth_timeout=max(timeout, 30.0))
            journal.event(f"{host}:{port}",
                          f"connect ok (попытка {attempt}, "
                          f"{time.monotonic() - started:.2f}s)")
            return device
        except AdbUnauthorized as exc:
            device.close()
            journal.error(f"{host}:{port}", "connect", exc)
            raise ActionError(str(exc), "unauthorized") from exc
        except (AdbError, AdbTimeout, OSError) as exc:
            device.close()
            last = exc
            if str(exc).startswith("connect:") or attempt == 2:
                journal.error(f"{host}:{port}", "connect", exc)
                break
            time.sleep(0.4)
    raise ActionError(str(last), "conn") from last


def shell(host: str, command: str, port: int = 5555, timeout: float = 10.0) -> str:
    """Одна shell-команда на устройстве. Возвращает вывод.

    Каждая команда и её ответ попадают в журнал (journal.command) — это
    основной материал для разбора «в консоли работает, в утилите нет».
    """
    device = _open(host, port, timeout)
    started = time.monotonic()
    try:
        output = device.shell(command, timeout=timeout)
        journal.command(f"{host}:{port}", command, output,
                        time.monotonic() - started)
        return output
    except (AdbError, AdbTimeout, OSError) as exc:
        journal.command(f"{host}:{port}", command, "",
                        time.monotonic() - started, error=repr(exc))
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()


# ---------------------------------------------------------------- скриншот
def screenshot(host: str, port: int = 5555, timeout: float = 20.0) -> bytes:
    """Снимок экрана (PNG). exec: без pty; fallback — screencap в файл + base64."""
    device = _open(host, port, timeout)
    try:
        raw = device.exec_out("screencap -p", timeout=timeout)
        journal.event(f"{host}:{port}", f"screencap exec: {len(raw)} B")
        if raw.startswith(PNG_MAGIC):
            return raw
        # Старые adbd искажают бинарный вывод — снимаем в файл и кодируем
        text = device.shell(f"screencap -p {SHOT_PATH} && base64 {SHOT_PATH}"
                            f" && rm -f {SHOT_PATH}", timeout=timeout)
        cleaned = re.sub(r"\s+", "", text)
        if cleaned:
            try:
                png = base64.b64decode(cleaned)
                if png.startswith(PNG_MAGIC):
                    return png
            except Exception as exc:  # noqa: BLE001
                raise ActionError(f"decode: {exc}", "") from exc
        raise ActionError("screencap: empty output", "")
    except (AdbError, AdbTimeout, OSError) as exc:
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()


# ---------------------------------------------------------------- пульт / reboot
def send_key(host: str, key, port: int = 5555, timeout: float = 8.0) -> None:
    """input keyevent. key — имя из KEYCODES или число."""
    code = KEYCODES.get(key, key)
    shell(host, f"input keyevent {int(code)}", port, timeout)


def send_text(host: str, text: str, port: int = 5555, timeout: float = 8.0) -> None:
    """Ввод текста (input text; пробелы и спецсимволы экранируются)."""
    clean = text.replace("\n", " ").replace("\r", " ")
    shell(host, f"input text {shlex_quote(clean)}", port, timeout)


def reboot(host: str, mode: str = "", port: int = 5555, timeout: float = 6.0) -> None:
    """Перезагрузка: '' (обычная), 'recovery', 'bootloader'.

    Устройство обрывает соединение в момент команды — это норма,
    поэтому ошибки транспорта игнорируются.
    """
    allowed = ("", "recovery", "bootloader")
    if mode not in allowed:
        raise ActionError(f"unknown reboot mode: {mode}", "")
    try:
        shell(host, f"reboot {mode}".strip(), port, timeout)
    except ActionError as exc:
        if exc.code != "conn":
            raise


# ---------------------------------------------------------------- приложения
def parse_pm_list(text: str) -> "list[tuple[str, str, str]]":
    """'pm list packages [-f] [--show-versioncode]' -> [(package, apk, version)].

    Умеет все встречающиеся форматы строки:

      package:/data/app/com.a/base.apk=com.a                    (-f)
      package:com.a                                             (голый список)
      package:com.a versionCode=12 versionName=1.2.3            (--show-versioncode)
      package:/data/app/com.a/base.apk=com.a versionCode=12 versionName=1.2.3

    Версия '' — если в строке её не было.
    """
    result = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):].strip()
        if not body:
            continue
        version = ""
        match = re.search(r"\bversionName=(\S+)", body)
        if match:
            version = match.group(1)
        # Хвост «versionCode=… versionName=…» отрезаем — имя пакета чистое
        cut = re.search(r"\s+(?:versionCode|versionName)=\S+", body)
        if cut:
            body = body[:cut.start()].strip()
        if "=" in body:
            path, name = body.split("=", 1)
        else:
            path, name = "", body
        name = name.strip()
        if name:
            result.append((name, path.strip(), version))
    return result


def parse_dumpsys_all(text: str) -> "dict[str, dict]":
    """Полный вывод 'dumpsys package' -> {package: {version, code, path…}}.

    Один запрос вместо перебора пакетов по одному: секции начинаются
    строкой «Package [имя] (хэш):», внутри лежат versionName=…,
    versionCode=…, codePath=…. Первое вхождение пакета выигрывает
    (повторы в «Hidden system packages» — дубликаты). Пустой словарь —
    разбор не удался (кривая прошивка, «Permission denial» и т.п.).
    """
    source = text or ""
    starts = [(match.start(), match.group(1))
              for match in re.finditer(r"Package \[([^\]\s]+)\]", source)]
    out = {}
    for idx, (pos, name) in enumerate(starts):
        if name in out:
            continue
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(source)
        info = parse_dumpsys_package(source[pos:end])
        if info:
            out[name] = info
    return out


def _origin_from_path(path: str) -> str:
    """Путь APK/кода -> происхождение: 'third' (/data), 'system'
    (/system|/product|/vendor|/odm|/apex), иначе '' (неизвестно)."""
    p = path or ""
    if p.startswith("/data"):
        return "third"
    if p.startswith(("/system", "/product", "/vendor", "/odm", "/apex")):
        return "system"
    return ""


def _enrich_apps(host: str, port: int, timeout: float, apps: "list[dict]",
                 kind_flag: str, failed: "set[str]", ok_command: str = "",
                 want_details: bool = False) -> None:
    """Добирает пути APK и версии, которых не было в базовом списке.

    До трёх шагов, каждый — под журналом; ошибка любого шага (кривой pm,
    запрет dumpsys) не роняет список — соответствующая колонка остаётся
    пустой:

      1. `pm list packages -f <kind> --show-versioncode` — пути и версии;
      2. `pm list packages -f <kind>`                    — пути;
      3. `dumpsys package` одним куском                  — версии.

    want_details=True (выгрузка для ИИ): шаг 3 выполняется всегда — из
    dumpsys, кроме версий, добираются versionCode, minSdk/targetSdk,
    даты установки/обновления и разрешения; кодPath закрывает и путь,
    и происхождение, если pm не дал -f.

    ok_command — базовая команда, уже вернувшая список: шаг 2 не станет
    повторять её (тот же вывод новой информации не даст), failed — набор
    команд, на которых базовая цепочка уже получила пустоту.
    """
    index = {app["package"]: app for app in apps}

    def missing(field: str) -> bool:
        return any(not app.get(field) for app in apps)

    def merge(entries: "list[tuple[str, str, str]]", where: str) -> None:
        hits = 0
        for name, path, version in entries:
            app = index.get(name)
            if not app:
                continue
            if path and not app.get("path"):
                app["path"] = path
                hits += 1
            if version and not app.get("version"):
                app["version"] = version
                hits += 1
        journal.event(f"{host}:{port}",
                      f"обогащение ({where}): {len(entries)} строк, "
                      f"заполнено полей {hits}")

    # 1) пути + версии одним запросом (--show-versioncode есть не везде:
    #    старые pm печатают usage-ошибку — тогда ответ не разберётся)
    if missing("path") or missing("version"):
        command = " ".join(filter(None, ("pm list packages -f", kind_flag,
                                         "--show-versioncode")))
        try:
            text = shell(host, command, port, timeout)
            merge(parse_pm_list(text), command)
        except ActionError as exc:
            journal.event(f"{host}:{port}", f"обогащение не удалось: {exc}")

    # 2) пути без versioncode — то, что уже отказало (failed) или уже
    #    вернуло базовый список (ok_command), второй раз не запрашивается
    if missing("path"):
        command = " ".join(filter(None, ("pm list packages -f", kind_flag)))
        if command == ok_command or command in failed:
            journal.event(f"{host}:{port}",
                          f"обогащение ({command}): пропуск — уже отвечала")
        else:
            try:
                text = shell(host, command, port, timeout)
                merge(parse_pm_list(text), command)
            except ActionError as exc:
                journal.event(f"{host}:{port}", f"обогащение не удалось: {exc}")

    # 3) версии: полный dumpsys package одним запросом — медленнее и
    #    «толще», зато работает даже там, где pm не знает ни -f, ни
    #    --show-versioncode. Заодно закрывает codePath, если пути нет.
    if want_details or missing("version") or missing("path"):
        try:
            text = shell(host, "dumpsys package", port, timeout)
            infos = parse_dumpsys_all(text)
            filled = 0
            for name, info in infos.items():
                app = index.get(name)
                if not app:
                    continue
                if info.get("version") and not app.get("version"):
                    app["version"] = info["version"]
                    filled += 1
                if info.get("path") and not app.get("path"):
                    app["path"] = info["path"]
                    filled += 1
                if want_details:
                    for key in ("code", "min_sdk", "target_sdk",
                                "installed", "updated"):
                        if info.get(key):
                            app[key] = info[key]
                    app["permissions"] = info.get("permissions", [])
                    if info.get("path") and not app.get("origin"):
                        app["origin"] = _origin_from_path(info["path"])
            journal.event(f"{host}:{port}",
                          f"dumpsys package: секций {len(infos)}, "
                          f"заполнено полей {filled}")
        except ActionError as exc:
            journal.event(f"{host}:{port}", f"dumpsys package недоступен: {exc}")


def list_apps(host: str, kind: str = "third", port: int = 5555,
              timeout: float = 20.0, detailed: bool = False) -> "list[dict]":
    """Список пакетов: {package, path, version, origin}. kind: 'third' (-3),
    'system' (-s), 'all'. detailed=True добавляет code/min_sdk/target_sdk/
    installed/updated/permissions (полный dumpsys всегда).

    На части прошивок `pm` отвергает флаги (-f/-3/-s) или молча отдаёт
    пустоту на комбинацию, которая работает в консоли пользователя.
    Поэтому список снимается цепочкой попыток с разными флагами, каждая
    попытка — в журнал (сырой ответ виден целиком):

      third:  `pm list packages -3`  →  `-f -3`  →  `-f` (только /data/*)
      system: `pm list packages -s`  →  `-f -s`  →  `-f` (только /system|product|vendor)
      all:    `pm list packages`     →  `-f`

    Первый удачный ответ часто содержит только имена (голый `-3`/`-s`),
    а колонки «Версия» и «APK» остаются пустыми — их добирает
    _enrich_apps: -f с --show-versioncode, затем голый -f, затем полный
    dumpsys package. Любая ошибка обогащения не роняет список.

    origin: 'third'/'system' — по вкладке, а для 'all' — по пути APK или
    codePath из dumpsys; если путь неизвестен, остаётся ''.
    """
    chains = {
        "third": ("-3", "-f -3", "-f"),
        "system": ("-s", "-f -s", "-f"),
        "all": ("", "-f"),
    }
    variants = chains.get(kind, chains["third"])
    failed: "set[str]" = set()
    apps: "list[dict]" = []
    for attempt, flags in enumerate(variants):
        command = f"pm list packages {flags}".rstrip()
        text = shell(host, command, port, timeout)
        parsed = parse_pm_list(text)                 # [(package, apk, version)]
        if flags == "-f" and kind in ("third", "system"):
            # Прямой путь к пути APK: отделяем сторонние от системных сами
            prefixes = ("/data",) if kind == "third" else ("/system", "/product", "/vendor")
            parsed = [(name, path, version) for name, path, version in parsed
                      if path.startswith(prefixes)]
        if parsed:
            if attempt:
                journal.event(f"{host}:{port}",
                              f"pm list: попытка {attempt + 1} ({flags or 'без флагов'}) "
                              f"— {len(parsed)} пакетов")
            apps = [{"package": name, "path": path, "version": version}
                    for name, path, version in parsed]
            break
        failed.add(command)
        journal.event(f"{host}:{port}",
                      f"pm list ({flags or 'без флагов'}): 0 пакетов, "
                      f"сырой ответ {len(text)} B — в журнале")
    if not apps:
        return []
    _enrich_apps(host, port, timeout, apps, variants[0], failed,
                 ok_command=command, want_details=detailed)
    # Происхождение: во вкладках third/system оно задано самим фильтром,
    # в «Все» — определяется по пути (если путь так и не нашёлся — '').
    for app in apps:
        app["origin"] = kind if kind in ("third", "system") \
            else _origin_from_path(app.get("path", ""))
    apps.sort(key=lambda item: item["package"].lower())
    return apps


def collect_apps(host: str, port: int = 5555, timeout: float = 30.0) -> "list[dict]":
    """Полная выгрузка всех пакетов для передачи в ИИ (оценка нужности/
    безопасности). Каждая запись: package, origin (system/third), version,
    code, min_sdk, target_sdk, enabled (yes/no/'' — неизвестно), path,
    installed, updated, permissions[].

    origin сверяется со списком системных (`pm list packages -s`): это
    надёжнее, чем путь, — прошивка может положить «стороннее» куда
    угодно. Отключённые помечаются по `pm list packages -d`. Если pm не
    знает -s/-d (нет строки 'package:' в ответе) — остаётся значение по
    пути/'' — честно, без догадок.
    """
    apps = list_apps(host, "all", port, timeout, detailed=True)
    if not apps:
        return []
    index = {app["package"]: app for app in apps}

    def flag_set(command: str) -> "tuple[set, bool]":
        # (множество имён, можно ли доверять ответу: в нём есть 'package:')
        try:
            text = shell(host, command, port, timeout)
        except ActionError:
            journal.event(f"{host}:{port}", f"{command}: недоступен")
            return set(), False
        names = {name for name, _p, _v in parse_pm_list(text)}
        return names, bool(names) or "package:" in (text or "")

    system_set, trusted = flag_set("pm list packages -s")
    if trusted:
        for name, app in index.items():
            app["origin"] = "system" if name in system_set else "third"
        journal.event(f"{host}:{port}",
                      f"классификация -s: системных {len(system_set & set(index))} "
                      f"из {len(index)}")
    disabled_set, trusted = flag_set("pm list packages -d")
    if trusted:
        for name, app in index.items():
            app["enabled"] = "no" if name in disabled_set else "yes"
        journal.event(f"{host}:{port}",
                      f"классификация -d: отключённых {len(disabled_set & set(index))}")
    return apps


def parse_dumpsys_package(text: str) -> dict:
    """Вывод 'dumpsys package <pkg>' -> {version, code, min_sdk, target_sdk,
    installed, updated, path, permissions}. permissions — упорядоченный
    список без повторов (requested/install/runtime сливаются — для оценки
    безопасности это неважно, набор тот же)."""
    out = {}
    match = re.search(r"versionName=(\S+)", text)
    if match:
        out["version"] = match.group(1)
    match = re.search(r"versionCode=(\d+)", text)
    if match:
        out["code"] = match.group(1)
    match = re.search(r"\bminSdk=(\d+)", text)
    if match:
        out["min_sdk"] = match.group(1)
    match = re.search(r"targetSdk=(\d+)", text)
    if match:
        out["target_sdk"] = match.group(1)
    match = re.search(r"firstInstallTime=(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", text)
    if match:
        out["installed"] = match.group(1)
    match = re.search(r"lastUpdateTime=(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", text)
    if match:
        out["updated"] = match.group(1)
    match = re.search(r"codePath=(/\S+)", text)
    if match:
        out["path"] = match.group(1)
    permissions = []
    for match in re.finditer(r"[\w.]+\.permission\.[A-Za-z0-9_]+", text or ""):
        perm = match.group(0)
        if perm not in permissions:
            permissions.append(perm)
        if len(permissions) >= 200:      # на всякий случай — куча не нужна
            break
    out["permissions"] = permissions
    return out


def app_details(host: str, package: str, port: int = 5555,
                timeout: float = 15.0) -> dict:
    text = shell(host, f"dumpsys package {shlex_quote(package)}", port, timeout)
    return parse_dumpsys_package(text)


APP_ACTIONS = {
    "launch": "monkey -p {pkg} -c android.intent.category.LAUNCHER 1",
    "stop": "am force-stop {pkg}",
    "uninstall": "pm uninstall --user 0 {pkg}",
    "disable": "pm disable-user --user 0 {pkg}",
    "enable": "pm enable {pkg}",
    "clear": "pm clear {pkg}",
}


def app_action(host: str, package: str, action: str, port: int = 5555,
               timeout: float = 25.0) -> str:
    """Действие над приложением: launch/stop/uninstall/disable/enable/clear."""
    template = APP_ACTIONS.get(action)
    if not template:
        raise ActionError(f"unknown app action: {action}", "")
    return shell(host, template.format(pkg=shlex_quote(package)), port, timeout)


def install_apk(host: str, apk_path: str, port: int = 5555,
                timeout: float = 180.0) -> str:
    """Локальный APK -> устройство (sync push) -> 'pm install -r'."""
    try:
        with open(apk_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        raise ActionError(str(exc), "") from exc
    if not data:
        raise ActionError("empty apk", "")
    device = _open(host, port, max(timeout, 30.0))
    try:
        journal.event(f"{host}:{port}", f"push APK: {len(data)} B -> {APK_PATH}")
        device.push_bytes(data, APK_PATH, timeout=timeout)
        output = device.shell(f"pm install -r {APK_PATH} && rm -f {APK_PATH}",
                              timeout=timeout)
        return output.strip()
    except (AdbError, AdbTimeout, OSError) as exc:
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()


# ---------------------------------------------------------------- файлы
_LS_DATE_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}|\w{3}\s+\d{1,2})\s+(\d{2}:\d{2}|\d{4})\s+(.*)$")


def parse_ls_l(text: str) -> "list[dict]":
    """Вывод 'ls -l [-a]' -> [{name, perms, size, date, is_dir, target}].

    Понимает оба формата даты (toybox «2023-01-01 12:00» и toolbox
    «Jan  1 12:00»/«Jan 1 2019»), наличие и отсутствие счётчика ссылок,
    симлинки «name -> target». Строки «total N» и неразобранное
    пропускаются — по этому признаку list_dir отличает удачный
    разбор от кривого вывода и переходит к следующему варианту ls.
    """
    result = []
    for line in (text or "").splitlines():
        line = line.rstrip()
        if not line or line.startswith(("total ", "Total ")):
            continue
        match = _LS_DATE_RE.search(line)
        if not match or not match.group(3).strip():
            continue
        head = line[:match.start()].strip()
        tokens = head.split()
        if not tokens:
            continue
        perms = tokens[0]
        # полноценная строка ls -l: права длиной 10, тип первым символом
        if len(perms) < 10 or perms[0] not in "-dlbcps":
            continue
        size = ""
        for token in reversed(tokens[1:]):
            if "," in token:            # старшие/младшие номера устройств
                continue
            if token.isdigit():
                size = token
            break
        name = match.group(3).strip()
        target = ""
        if perms[0] == "l" and " -> " in name:
            name, target = name.split(" -> ", 1)
        result.append({"name": name, "perms": perms, "size": size,
                       "date": match.group(1) + " " + match.group(2),
                       "is_dir": perms[0] == "d", "target": target})
    return result


def list_dir(host: str, path: str = "/", port: int = 5555,
             timeout: float = 15.0) -> dict:
    """Содержимое каталога: {'path', 'entries', 'via'}.

    Цепочка попыток `ls -a -l` → `-l` → `-1` → голый `ls`: на кривых
    прошивках ls не знает флагов или печатает usage-ошибку. Точки «.»
    и «..» отфильтровываются; каталоги идут перед файлами. «Permission
    denied» и «No such file or directory» распознаются сразу — это
    честный ответ устройства, а не повод перебирать варианты ls:
    ActionError с кодами 'denied'/'nopath' (UI переводит в подсказку
    про root/опечатку в пути).
    """
    quoted = shlex_quote(path or "/")
    denied = no_path = False
    entries: "list[dict]" = []
    used_via = ""
    for attempt, flags in enumerate(("-a -l", "-l", "-1", "")):
        command = " ".join(filter(None, ("ls", flags, quoted)))
        text = shell(host, command, port, timeout)
        if "Permission denied" in text:
            denied = True
            continue
        if "No such file or directory" in text:
            no_path = True
            continue
        entries = parse_ls_l(text)
        if entries:
            entries = [e for e in entries if e["name"] not in (".", "..")]
            if entries or text.strip().lower().startswith("total"):
                entries.sort(key=lambda e: (not e["is_dir"],
                                            e["name"].lower()))
                return {"path": path, "entries": entries, "via": command}
            continue
        if attempt == 2 and text.strip():
            # голый список имён (ls -1): прав/размеров нет, но навигация
            # по именам всё равно возможна
            entries = [{"name": line.strip(), "perms": "", "size": "",
                        "date": "", "is_dir": False, "target": ""}
                       for line in text.splitlines() if line.strip()]
            used_via = command
            break
        if text.strip().lower().startswith(("total", "usage", "bad")):
            continue
    if entries:
        return {"path": path, "entries": entries, "via": used_via}
    if no_path:
        raise ActionError(f"ls: no such file or directory: {path}", "nopath")
    if denied:
        raise ActionError(f"ls: Permission denied: {path}", "denied")
    return {"path": path, "entries": [], "via": "ls"}


def pull_file(host: str, remote_path: str, port: int = 5555,
              timeout: float = 60.0) -> bytes:
    """Файл с устройства в память ПК (cat через exec:, фолбэк — base64).

    cat не отличает «файл пуст» от «файл нечитаем»: текст ошибки
    «cat: …: Permission denied» пришёл бы как содержимое — такие ответы
    превращаются в ActionError с кодом 'denied'.
    """
    device = _open(host, port, timeout)
    try:
        data = device.pull_file(remote_path, timeout=timeout)
    except (AdbError, AdbTimeout, OSError, ValueError) as exc:
        journal.error(f"{host}:{port}", "pull", exc)
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()
    if data.startswith(b"cat:") or b": Permission denied" in data[:100]:
        raise ActionError(data.decode("utf-8", "replace").strip()[:120],
                          "denied")
    journal.event(f"{host}:{port}", f"pull {remote_path}: {len(data)} B")
    return data


# ---------------------------------------------------------------- статистика
STATS_COMMAND = (
    "echo ==BATTERY; dumpsys battery 2>/dev/null; "
    "echo ==MEM; cat /proc/meminfo 2>/dev/null; "
    "echo ==DISK; df 2>/dev/null; "
    "echo ==WM; wm size 2>/dev/null; wm density 2>/dev/null; "
    "echo ==UP; cat /proc/uptime 2>/dev/null; "
    "echo ==NET; ip -f inet addr show 2>/dev/null || netcfg 2>/dev/null; "
    "echo ==END"
)

ROOT_COMMAND = ("echo ==ID; id; "
                "echo ==SECURE; getprop ro.adb.secure; "
                "echo ==SU; command -v su || which su; "
                "echo ==PATCH; getprop ro.build.version.security_patch; "
                "echo ==SDK; getprop ro.build.version.sdk; "
                "echo ==REL; getprop ro.build.version.release; "
                "echo ==END")


def _sections(text: str) -> "dict[str, str]":
    """Разбивает вывод STATS_COMMAND на секции по маркерам ==NAME."""
    sections: dict = {}
    current = None
    buffer: "list[str]" = []
    for line in (text or "").splitlines():
        marker = re.match(r"^==([A-Z]+)\s*$", line.strip())
        if marker:
            if current:
                sections[current] = "\n".join(buffer)
            current, buffer = marker.group(1), []
        elif current:
            buffer.append(line)
    if current:
        sections[current] = "\n".join(buffer)
    return sections


def parse_meminfo(text: str) -> dict:
    """/proc/meminfo -> {total_mb, available_mb, used_pct}."""
    def field(name):
        match = re.search(rf"^{name}:\s+(\d+)", text, re.M)
        return int(match.group(1)) if match else 0

    total_kb = field("MemTotal")
    available_kb = field("MemAvailable") or field("MemFree")
    used_pct = int(round(100 * (total_kb - available_kb) / total_kb)) if total_kb else 0
    used_pct = max(0, min(100, used_pct))
    return {"total_mb": total_kb // 1024, "available_mb": available_kb // 1024,
            "used_pct": used_pct}


def parse_df(text: str) -> dict:
    """Вывод df -> статистика раздела данных {total_mb, used_pct, mount}.

    Приоритет монтирования: /sdcard, /storage/emulated, /data, иначе /.
    Понимает и toybox-таблицу, и старый toolbox ('N blocks total, M used').
    """
    candidates = ("/sdcard", "/storage/emulated", "/data", "/")
    best = None
    for line in (text or "").splitlines():
        if "blocks total" in line:          # старый toolbox
            match = re.search(r"(\d+)\s+blocks total,\s*(\d+)\s+used", line)
            if match and not best:
                total_kb, used_kb = int(match.group(1)), int(match.group(2))
                if total_kb:
                    best = {"total_mb": total_kb // 1024,
                            "used_pct": min(100, int(100 * used_kb / total_kb)),
                            "mount": line.split(":", 1)[0].strip() or "/data"}
            continue
        parts = line.split()
        # toybox: Filesystem 1K-blocks Used Available Use% Mounted on
        if len(parts) >= 6 and parts[1].isdigit() and parts[-2].rstrip("%").isdigit():
            mount, use_pct, size_kb = parts[-1], parts[-2].rstrip("%"), parts[1]
            if mount in candidates and (best is None or
                                        candidates.index(mount) <
                                        candidates.index(best["mount"])):
                best = {"total_mb": int(size_kb) // 1024,
                        "used_pct": min(100, int(use_pct)), "mount": mount}
    return best or {}


def parse_battery(text: str) -> dict:
    """'dumpsys battery' -> {level, temp_c, charging}."""
    def num(name):
        match = re.search(rf"^\s*{name}:\s*(\d+)", text, re.M)
        return int(match.group(1)) if match else None

    level = num("level")
    temp = num("temperature")
    charging = bool(re.search(r"^\s*(AC|USB|Wireless|Dock) powered:\s*true", text, re.M | re.I))
    result = {}
    if level is not None:
        result["level"] = max(0, min(100, level))
    if temp is not None:
        result["temp_c"] = round(temp / 10.0, 1)
    result["charging"] = charging
    return result


def parse_wm(text: str) -> dict:
    """'wm size'+'wm density' -> {size, density}."""
    out = {}
    match = re.search(r"Physical size:\s*(\d+x\d+)", text)
    if match:
        out["size"] = match.group(1)
    match = re.search(r"Physical density:\s*(\d+)", text)
    if match:
        out["density"] = match.group(1)
    return out


def parse_uptime(text: str) -> float:
    """/proc/uptime -> секунды."""
    match = re.search(r"(\d+(?:\.\d+)?)", text or "")
    return float(match.group(1)) if match else 0.0


def parse_ip_addr(text: str) -> str:
    """'ip addr show' или netcfg -> первый локальный IPv4 (не 127.x)."""
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", text or ""):
        ip = match.group(1)
        if not ip.startswith("127.") and not ip.startswith("0."):
            return ip
    for match in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/\d+", text or ""):
        ip = match.group(1)
        if not ip.startswith("127.") and not ip.startswith("0."):
            return ip
    return ""


def parse_id(text: str) -> dict:
    """Вывод 'id' -> {uid, user, is_root}."""
    match = re.search(r"uid=(\d+)\(([^)]*)\)", text or "")
    if not match:
        return {}
    return {"uid": int(match.group(1)), "user": match.group(2),
            "is_root": match.group(1) == "0"}


def read_stats(host: str, port: int = 5555, timeout: float = 20.0) -> dict:
    """Батарея/память/диск/экран/аптайм/сеть — один shell-вызов."""
    text = shell(host, STATS_COMMAND, port, timeout)
    sections = _sections(text)
    stats: dict = {}
    if "MEM" in sections and sections["MEM"].strip():
        stats["memory"] = parse_meminfo(sections["MEM"])
    if "DISK" in sections and sections["DISK"].strip():
        stats["disk"] = parse_df(sections["DISK"])
    if "BATTERY" in sections and sections["BATTERY"].strip():
        battery = parse_battery(sections["BATTERY"])
        if battery.get("level") is not None:
            stats["battery"] = battery
    if "WM" in sections and sections["WM"].strip():
        stats["display"] = parse_wm(sections["WM"])
    if "UP" in sections and sections["UP"].strip():
        stats["uptime_sec"] = parse_uptime(sections["UP"])
    if "NET" in sections:
        ip = parse_ip_addr(sections["NET"])
        if ip:
            stats["device_ip"] = ip
    return stats


def check_root(host: str, port: int = 5555, timeout: float = 12.0) -> dict:
    """uid, ro.adb.secure, путь к su, актуальные patch/sdk/release."""
    text = shell(host, ROOT_COMMAND, port, timeout)
    sections = _sections(text)
    info: dict = {}
    id_info = parse_id(sections.get("ID", ""))
    info.update(id_info)
    info["adb_secure"] = sections.get("SECURE", "").strip()
    su_path = sections.get("SU", "").strip().splitlines()
    info["su_path"] = su_path[0].strip() if su_path and su_path[0].strip() else ""
    info["su_found"] = bool(info["su_path"]) and "not found" not in info["su_path"]
    info["security_patch"] = sections.get("PATCH", "").strip()
    info["sdk"] = sections.get("SDK", "").strip()
    info["android_version"] = sections.get("REL", "").strip()
    return info


# ---------------------------------------------------------------- settings
SETTING_NAMESPACES = ("global", "secure", "system")
DEV_SETTINGS_KEY = "development_settings_enabled"
DEV_SETTINGS_ACTION = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"


def _check_setting_name(namespace: str, key: str) -> None:
    """Валидация раздела и ключа settings (защита от опечаток и инъекций)."""
    if namespace not in SETTING_NAMESPACES:
        raise ActionError(f"unknown settings namespace: {namespace}", "")
    if not key or any(ch.isspace() for ch in key):
        raise ActionError(f"invalid settings key: {key!r}", "")


def get_setting(host: str, namespace: str, key: str, port: int = 5555,
                timeout: float = 10.0) -> str:
    """'settings get <ns> <key>' — значение параметра ('null', '0', '1', …)."""
    _check_setting_name(namespace, key)
    return shell(host, f"settings get {namespace} {key}", port, timeout).strip()


def put_setting(host: str, namespace: str, key: str, value: str,
                port: int = 5555, timeout: float = 10.0) -> str:
    """'settings put <ns> <key> <value>' — запись параметра.

    Значение экранируется для shell устройства: пробелы и спецсимволы
    не ломают команду (частая ошибка ручного adb — «Too many arguments»).
    """
    _check_setting_name(namespace, key)
    value = "" if value is None else str(value)
    cmd = f"settings put {namespace} {key} {shlex_quote(value)}"
    return shell(host, cmd, port, timeout).strip()


def set_developer_mode(host: str, enable: bool, port: int = 5555,
                       timeout: float = 10.0) -> str:
    """Включает/выключает глобальный флаг development_settings_enabled.

    Это тот самый переключатель, который прошивка прячет от 7 нажатий
    на «Номер сборки». Возвращает фактическое значение после записи
    ('1'/'0') — для подтверждения в UI.
    """
    put_setting(host, "global", DEV_SETTINGS_KEY,
                "1" if enable else "0", port, timeout)
    return get_setting(host, "global", DEV_SETTINGS_KEY, port, timeout)


def open_developer_settings(host: str, port: int = 5555,
                            timeout: float = 8.0) -> str:
    """Открывает меню «Для разработчиков» на экране устройства (am start).

    Через intent-action вместо имени activity — работает и там, где
    производитель подменил приложение настроек. Если системных настроек
    с этим меню нет, устройство вернёт ошибку в выводе — показываем её.
    """
    return shell(host, f"am start -a {shlex_quote(DEV_SETTINGS_ACTION)}",
                 port, timeout).strip()


# ---------------------------------------------------------------- logcat
def logcat_dump(host: str, count: int = 300, priority: str = "",
                port: int = 5555, timeout: float = 20.0) -> str:
    """Последние строки logcat. priority: ''|'V'|'D'|'I'|'W'|'E'."""
    prio = priority.strip().upper()
    cmd = f"logcat -d -t {max(10, min(5000, int(count)))}"
    if prio in ("V", "D", "I", "W", "E"):
        cmd += f" *:{prio}"
    return shell(host, cmd, port, timeout)


def logcat_clear(host: str, port: int = 5555, timeout: float = 10.0) -> None:
    shell(host, "logcat -c", port, timeout)


# ---------------------------------------------------------------- риск-оценка
def _patch_age_days(patch: str, today: datetime.date) -> int:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", (patch or "").strip())
    if not match:
        return -1
    try:
        patch_date = datetime.date(*map(int, match.groups()))
    except ValueError:
        return -1
    return (today - patch_date).days


def assess_risk(extras: "dict | None" = None, uid: "int | None" = None,
                adb_secure: str = "", su_found: bool = False,
                security_patch: str = "", sdk: str = "",
                android_version: str = "",
                today: "datetime.date | None" = None) -> dict:
    """Оценка безопасности устройства (чистая функция).

    extras — словарь device.extras с ключами 'adb_*' (может быть None:
    тогда используются остальные аргументы). Возвращает::

        {score: int, level: 'low'|'medium'|'high'|'critical',
         findings: [i18n-ключи], recommendations: [i18n-ключи]}
    """
    extras = extras or {}
    patch = (security_patch or extras.get("adb_security_patch", "")).strip()
    sdk = (sdk or extras.get("adb_sdk", "")).strip()
    release = (android_version or extras.get("adb_android_version", "")).strip()
    if uid is None and extras.get("adb_uid") not in (None, ""):
        try:
            uid = int(extras["adb_uid"])
        except (TypeError, ValueError):
            uid = None
    adb_secure = (adb_secure if adb_secure != "" else extras.get("adb_secure", "")).strip()

    today = today or datetime.date.today()
    score = 0
    findings: "list[str]" = []

    # ADB открыт по сети — само наличие подключения/данных
    score += 2
    findings.append("risk_open_adb")

    # Возраст патча безопасности
    age = _patch_age_days(patch, today)
    if age >= 3 * 365:
        score += 3
        findings.append("risk_old_patch_3y")
    elif age >= 2 * 365:
        score += 2
        findings.append("risk_old_patch_2y")
    elif age >= 365:
        score += 1
        findings.append("risk_old_patch_1y")

    # Поддельная/нестыкуемая прошивка: версия Android не соответствует SDK
    try:
        expected = SDK_RELEASE.get(int(sdk))
    except (TypeError, ValueError):
        expected = None
    if expected and release and not release.startswith(expected):
        score += 2
        findings.append("risk_fake_version")

    # adbd от root
    if uid == 0:
        score += 3
        findings.append("risk_adbd_root")
    if su_found:
        score += 1
        findings.append("risk_su_binary")

    # Авторизация не требуется (ro.adb.secure=0)
    if adb_secure == "0":
        score += 3
        findings.append("risk_no_auth")

    if score >= 9:
        level = "critical"
    elif score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"

    recommendations = []
    if uid == 0 or su_found:
        recommendations.append("rec_root_distrust")
    if adb_secure == "0":
        recommendations.append("rec_disable_adb")
    if age >= 365:
        recommendations.append("rec_update_fw")
    if "risk_fake_version" in findings:
        recommendations.append("rec_trust_check")
    if recommendations and score >= 4:
        recommendations.append("rec_segment_net")
    return {"score": min(score, 12), "level": level,
            "findings": findings, "recommendations": recommendations}
