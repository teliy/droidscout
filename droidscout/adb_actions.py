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
        raise ActionError(f"keygen: {exc}", "conn") from exc
    last = None
    for attempt in (1, 2):
        device = AdbDevice(host, port, timeout=timeout, keypair=keypair)
        try:
            device.connect(auth_timeout=max(timeout, 30.0))
            return device
        except AdbUnauthorized as exc:
            device.close()
            raise ActionError(str(exc), "unauthorized") from exc
        except (AdbError, AdbTimeout, OSError) as exc:
            device.close()
            last = exc
            if str(exc).startswith("connect:") or attempt == 2:
                break
            time.sleep(0.4)
    raise ActionError(str(last), "conn") from last


def shell(host: str, command: str, port: int = 5555, timeout: float = 10.0) -> str:
    """Одна shell-команда на устройстве. Возвращает вывод."""
    device = _open(host, port, timeout)
    try:
        return device.shell(command, timeout=timeout)
    except (AdbError, AdbTimeout, OSError) as exc:
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()


# ---------------------------------------------------------------- скриншот
def screenshot(host: str, port: int = 5555, timeout: float = 20.0) -> bytes:
    """Снимок экрана (PNG). exec: без pty; fallback — screencap в файл + base64."""
    device = _open(host, port, timeout)
    try:
        raw = device.exec_out("screencap -p", timeout=timeout)
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
def parse_pm_list(text: str) -> "list[tuple[str, str]]":
    """'pm list packages [-f]' -> [(package, apk_path|'')]."""
    result = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("package:"):
            continue
        body = line[len("package:"):]
        if "=" in body:
            path, name = body.split("=", 1)
        else:
            path, name = "", body
        name = name.strip()
        if name:
            result.append((name, path.strip()))
    return result


def list_apps(host: str, kind: str = "third", port: int = 5555,
              timeout: float = 20.0) -> "list[dict]":
    """Список пакетов. kind: 'third' (-3), 'system' (-s), 'all'."""
    flags = {"third": "-f -3", "system": "-f -s", "all": "-f"}.get(kind, "-f -3")
    text = shell(host, f"pm list packages {flags}", port, timeout)
    apps = [{"package": name, "path": path} for name, path in parse_pm_list(text)]
    apps.sort(key=lambda item: item["package"].lower())
    return apps


def parse_dumpsys_package(text: str) -> dict:
    """Вывод 'dumpsys package <pkg>' -> {version, code, installed, updated,
    target_sdk, path}."""
    out = {}
    match = re.search(r"versionName=(\S+)", text)
    if match:
        out["version"] = match.group(1)
    match = re.search(r"versionCode=(\d+)", text)
    if match:
        out["code"] = match.group(1)
    match = re.search(r"firstInstallTime=(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", text)
    if match:
        out["installed"] = match.group(1)
    match = re.search(r"lastUpdateTime=(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?)", text)
    if match:
        out["updated"] = match.group(1)
    match = re.search(r"targetSdk=(\d+)", text)
    if match:
        out["target_sdk"] = match.group(1)
    match = re.search(r"codePath=(/\S+)", text)
    if match:
        out["path"] = match.group(1)
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
        device.push_bytes(data, APK_PATH, timeout=timeout)
        output = device.shell(f"pm install -r {APK_PATH} && rm -f {APK_PATH}",
                              timeout=timeout)
        return output.strip()
    except (AdbError, AdbTimeout, OSError) as exc:
        raise ActionError(str(exc), "conn") from exc
    finally:
        device.close()


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
