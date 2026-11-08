"""Автоустановка Android Platform-Tools (adb) с официального сервера Google.

Порядок поиска adb:
  1. путь из настроек (adb_path);
  2. каталог <конфигурация приложения>/platform-tools (сюда ставим сами);
  3. PATH системы.

Скачивание идёт с dl.google.com (HTTPS, без посредников). Модуль не зависит
от Qt — весь интерфейс (прогресс, диалоги) живёт в ui/.
"""

import os
import platform as _platform
import shutil
import stat
import tempfile
import urllib.error
import urllib.request
import zipfile
from typing import Callable, Optional

from . import config

# Официальные ссылки Google (platform-tools-latest-*.zip, ~13 МБ)
PLATFORM_TOOLS_URLS = {
    "windows": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
    "darwin": "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
    "linux": "https://dl.google.com/android/repository/platform-tools-latest-linux.zip",
}

# Для тестов: можно подменить базовый адрес на локальный HTTP-сервер
URL_OVERRIDE = None

ProgressCb = Callable[[int, int], None]   # (загружено_байт, всего_байт; -1 если неизвестно)
StageCb = Callable[[str], None]           # 'download' | 'extract'


def tools_root() -> str:
    """Каталог, куда устанавливается platform-tools."""
    return os.path.join(config.config_dir(), "platform-tools")


def _is_exe(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if os.name == "nt":
        return True
    return os.access(path, os.X_OK)


def find_adb() -> Optional[str]:
    """Находит adb: настройка adb_path -> наш platform-tools -> PATH."""
    custom = (config.get("adb_path") or "").strip()
    if custom:
        if _is_exe(custom):
            return custom
        # Разрешаем указать каталог platform-tools или даже сам каталог с adb
        guess = os.path.join(custom, "adb.exe" if os.name == "nt" else "adb")
        if _is_exe(guess):
            return guess
    bundled = os.path.join(tools_root(), "adb.exe" if os.name == "nt" else "adb")
    if _is_exe(bundled):
        return bundled
    found = shutil.which("adb")
    return found


def adb_version(adb_path: str, timeout: int = 10) -> str:
    """Возвращает строку версии adb (для показа в настройках), '' при ошибке."""
    import subprocess
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        proc = subprocess.run([adb_path, "version"], capture_output=True, text=True,
                              timeout=timeout, creationflags=flags)
        for line in (proc.stdout or "").splitlines():
            if line.lower().startswith("android debug bridge"):
                return line.strip()
        return (proc.stdout or "").splitlines()[0].strip() if proc.stdout else ""
    except (subprocess.TimeoutExpired, OSError, IndexError):
        return ""


def _url_for(system: Optional[str] = None) -> str:
    if URL_OVERRIDE:
        return URL_OVERRIDE
    system = (system or _platform.system().lower() or "linux").replace("win32", "windows")
    if system == "win32" or system == "windows":
        return PLATFORM_TOOLS_URLS["windows"]
    if system == "darwin":
        return PLATFORM_TOOLS_URLS["darwin"]
    return PLATFORM_TOOLS_URLS["linux"]


def download_and_install(progress: Optional[ProgressCb] = None,
                         stage: Optional[StageCb] = None,
                         url: Optional[str] = None,
                         system: Optional[str] = None) -> str:
    """Скачивает и распаковывает platform-tools. Возвращает путь к adb.

    Вызывать из фонового потока: сеть и распаковка занимают секунды.
    """
    progress = progress or (lambda done, total: None)
    stage = stage or (lambda key: None)
    url = url or _url_for(system)

    stage("download")
    request = urllib.request.Request(url, headers={"User-Agent": "DroidScout/1.0"})
    tmp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    try:
        with urllib.request.urlopen(request, timeout=60) as resp, tmp_zip:
            total = int(resp.headers.get("Content-Length") or -1)
            done = 0
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                tmp_zip.write(chunk)
                done += len(chunk)
                progress(done, total)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"download: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"download: {exc}") from exc

    stage("extract")
    root = tools_root()
    os.makedirs(root, exist_ok=True)
    try:
        with zipfile.ZipFile(tmp_zip.name) as zf:
            members = zf.infolist()
            # Официальный архив лежит в каталоге platform-tools/ — если всё
            # содержимое имеет один и тот же верхний каталог, отбрасываем его
            # (наш root уже называется platform-tools).
            tops = {m.filename.replace("\\", "/").split("/")[0] for m in members
                    if m.filename.strip("/\\")}
            strip_top = next(iter(tops)) if len(tops) == 1 and len(members) > 1 else None
            for member in members:
                # Защита от «/abs/path» и «..» внутри архива
                name = member.filename.lstrip("/\\")
                parts = [p for p in name.replace("\\", "/").split("/")
                         if p not in ("", ".", "..")]
                if strip_top and parts and parts[0] == strip_top:
                    parts = parts[1:]
                if not parts:
                    continue
                target = os.path.join(root, *parts)
                if name.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(member) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst, length=1 << 16)
                mode = (member.external_attr >> 16) & 0o7777 if member.external_attr else 0
                if os.name != "nt":
                    os.chmod(target, mode or 0o644)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"bad zip: {exc}") from exc
    finally:
        try:
            os.unlink(tmp_zip.name)
        except OSError:
            pass

    # Верхний каталог архива обычно называется platform-tools/ — наша структура
    # уже совпадает; если нет (нестандартный архив) — ищем adb рекурсивно.
    adb_name = "adb.exe" if os.name == "nt" else "adb"
    adb_path = os.path.join(root, adb_name)
    if _is_exe(adb_path):
        return adb_path
    for dirpath, _dirnames, filenames in os.walk(root):
        if adb_name in filenames:
            candidate = os.path.join(dirpath, adb_name)
            if _is_exe(candidate):
                return candidate
    raise RuntimeError("adb not found inside package")


def make_executable(path: str) -> None:
    """chmod +x (используется тестами и после ручной распаковки)."""
    if os.name != "nt":
        current = os.stat(path).st_mode
        os.chmod(path, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
