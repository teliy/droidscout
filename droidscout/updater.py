"""Проверка обновлений и самообновление из GitHub Releases.

Механика:
  1. GET /repos/{owner}/{repo}/releases/latest (токен нужен для приватного репо).
  2. Сравнение версии из тега с текущей.
  3. Скачивание zipball исходников, замена файлов приложения (кроме venv,
     .git, настроек и истории), при необходимости `pip install -r requirements.txt`.
  4. Приложение предлагает перезапуск.

Информация о репозитории берётся из droidscout/_repo.json (создаётся
установщиком), затем из настроек, затем значения по умолчанию.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from typing import Callable, Dict, Optional

from . import __version__, APP_NAME, config, i18n

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEFAULT_OWNER = "OWNER"
DEFAULT_REPO = "droidscout"
UPDATE_EXCLUDE = {"venv", ".venv", ".git", "__pycache__", "backup", ".idea", ".vscode"}
KEEP_FILES = {"settings.json", "history.db", "_repo.json"}


def repo_info() -> Dict[str, str]:
    """owner/repo: _repo.json -> настройки -> значения по умолчанию."""
    owner = config.get("repo_owner") or ""
    repo = config.get("repo_name") or DEFAULT_REPO
    if not owner:
        marker = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "droidscout", "_repo.json")
        alt = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "_repo.json")
        for path in (marker, alt):
            try:
                with open(path, encoding="utf-8-sig") as f:  # utf-8-sig: терпит BOM
                    data = json.load(f)
                owner = data.get("owner") or owner
                repo = data.get("repo") or repo
                if owner:
                    break
            except (OSError, ValueError):
                continue
    return {"owner": owner or DEFAULT_OWNER, "repo": repo}


def _api_url(path: str) -> str:
    info = repo_info()
    return f"https://api.github.com/repos/{info['owner']}/{info['repo']}{path}"


def _request(url: str, timeout: int = 15):
    headers = {"User-Agent": f"{APP_NAME}/{__version__}",
               "Accept": "application/vnd.github+json"}
    token = (config.get("github_token") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=timeout)


def parse_version(text: str) -> tuple:
    """'v1.2.3-beta' -> (1, 2, 3)."""
    match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", text or "")
    if not match:
        return (0, 0, 0)
    parts = match.groups()
    return tuple(int(p) if p else 0 for p in parts)


def is_newer(candidate: str, current: str = __version__) -> bool:
    return parse_version(candidate) > parse_version(current)


def _friendly_http_error(exc: urllib.error.HTTPError) -> str:
    """Читаемые сообщения для типовых кодов GitHub API.

    В тексте обязательно остаётся числовой код (401/403/404) —
    UI по нему добавляет подсказку о приватном репозитории.
    """
    mapping = {
        401: "update_err_401",
        403: "update_err_403",
        404: "update_err_404",
    }
    key = mapping.get(exc.code)
    if key:
        return i18n.tr(key)
    return str(exc)


def fetch_latest_release() -> Optional[Dict[str, str]]:
    """Вернёт dict(tag, name, notes, zipball, html_url, published) или None.

    Raises RuntimeError при сетевых ошибках / 404 (нет релизов).
    """
    try:
        with _request(_api_url("/releases/latest")) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(_friendly_http_error(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(str(exc)) from exc
    if "tag_name" not in data:
        raise RuntimeError("no releases found")
    tag = data["tag_name"]
    return {
        "tag": tag,
        "name": data.get("name") or tag,
        "notes": (data.get("body") or "").strip(),
        "zipball": data.get("zipball_url") or "",
        "html_url": data.get("html_url") or "",
        "published": data.get("published_at") or "",
    }


def check_for_update() -> Optional[Dict[str, str]]:
    """Удобная обёртка: возвращает информацию о релизе, если он новее."""
    info = fetch_latest_release()
    config.set_key("last_update_check", int(time.time()))
    if info and is_newer(info["tag"]):
        return info
    return None


class SelfUpdater:
    """Скачивает и устанавливает обновление в каталог приложения."""

    def __init__(self, progress_cb: Optional[Callable[[str], None]] = None):
        self.progress = progress_cb or (lambda message: None)
        self.app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def download(self, release: Dict[str, str]) -> str:
        """Скачивает zipball, возвращает путь к извлечённому каталогу."""
        url = release.get("zipball") or _api_url("/zipball/" + release["tag"])
        self.progress("update_downloading")
        with _request(url, timeout=60) as resp, \
                tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            shutil.copyfileobj(resp, tmp, length=1 << 16)
            zip_path = tmp.name
        self.progress("update_installing")
        extract_dir = tempfile.mkdtemp(prefix="droidscout_update_")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        os.unlink(zip_path)
        # GitHub кладёт содержимое в каталог вида owner-repo-tag
        entries = [e for e in os.listdir(extract_dir)
                   if os.path.isdir(os.path.join(extract_dir, e))]
        if len(entries) == 1:
            return os.path.join(extract_dir, entries[0])
        return extract_dir

    def install(self, source_dir: str) -> bool:
        """Заменяет файлы приложения файлами новой версии (venv не трогаем)."""
        changed = False
        # Если источник — единственный каталог (типичный zipball GitHub),
        # спускаемся внутрь него.
        entries_all = os.listdir(source_dir)
        dirs_all = [e for e in entries_all if os.path.isdir(os.path.join(source_dir, e))]
        if len(entries_all) == 1 and len(dirs_all) == 1 and not entries_all[0].startswith("."):
            source_dir = os.path.join(source_dir, entries_all[0])

        for entry in os.listdir(source_dir):
            if entry in UPDATE_EXCLUDE:
                continue
            src = os.path.join(source_dir, entry)
            dst = os.path.join(self.app_root, entry)
            try:
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True,
                                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
                else:
                    shutil.copy2(src, dst)
                changed = True
            except OSError as exc:
                self.progress(f"copy_error:{entry}:{exc}")
        if not changed:
            return False

        # Чистим старые .pyc, чтобы Python не подхватил кэш
        for package_dir in (os.path.join(self.app_root, "droidscout"),):
            for root, dirs, _files in os.walk(package_dir):
                for dirname in list(dirs):
                    if dirname == "__pycache__":
                        shutil.rmtree(os.path.join(root, dirname), ignore_errors=True)
                        dirs.remove(dirname)

        # Если в новом релизе изменились зависимости — доставим их в venv
        self._pip_install()
        return True

    def _pip_install(self) -> None:
        requirements = os.path.join(self.app_root, "requirements.txt")
        if not os.path.exists(requirements):
            return
        pip = os.path.join(self.app_root, "venv", "Scripts", "pip.exe") if os.name == "nt" \
            else os.path.join(self.app_root, "venv", "bin", "pip")
        if not os.path.exists(pip):
            return
        try:
            subprocess.run([pip, "install", "-r", requirements, "--quiet",
                            "--disable-pip-version-check"],
                           timeout=600, check=False, creationflags=CREATE_NO_WINDOW)
        except (subprocess.TimeoutExpired, OSError):
            pass

    def perform(self, release: Dict[str, str]) -> bool:
        source_dir = self.download(release)
        try:
            return self.install(source_dir)
        finally:
            shutil.rmtree(os.path.dirname(source_dir), ignore_errors=True)

    def restart_app(self) -> None:
        """Перезапускает приложение (после подтверждения пользователем)."""
        python = sys.executable
        script = os.path.join(self.app_root, "droidscout.py")
        if os.path.exists(script):
            os.environ.setdefault("DROIDSCOUT_RESTART", "1")
            subprocess.Popen([python, script], close_fds=True)
        else:
            subprocess.Popen([python, "-m", "droidscout"], close_fds=True)
