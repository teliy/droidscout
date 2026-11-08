#!/usr/bin/env bash
# ============================================================================
#  DroidScout — установщик для Linux / macOS
#
#  Приватный репозиторий (команда спросит логин и токен; ВАЖНО: заголовок
#  Authorization обязателен — без него raw.githubusercontent вернёт 404):
#    read -rp "Логин GitHub: " DS_OWNER; read -rsp "Токен GitHub: " DS_TOKEN; echo; \
#      export DS_OWNER DS_TOKEN; \
#      curl -fsSL -H "Authorization: token $DS_TOKEN" \
#        "https://raw.githubusercontent.com/$DS_OWNER/droidscout/main/install.sh" | bash
#
#  Публичный репозиторий:
#    curl -fsSL https://raw.githubusercontent.com/ВАШ_ЛОГИН/droidscout/main/install.sh | bash
#
#  Установщик:
#    1. спросит каталог установки (Enter — по умолчанию);
#    2. проверит Python 3.9+ и модуль venv;
#    3. скачает архив репозитория (для приватного — с токеном);
#    4. создаст venv и поставит зависимости;
#    5. создаст лаунчер `droidscout` в ~/.local/bin и запись в меню приложений.
# ============================================================================
set -euo pipefail

# Логин и токен можно передать через окружение: DS_OWNER и DS_TOKEN.
# Плейсхолдер логина при публикации заменяется реальным (scripts/publish_github.*).
PLACEHOLDER='OWN'"ER"
REPO_OWNER="${DS_OWNER:-$PLACEHOLDER}"
REPO_NAME="droidscout"
BRANCH="main"
API_BASE="${DS_API_BASE:-https://api.github.com}"       # тех. хук для тестов
ARCHIVE_BASE="${DS_ARCHIVE_BASE:-https://github.com}"   # тех. хук для тестов
REPO_TOKEN="${DS_TOKEN:-}"

REPO_SLUG="${REPO_OWNER}/${REPO_NAME}"
DEFAULT_DIR="${HOME}/.local/share/${REPO_NAME}"
BIN_DIR="${HOME}/.local/bin"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m ==> \033[0m%s\n' "$*" >&2; }
fail() { printf '\033[1;31mОШИБКА:\033[0m %s\n' "$*" >&2; exit 1; }

# --- чтение ввода с терминала, даже когда скрипт прилетает по пайпу ----------
# tty_read "подсказка" hidden(yes|no) — печатает значение в stdout
tty_read() {
  local val="" flag=""
  [ "${2:-no}" = "yes" ] && flag="-s"
  if [ -r /dev/tty ]; then
    printf '%s' "$1" >&2
    # shellcheck disable=SC2086
    read $flag -r val </dev/tty || val=""
    printf '\n' >&2
  elif [ -t 0 ]; then
    printf '%s' "$1" >&2
    # shellcheck disable=SC2086
    read $flag -r val || val=""
    printf '\n' >&2
  fi
  printf '%s' "$val"
}

ask_path() {
  local answer
  answer="$(tty_read "Каталог установки [$DEFAULT_DIR]: " no)"
  printf '%s' "${answer:-$DEFAULT_DIR}"
}

# --- зависимости -------------------------------------------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

download() {  # $1 = url, $2 = выходной файл (без авторизации)
  if need_cmd curl; then curl -fSL --retry 3 -o "$2" "$1"
  elif need_cmd wget; then wget -qO "$2" "$1"
  else fail "Нужен curl или wget."; fi
}

# --- Python ------------------------------------------------------------------
# Предпочитаем интерпретатор, у которого есть и venv, и ensurepip
# (в Debian/Ubuntu ensurepip живёт в пакете python3-venv).
PYTHON_BIN=""
PYTHON_FALLBACK=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  need_cmd "$candidate" || continue
  if "$candidate" -c 'import venv, ensurepip' >/dev/null 2>&1; then
    PYTHON_BIN="$candidate"
    break
  fi
  [ -z "$PYTHON_FALLBACK" ] && PYTHON_FALLBACK="$candidate"
done
PYTHON_BIN="${PYTHON_BIN:-$PYTHON_FALLBACK}"
[ -n "$PYTHON_BIN" ] || fail "Python 3.9+ не найден. Установите его:
  Debian/Ubuntu:  sudo apt install python3 python3-venv python3-pip
  Fedora:         sudo dnf install python3
  Arch:           sudo pacman -S python"

VERSION_OK=$($PYTHON_BIN -c 'import sys; print(1 if sys.version_info >= (3, 9) else 0)')
[ "$VERSION_OK" = "1" ] || fail "Нужен Python 3.9+, найден: $($PYTHON_BIN -V 2>&1)"

$PYTHON_BIN -c 'import venv' 2>/dev/null || fail "Модуль venv отсутствует.
  Debian/Ubuntu:  sudo apt install python3-venv"
$PYTHON_BIN -c 'import ensurepip' 2>/dev/null || fail "В Python отсутствует ensurepip (venv не сможет получить pip).
  Debian/Ubuntu:  sudo apt install python3-venv python3-pip"

log "Python: $($PYTHON_BIN -V 2>&1)"

# --- каталог установки -------------------------------------------------------
echo
echo "Куда установить DroidScout?"
INSTALL_DIR="$(ask_path | tr -d '\r')"
mkdir -p "$INSTALL_DIR" || fail "Не удалось создать каталог $INSTALL_DIR"
log "Каталог установки: $INSTALL_DIR"

# --- GitHub-аккаунт и токен ----------------------------------------------------
if [ "$REPO_OWNER" = "$PLACEHOLDER" ]; then
  ANSWER="$(tty_read 'Ваш логин на GitHub: ' no)"
  [ -n "$ANSWER" ] && REPO_OWNER="$ANSWER"
  REPO_SLUG="${REPO_OWNER}/${REPO_NAME}"
fi

if [ -z "$REPO_TOKEN" ]; then
  echo
  echo "Токен GitHub нужен для ПРИВАТНОГО репозитория (fine-grained, право Contents: Read)."
  echo "Создать токен: https://github.com/settings/personal-access-tokens/new"
  echo "Если репозиторий публичный — просто нажмите Enter."
  REPO_TOKEN="$(tty_read 'Токен GitHub (ввод скрыт): ' yes)"
fi
log "Репозиторий: $REPO_SLUG"

# --- скачивание репозитория --------------------------------------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log "Скачиваю архив ${REPO_SLUG} (${BRANCH})…"
DOWNLOAD_OK=1
if [ -n "$REPO_TOKEN" ]; then
  ZIP_URL="${API_BASE}/repos/${REPO_SLUG}/zipball/${BRANCH}"
  if need_cmd curl; then
    curl -fSL --retry 3 -H "Authorization: token ${REPO_TOKEN}" -o "${TMP_DIR}/repo.zip" \
         "$ZIP_URL" || DOWNLOAD_OK=0
  elif need_cmd wget; then
    wget -qO "${TMP_DIR}/repo.zip" --header="Authorization: token ${REPO_TOKEN}" \
         "$ZIP_URL" || DOWNLOAD_OK=0
  else
    fail "Нужен curl или wget."
  fi
else
  ZIP_URL="${ARCHIVE_BASE}/${REPO_SLUG}/archive/refs/heads/${BRANCH}.zip"
  download "$ZIP_URL" "${TMP_DIR}/repo.zip" || DOWNLOAD_OK=0
fi

if [ "$DOWNLOAD_OK" != "1" ]; then
  fail "Не удалось скачать ${ZIP_URL}
  Возможные причины:
   • репозиторий ещё не создан на GitHub (см. scripts/publish_github.sh);
   • опечатка в логине;
   • репозиторий приватный, а токен не указан или без права Contents: Read."
fi

if need_cmd unzip; then unzip -q "${TMP_DIR}/repo.zip" -d "${TMP_DIR}/src"
else
  $PYTHON_BIN - "${TMP_DIR}/repo.zip" "${TMP_DIR}/src" <<'PYEOF'
import sys, zipfile, os
os.makedirs(sys.argv[2], exist_ok=True)
with zipfile.ZipFile(sys.argv[1]) as zf:
    zf.extractall(sys.argv[2])
PYEOF
fi

SRC_ROOT="${TMP_DIR}/src/${REPO_NAME}-${BRANCH}"
[ -d "$SRC_ROOT" ] || SRC_ROOT="$(find "${TMP_DIR}/src" -maxdepth 1 -mindepth 1 -type d | head -n1)"
[ -d "$SRC_ROOT" ] || fail "Архив репозитория повреждён."

# --- разворачиваем исходники (сохранив старые настройки/venv) ----------------
log "Копирую файлы приложения…"
rsync_copy() {  # без rsync: cp с сохранением существующих venv и данных
  (shopt -s dotglob; cp -R "${SRC_ROOT}/"* "$INSTALL_DIR/")
}
if [ -d "$INSTALL_DIR/droidscout" ]; then
  warn "Найдена предыдущая установка — обновляю файлы (venv и история сохраняются)."
fi
rsync_copy

# --- venv + зависимости -------------------------------------------------------
log "Создаю виртуальное окружение venv…"
$PYTHON_BIN -m venv "${INSTALL_DIR}/venv" || fail "Не удалось создать venv."

log "Обновляю pip и устанавливаю зависимости (PySide6, zeroconf, psutil, requests)…"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet --disable-pip-version-check
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" \
  --disable-pip-version-check

# --- запоминаем репозиторий для автообновлений --------------------------------
printf '{"owner": "%s", "repo": "%s", "branch": "%s"}\n' \
       "$REPO_OWNER" "$REPO_NAME" "$BRANCH" > "${INSTALL_DIR}/droidscout/_repo.json"

# --- сохраняем токен для автообновлений (приватный репозиторий) ----------------
if [ -n "$REPO_TOKEN" ]; then
  if [ "$(uname -s)" = "Darwin" ]; then
    CFG_DIR="${HOME}/Library/Application Support/DroidScout"
  else
    CFG_DIR="${XDG_CONFIG_HOME:-${HOME}/.config}/droidscout"
  fi
  mkdir -p "$CFG_DIR"
  "$PYTHON_BIN" - "${CFG_DIR}/settings.json" "$REPO_OWNER" "$REPO_NAME" "$REPO_TOKEN" <<'PYEOF'
import json, os, sys
path, owner, name, token = sys.argv[1:5]
try:
    with open(path, encoding="utf-8-sig") as f:
        data = json.load(f)
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
data.update({"repo_owner": owner, "repo_name": name, "github_token": token})
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
os.replace(tmp, path)
os.chmod(path, 0o600)
PYEOF
  chmod 600 "${CFG_DIR}/settings.json" 2>/dev/null || true
  log "Токен сохранён в настройки приложения — автообновления будут работать."
fi

# --- лаунчер -------------------------------------------------------------------
mkdir -p "$BIN_DIR"
cat > "${BIN_DIR}/droidscout" <<EOF
#!/usr/bin/env bash
exec "${INSTALL_DIR}/venv/bin/python" "${INSTALL_DIR}/droidscout.py" "\$@"
EOF
chmod +x "${BIN_DIR}/droidscout"

# ярлык в меню приложений
DESKTOP_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"
if mkdir -p "$DESKTOP_DIR" 2>/dev/null; then
  cat > "${DESKTOP_DIR}/droidscout.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=DroidScout
Comment=Поиск Android-устройств в локальной сети
Exec=${BIN_DIR}/droidscout
Icon=applications-internet
Terminal=false
Categories=Network;Utility;
EOF
fi

# --- готово ---------------------------------------------------------------------
echo
log "Установка завершена!"
echo "    Каталог:      $INSTALL_DIR"
echo "    Запуск:       droidscout   (или: ${BIN_DIR}/droidscout)"
echo "    Обновление:   кнопка «Проверить обновления» в приложении"
if [ -z "$REPO_TOKEN" ]; then
  echo "    Примечание:  репозиторий приватный? Тогда укажите токен в Настройках приложения."
fi
[ -d "$BIN_DIR" ] && case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "    Внимание: добавьте $BIN_DIR в PATH, чтобы команда droidscout была доступна."; ;;
esac
