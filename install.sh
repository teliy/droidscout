#!/usr/bin/env bash
# ============================================================================
#  DroidScout — установщик для Linux / macOS
#
#  Однострочная установка:
#    curl -fsSL https://raw.githubusercontent.com/OWNER/droidscout/main/install.sh | bash
#
#  Установщик:
#    1. спросит каталог установки (Enter — по умолчанию);
#    2. проверит Python 3.9+ и модуль venv;
#    3. скачает архив репозитория;
#    4. создаст venv и поставит зависимости;
#    5. создаст лаунчер `droidscout` в ~/.local/bin и запись в меню приложений.
# ============================================================================
set -euo pipefail

# >>> ЗАМЕНИТЕ на свой GitHub-аккаунт при публикации репозитория <<<
REPO_OWNER="OWNER"
REPO_NAME="droidscout"
BRANCH="main"

REPO_SLUG="${REPO_OWNER}/${REPO_NAME}"
DEFAULT_DIR="${HOME}/.local/share/${REPO_NAME}"
BIN_DIR="${HOME}/.local/bin"

log()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m ==> \033[0m%s\n' "$*" >&2; }
fail() { printf '\033[1;31mОШИБКА:\033[0m %s\n' "$*" >&2; exit 1; }

# --- читаем ввод с терминала, даже когда скрипт прилетает по пайпу -----------
ask_path() {
  local answer=""
  if [ -t 0 ]; then
    # скрипт запущен напрямую (bash install.sh) — читаем stdin
    printf 'Каталог установки [%s]: ' "$DEFAULT_DIR" >&2
    read -r answer || answer=""
  elif [ -r /dev/tty ]; then
    # скрипт прилетел по пайпу (curl | bash) — читаем с терминала через subshell
    answer=$( { printf 'Каталог установки [%s]: ' "$DEFAULT_DIR" > /dev/tty; \
               bash -c 'read -r a < /dev/tty && printf %s "$a"'; } 2>/dev/null ) || answer=""
  fi
  echo "${answer:-$DEFAULT_DIR}"
}

# --- зависимости -------------------------------------------------------------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

download() {
  if need_cmd curl; then curl -fSL --retry 3 -o "$2" "$1"
  elif need_cmd wget; then wget -qO "$2" "$1"
  else fail "Нужен curl или wget."; fi
}

# --- Python ------------------------------------------------------------------
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if need_cmd "$candidate"; then PYTHON_BIN="$candidate"; break; fi
done
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

# --- скачивание репозитория --------------------------------------------------
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

log "Скачиваю архив ${REPO_SLUG} (${BRANCH})…"
download "https://github.com/${REPO_SLUG}/archive/refs/heads/${BRANCH}.zip" \
         "${TMP_DIR}/repo.zip"

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
[ -d "$BIN_DIR" ] && case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "    Внимание: добавьте $BIN_DIR в PATH, чтобы команда droidscout была доступна."; ;;
esac
