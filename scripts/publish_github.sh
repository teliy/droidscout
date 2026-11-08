#!/usr/bin/env bash
# Создаёт ПРИВАТНЫЙ репозиторий на GitHub и пушит текущий код.
#
# Требуется GitHub CLI (gh):  https://cli.github.com
#   Debian/Ubuntu: sudo apt install gh && gh auth login
#   macOS:         brew install gh && gh auth login
#
# Использование:
#   ./scripts/publish_github.sh <ваш-github-логин>
#
# Скрипт подставит логин в install.sh, install.ps1 и README вместо OWNER.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Использование: $0 <ваш-github-логин>"
  exit 1
fi

LOGIN="$1"
if ! [[ "$LOGIN" =~ ^[A-Za-z0-9-]+$ ]]; then
  echo "Некорректный логин GitHub: $LOGIN"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) не установлен. https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Сначала выполните: gh auth login"; exit 1; }

cd "$ROOT"

# Подставляем логин вместо плейсхолдера (только целое слово: REPO_OWNER/DS_OWNER не трогаем).
# macOS/BSD sed не знает \b — используем [[:<:]] [[:>:]].
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' "s/[[:<:]]OWNER[[:>:]]/${LOGIN}/g" install.sh install.ps1 README.md droidscout/updater.py
else
  sed -i "s/\bOWNER\b/${LOGIN}/g" install.sh install.ps1 README.md droidscout/updater.py
fi

git init -b main 2>/dev/null || git init
git add -A
git commit -m "DroidScout 1.0.0: сетевой сканер Android-устройств" || true

gh repo create droidscout --private --source=. --remote=origin --push

# Релиз нужен, чтобы «Проверить обновления» сразу находила текущую версию.
gh release create v1.0.0 --title "DroidScout 1.0.0" --notes "Первый релиз." >/dev/null 2>&1 \
  || echo "(релиз v1.0.0 не создан или уже существует — не критично)"

echo
echo "Готово! Приватный репозиторий: https://github.com/${LOGIN}/droidscout"
echo
echo "================= Шаг 2: создайте токен (для установки и обновлений) ================="
echo "  Откройте:  https://github.com/settings/personal-access-tokens/new"
echo "  - Repository access: Only select repositories  ->  droidscout"
echo "  - Permissions -> Repository -> Contents: Read-only"
echo
echo "================= Шаг 3: установка (скопируйте блок целиком) ================="
echo
echo "  Windows (PowerShell):"
echo '    & { $o = Read-Host "Логин GitHub"'
echo '        $s = Read-Host "Токен GitHub" -AsSecureString'
echo '        $env:DS_OWNER = $o'
echo '        $env:DS_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto('
echo '                            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))'
echo '        irm "https://raw.githubusercontent.com/$o/droidscout/main/install.ps1" | iex }'
echo
echo "  Linux / macOS (bash):"
echo '    read -rp "Логин GitHub: " DS_OWNER; read -rsp "Токен GitHub: " DS_TOKEN; echo; \'
echo '    export DS_OWNER DS_TOKEN; \'
echo '    curl -fsSL "https://raw.githubusercontent.com/$DS_OWNER/droidscout/main/install.sh" | bash'
echo
echo "Токен установщик сохранит в настройки приложения — автообновления заработают сразу."
echo
echo "Если сделаете репозиторий ПУБЛИЧНЫМ, токен не понадобится:"
echo "  Windows: irm https://raw.githubusercontent.com/${LOGIN}/droidscout/main/install.ps1 | iex"
echo "  Linux:   curl -fsSL https://raw.githubusercontent.com/${LOGIN}/droidscout/main/install.sh | bash"
