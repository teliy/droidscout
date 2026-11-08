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
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v gh >/dev/null 2>&1 || { echo "GitHub CLI (gh) не установлен. https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Сначала выполните: gh auth login"; exit 1; }

cd "$ROOT"

# Подставляем логин вместо плейсхолдера OWNER
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' "s/OWNER/${LOGIN}/g" install.sh install.ps1 README.md droidscout/updater.py
else
  sed -i "s/OWNER/${LOGIN}/g" install.sh install.ps1 README.md droidscout/updater.py
fi

git init -b main 2>/dev/null || git init
git add -A
git commit -m "DroidScout 1.0.0: сетевой сканер Android-устройств" || true

gh repo create droidscout --private --source=. --remote=origin --push
echo
echo "Готово! Приватный репозиторий: https://github.com/${LOGIN}/droidscout"
echo "Однострочная установка теперь:"
echo "  Windows:   irm https://raw.githubusercontent.com/${LOGIN}/droidscout/main/install.ps1 | iex"
echo "  Linux/mac: curl -fsSL https://raw.githubusercontent.com/${LOGIN}/droidscout/main/install.sh | bash"
echo
echo "ВНИМАНИЕ: пока репозиторий приватный, для автообновлений приложения"
echo "нужен GitHub-токен (Настройки -> Токен GitHub) или сделайте репозиторий публичным."
