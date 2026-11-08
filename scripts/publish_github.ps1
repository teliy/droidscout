# Создаёт ПРИВАТНЫЙ репозиторий на GitHub и пушит текущий код.
#
# Требуется GitHub CLI: https://cli.github.com  (winget install GitHub.cli)
# После установки выполните один раз: gh auth login
#
# Использование (из корня репозитория):
#   powershell -ExecutionPolicy Bypass -File scripts\publish_github.ps1 -Login "ваш-логин"
#
# Скрипт подставляет логин вместо плейсхолдера OWNER в установщиках и README.
param(
    [Parameter(Mandatory = $true)]
    [string]$Login
)

$ErrorActionPreference = "Stop"

if ($Login -notmatch '^[A-Za-z0-9-]+$') {
    Write-Host "Некорректный логин GitHub: $Login" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "GitHub CLI (gh) не установлен. https://cli.github.com" -ForegroundColor Red
    exit 1
}
gh auth status *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Сначала выполните: gh auth login" -ForegroundColor Red; exit 1 }

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Подставляем логин вместо плейсхолдера (только целое слово OWNER:
# REPO_OWNER и DS_OWNER не затрагиваются).
# .ps1 сохраняем С BOM (требование PowerShell 5.1 для кириллицы), остальное — без.
$utf8Bom    = New-Object System.Text.UTF8Encoding($true)
$utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
foreach ($file in @("install.sh", "install.ps1", "README.md", "droidscout\updater.py")) {
    $path = Join-Path $root $file
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    $text = $text -replace "\bOWNER\b", $Login
    $enc  = if ($file.EndsWith(".ps1")) { $utf8Bom } else { $utf8NoBom }
    [IO.File]::WriteAllText($path, $text, $enc)
}

git init 2>$null
git add -A
git commit -m "DroidScout 1.0.0: сетевой сканер Android-устройств" 2>$null

gh repo create droidscout --private --source . --remote origin --push

# Релиз нужен, чтобы «Проверить обновления» сразу находила текущую версию.
gh release create v1.0.0 --title "DroidScout 1.0.0" --notes "Первый релиз." *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "(релиз v1.0.0 не создан или уже существует — не критично)"
}

Write-Host ""
Write-Host "Готово! Приватный репозиторий: https://github.com/$Login/droidscout" -ForegroundColor Green
Write-Host ""
Write-Host "================= Шаг 2: создайте токен (для установки и обновлений) ================="
Write-Host "  Откройте:  https://github.com/settings/personal-access-tokens/new"
Write-Host "  - Repository access: Only select repositories  ->  droidscout"
Write-Host "  - Permissions -> Repository -> Contents: Read-only"
Write-Host ""
Write-Host "================= Шаг 3: установка (скопируйте блок целиком) ================="
Write-Host ""
Write-Host '  & { $o = Read-Host "Логин GitHub"'
Write-Host '      $s = Read-Host "Токен GitHub" -AsSecureString'
Write-Host '      $env:DS_OWNER = $o'
Write-Host '      $env:DS_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto('
Write-Host '                          [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))'
Write-Host '      irm "https://raw.githubusercontent.com/$o/droidscout/main/install.ps1" | iex }'
Write-Host ""
Write-Host "Токен установщик сохранит в настройки приложения — автообновления заработают сразу."
Write-Host ""
Write-Host "Если сделаете репозиторий ПУБЛИЧНЫМ, токен не понадобится:"
Write-Host "  irm https://raw.githubusercontent.com/$Login/droidscout/main/install.ps1 | iex"
