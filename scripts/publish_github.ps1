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

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Host "GitHub CLI (gh) не установлен. https://cli.github.com" -ForegroundColor Red
    exit 1
}
gh auth status *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Сначала выполните: gh auth login" -ForegroundColor Red; exit 1 }

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Подставляем логин вместо плейсхолдера OWNER.
# .ps1 сохраняем С BOM (требование PowerShell 5.1 для кириллицы), остальное — без.
$utf8Bom    = New-Object System.Text.UTF8Encoding($true)
$utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
foreach ($file in @("install.sh", "install.ps1", "README.md", "droidscout\updater.py")) {
    $path = Join-Path $root $file
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    $text = $text -replace "OWNER", $Login
    $enc  = if ($file.EndsWith(".ps1")) { $utf8Bom } else { $utf8NoBom }
    [IO.File]::WriteAllText($path, $text, $enc)
}

git init 2>$null
git add -A
git commit -m "DroidScout 1.0.0: сетевой сканер Android-устройств" 2>$null

gh repo create droidscout --private --source . --remote origin --push
Write-Host ""
Write-Host "Готово! Приватный репозиторий: https://github.com/$Login/droidscout" -ForegroundColor Green
Write-Host "Однострочная установка теперь:"
Write-Host "  Windows: irm https://raw.githubusercontent.com/$Login/droidscout/main/install.ps1 | iex"
Write-Host "  Linux:   curl -fsSL https://raw.githubusercontent.com/$Login/droidscout/main/install.sh | bash"
Write-Host ""
Write-Host "ВНИМАНИЕ: пока репозиторий приватный, для автообновлений приложения"
Write-Host "нужен GitHub-токен (Настройки -> Токен GitHub) или сделайте репозиторий публичным."
