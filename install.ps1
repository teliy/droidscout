# ============================================================================
#  DroidScout - установщик для Windows (PowerShell 5.1+)
#
#  Однострочная установка:
#    irm https://raw.githubusercontent.com/OWNER/droidscout/main/install.ps1 | iex
#
#  Установщик:
#    1. спросит каталог установки (Enter - по умолчанию);
#    2. проверит Python 3.9+ (при отсутствии предложит установить через winget);
#    3. скачает архив репозитория;
#    4. создаст venv и поставит зависимости;
#    5. создаст лаунчер DroidScout.cmd и ярлык на рабочем столе.
# ============================================================================

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# >>> ЗАМЕНИТЕ на свой GitHub-аккаунт при публикации репозитория <<<
$RepoOwner = "OWNER"
$RepoName  = "droidscout"
$Branch    = "main"

$RepoSlug   = "$RepoOwner/$RepoName"
$DefaultDir = Join-Path $env:LOCALAPPDATA $RepoName

function Write-Log([string]$Message)  { Write-Host "==> $Message" -ForegroundColor Green }
function Write-Warn2([string]$Message){ Write-Host " ==> $Message" -ForegroundColor Yellow }
function Fail([string]$Message)       { Write-Host "ОШИБКА: $Message" -ForegroundColor Red; exit 1 }

# --- Python -----------------------------------------------------------------
function Get-PythonExe {
    foreach ($name in @("py", "python3", "python")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

$pythonExe = Get-PythonExe
if ($pythonExe) {
    $ver = & $pythonExe -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
    $ok  = & $pythonExe -c "import sys; print(1 if sys.version_info >= (3, 9) else 0)" 2>$null
    if ("$ok" -ne "1") {
        Write-Warn2 "Найден Python $ver, но требуется 3.9+."
        $pythonExe = $null
    }
}

if (-not $pythonExe) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Python 3.9+ не найден. Устанавливаю через winget (Python 3.12)…"
        winget install --id Python.Python.3.12 --source winget --accept-source-agreements --accept-package-agreements
        # обновляем PATH текущей сессии
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                    [Environment]::GetEnvironmentVariable("Path", "User")
        $pythonExe = Get-PythonExe
        if (-not $pythonExe) { Fail "Python не найден после установки winget. Перезапустите консоль и повторите." }
    } else {
        Fail "Python 3.9+ не найден и winget недоступен. Установите Python с https://python.org и повторите."
    }
}
Write-Log ("Python: " + (& $pythonExe -V 2>&1))

# --- каталог установки ---------------------------------------------------------
Write-Host ""
Write-Host "Куда установить DroidScout?"
Write-Host ("Enter - по умолчанию: " + $DefaultDir)
$answer = Read-Host "Каталог установки"
if ([string]::IsNullOrWhiteSpace($answer)) { $InstallDir = $DefaultDir } else { $InstallDir = $answer.Trim('"') }

try {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
} catch {
    Fail "Не удалось создать каталог $InstallDir : $($_.Exception.Message)"
}
Write-Log "Каталог установки: $InstallDir"

# --- скачивание репозитория -----------------------------------------------------
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("droidscout_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$zipPath = Join-Path $tmpDir "repo.zip"

Write-Log "Скачиваю архив $RepoSlug ($Branch)…"
try {
    Invoke-WebRequest -Uri "https://github.com/$RepoSlug/archive/refs/heads/$Branch.zip" -OutFile $zipPath -UseBasicParsing
} catch {
    Fail "Не удалось скачать репозиторий: $($_.Exception.Message)"
}

Write-Log "Распаковываю…"
try {
    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
} catch {
    Fail "Не удалось распаковать архив: $($_.Exception.Message)"
}

$srcRoot = Join-Path $tmpDir "$RepoName-$Branch"
if (-not (Test-Path $srcRoot)) {
    $srcRoot = Get-ChildItem $tmpDir -Directory | Select-Object -First 1 -ExpandProperty FullName
}
if (-not (Test-Path (Join-Path $srcRoot "droidscout"))) {
    Fail "Архив репозитория повреждён."
}

# --- разворачиваем исходники (venv и данные не трогаем) --------------------------
Write-Log "Копирую файлы приложения…"
if (Test-Path (Join-Path $InstallDir "droidscout")) {
    Write-Warn2 "Найдена предыдущая установка - обновляю файлы (venv и история сохраняются)."
}
Get-ChildItem $srcRoot -Force | ForEach-Object {
    Copy-Item $_.FullName -Destination $InstallDir -Recurse -Force
}

# --- venv + зависимости -----------------------------------------------------------
Write-Log "Создаю виртуальное окружение venv…"
& $pythonExe -m venv (Join-Path $InstallDir "venv")
if ($LASTEXITCODE -ne 0) { Fail "Не удалось создать venv." }

$venvPython = Join-Path $InstallDir "venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { Fail "venv создан некорректно (нет python.exe)." }

Write-Log "Обновляю pip и устанавливаю зависимости (PySide6, zeroconf, psutil, requests)…"
& $venvPython -m pip install --upgrade pip --quiet --disable-pip-version-check
& $venvPython -m pip install -r (Join-Path $InstallDir "requirements.txt") --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { Fail "Не удалось установить зависимости." }

# --- запоминаем репозиторий для автообновлений ------------------------------------
$repoJson = "{`"owner`": `"$RepoOwner`", `"repo`": `"$RepoName`", `"branch`": `"$Branch`"}"
# UTF-8 без BOM: Python json не понимает BOM
[IO.File]::WriteAllText((Join-Path $InstallDir "droidscout\_repo.json"), $repoJson,
                        (New-Object System.Text.UTF8Encoding($false)))

# --- лаунчер и ярлык ----------------------------------------------------------------
$cmdPath = Join-Path $InstallDir "DroidScout.cmd"
@'
@echo off
start "" "%~dp0venv\Scripts\pythonw.exe" "%~dp0droidscout.py" %*
'@ | Set-Content -Path $cmdPath -Encoding ASCII

try {
    $desktop = [Environment]::GetFolderPath("Desktop")
    $shell   = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $desktop "DroidScout.lnk"))
    $shortcut.TargetPath = $cmdPath
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "DroidScout - поиск Android-устройств в сети"
    $shortcut.Save()
    Write-Log "Ярлык создан на рабочем столе."
} catch {
    Write-Warn2 "Не удалось создать ярлык: $($_.Exception.Message)"
}

Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

# --- готово --------------------------------------------------------------------------
Write-Host ""
Write-Log "Установка завершена!"
Write-Host "    Каталог:    $InstallDir"
Write-Host "    Запуск:     ярлык DroidScout на рабочем столе, или $cmdPath"
Write-Host "    Обновление: кнопка «Проверить обновления» в приложении"
