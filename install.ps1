# ============================================================================
#  DroidScout - установщик для Windows (PowerShell 5.1+)
#
#  Приватный репозиторий (команда спросит логин и токен; ВАЖНО: заголовок
#  Authorization обязателен - без него raw.githubusercontent вернёт 404):
#    & { $o = Read-Host "Логин GitHub"
#        $s = Read-Host "Токен GitHub" -AsSecureString
#        $t = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
#        $env:DS_OWNER = $o
#        $env:DS_TOKEN = $t
#        $f = Join-Path $env:TEMP "droidscout-install.ps1"
#        Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "token $t" } -Uri "https://raw.githubusercontent.com/$o/droidscout/main/install.ps1" -OutFile $f
#        & $f
#        Remove-Item Env:DS_TOKEN, Env:DS_OWNER -ErrorAction SilentlyContinue
#        Remove-Item $f -ErrorAction SilentlyContinue }
#
#  Публичный репозиторий:
#    irm https://raw.githubusercontent.com/ВАШ_ЛОГИН/droidscout/main/install.ps1 | iex
#
#  Установщик:
#    1. спросит каталог установки (Enter - по умолчанию);
#    2. проверит Python 3.9+ (при отсутствии предложит установить через winget);
#    3. скачает архив репозитория (для приватного - с токеном);
#    4. создаст venv и поставит зависимости;
#    5. создаст лаунчер DroidScout.cmd и ярлык на рабочем столе.
#
#  Логин и токен можно передать заранее через переменные окружения DS_OWNER и DS_TOKEN.
# ============================================================================

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# >>> Плейсхолдер логина заменяется скриптом scripts\publish_github.ps1 <<<
$Placeholder = "OWN" + "ER"   # не заменяется publish-скриптом
$RepoOwner = if ($env:DS_OWNER) { $env:DS_OWNER } else { $Placeholder }
$RepoToken = if ($env:DS_TOKEN) { $env:DS_TOKEN } else { "" }
$RepoName  = "droidscout"
$Branch    = "main"
# тех. хуки для тестов:
$ApiBase     = if ($env:DS_API_BASE)     { $env:DS_API_BASE }     else { "https://api.github.com" }
$ArchiveBase = if ($env:DS_ARCHIVE_BASE) { $env:DS_ARCHIVE_BASE } else { "https://github.com" }

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

# --- GitHub-аккаунт и токен --------------------------------------------------------
if ($RepoOwner -eq $Placeholder) {
    Write-Host ""
    $ans = Read-Host "Ваш логин на GitHub"
    if (-not [string]::IsNullOrWhiteSpace($ans)) { $RepoOwner = $ans.Trim() }
    $RepoSlug = "$RepoOwner/$RepoName"
}
if (-not $RepoToken) {
    Write-Host ""
    Write-Host "Токен GitHub нужен для ПРИВАТНОГО репозитория (fine-grained, право Contents: Read)."
    Write-Host "Создать токен: https://github.com/settings/personal-access-tokens/new"
    Write-Host "Если репозиторий публичный - просто нажмите Enter."
    $secure = Read-Host "Токен GitHub (ввод скрыт)" -AsSecureString
    $RepoToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
}
Write-Log "Репозиторий: $RepoSlug"

# --- скачивание репозитория -----------------------------------------------------
$tmpDir = Join-Path ([IO.Path]::GetTempPath()) ("droidscout_" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$zipPath = Join-Path $tmpDir "repo.zip"

$headers = @{ "User-Agent" = "DroidScout-Installer/1.0" }
if ($RepoToken) {
    $zipUrl = "$ApiBase/repos/$RepoSlug/zipball/$Branch"
    $headers["Authorization"] = "token $RepoToken"
} else {
    $zipUrl = "$ArchiveBase/$RepoSlug/archive/refs/heads/$Branch.zip"
}

Write-Log "Скачиваю архив $RepoSlug ($Branch)…"
try {
    Invoke-WebRequest -Uri $zipUrl -Headers $headers -OutFile $zipPath -UseBasicParsing
} catch {
    $code = $null
    try { $code = [int]$_.Exception.Response.StatusCode } catch {}
    if ($code -eq 404) {
        Fail "Репозиторий не найден (404). Проверьте логин '$RepoOwner' и имя репозитория; создайте репозиторий (scripts\publish_github.ps1); для приватного репозитория нужен корректный токен."
    } elseif ($code -eq 401) {
        Fail "Токен отклонён GitHub (401). Проверьте значение токена (нужно право Contents: Read)."
    } else {
        Fail "Не удалось скачать репозиторий: $($_.Exception.Message)"
    }
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

# --- сохраняем токен для автообновлений (приватный репозиторий) ---------------------
if ($RepoToken) {
    $settingsDir  = Join-Path $env:APPDATA "DroidScout"
    $settingsPath = Join-Path $settingsDir "settings.json"
    $values = @{}
    if (Test-Path $settingsPath) {
        try {
            $loaded = Get-Content $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $loaded.PSObject.Properties | ForEach-Object { $values[$_.Name] = $_.Value }
        } catch {}
    }
    $values["repo_owner"]   = $RepoOwner
    $values["repo_name"]    = $RepoName
    $values["github_token"] = $RepoToken
    if (-not (Test-Path $settingsDir)) {
        New-Item -ItemType Directory -Force -Path $settingsDir | Out-Null
    }
    $json = $values | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($settingsPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Log "Токен сохранён в настройки приложения - автообновления будут работать."
}

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
if (-not $RepoToken) {
    Write-Host "    Примечание: репозиторий приватный? Тогда укажите токен в Настройках приложения."
}
