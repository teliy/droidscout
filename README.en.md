# DroidScout

**A local network scanner that finds Android devices** — phones, tablets, TV boxes and media players. A Python GUI app (PySide6/Qt) with dark and light themes, a bilingual interface (RU/EN), scan history and self-update from GitHub.

*Русская версия: [README.md](README.md)*

---

## Installation

### One-liner — public repository, no token

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/teliy/droidscout/main/install.ps1 | iex
```

**Linux / macOS (bash):**

```bash
curl -fsSL https://raw.githubusercontent.com/teliy/droidscout/main/install.sh | bash
```

The installer asks for an installation folder, checks for Python 3.9+ (offers to install it if missing), downloads the repository itself, **creates a venv**, installs all dependencies and makes shortcuts:

- Windows: a desktop shortcut + `DroidScout.cmd`;
- Linux/macOS: a `droidscout` command in `~/.local/bin` + an applications-menu entry.

> Your own fork? Replace `teliy` with your GitHub login (or run `scripts/publish_github.*` — it substitutes the login for you).

### If the repository is private (with a token)

GitHub serves **private** repository files only with a token — a plain `raw.githubusercontent.com` link returns **404 Not Found**. In that case:

**Step 1.** Create a fine-grained token: <https://github.com/settings/personal-access-tokens/new>

- *Repository access* → *Only select repositories* → `droidscout`;
- *Permissions → Repository → Contents* → **Read-only** (Metadata is added automatically);
- the expiry is up to you. The token is stored only on your computer.

**Step 2.** Copy the whole block and paste it into a console — it will ask for the login and token:

**Windows (PowerShell):**

```powershell
& { $o = Read-Host "GitHub login"
    $s = Read-Host "GitHub token" -AsSecureString
    $t = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))
    $env:DS_OWNER = $o
    $env:DS_TOKEN = $t
    $f = Join-Path $env:TEMP "droidscout-install.ps1"
    Invoke-WebRequest -UseBasicParsing -Headers @{ Authorization = "token $t" } -Uri "https://raw.githubusercontent.com/$o/droidscout/main/install.ps1" -OutFile $f
    & $f
    Remove-Item Env:DS_TOKEN, Env:DS_OWNER -ErrorAction SilentlyContinue
    Remove-Item $f -ErrorAction SilentlyContinue }
```

**Linux / macOS (bash):**

```bash
read -rp "GitHub login: " DS_OWNER; read -rsp "GitHub token (hidden): " DS_TOKEN; echo; \
export DS_OWNER DS_TOKEN; \
curl -fsSL -H "Authorization: token $DS_TOKEN" "https://raw.githubusercontent.com/$DS_OWNER/droidscout/main/install.sh" | bash; \
unset DS_OWNER DS_TOKEN
```

The installer asks for an installation folder, downloads the repository with the token, creates a venv,
installs the dependencies and **saves the token into the app settings** — self-updates will work
right away. The token can be changed or removed later: app → Settings → Repository.

## What it can do

- **Finds every live host** in the subnet (ICMP sweep, up to 65,000 addresses; with ICMP blocked — an automatic TCP sweep of all addresses).
- **An honest table with no junk**: a host that answered no ping and showed no ports/MAC/name never enters the table; ping-only responders are shown muted gray and are not marked as “new” — the green highlight belongs only to real newcomers with data.
- **TTL from the ping reply** in the device card with an OS class guess (64 — Linux/IoT, 128 — Windows, 255 — network gear).
- **The “All ports” button** on the card: a 1–65535 scan with progress, rate and ETA; service recognition (HTTP headers, TLS certificates, SSH/FTP banners, RTSP, Redis, telnet, Python REPL…), raw replies shown as text + hex with the device context — the probe log always carries IP, MAC, name and vendor; silent ports get a control re-probe (slow REPL consoles answer late); UDP probes; report saving.
- **Digs things up on its own**: the ADB port (5555) is recognized by an unauthorized CNXN handshake — the model, name and codename of the Android device land in the table and the card; a found Python/MicroPython console automatically goes through a full REPL probe — firmware and chip (`os.uname()`), filesystem contents (`os.listdir('/')` and `os.listdir('/flash')` — vendor scripts and configs), the `main.py` source (what the module does at boot), serial and frequency (`machine.unique_id()/freq()`), network settings (`network.WLAN(0).ifconfig()`) and free memory — read-only print requests only, each wrapped in `exec("try:…except:…")` so the session never breaks; the transcript and the “What we learned” block go into the raw reply, the report and the card’s traits. Impostor consoles (pseudo-REPLs like “Bad command …” on Shenzhen iComm modules) are recognized with the first question: instead of eight useless source dumps it sends read-only probes (help/?/version/…) and a dictionary of ~60 typical commands (sysinfo, get, ifconfig, ls, at+gmr, …); live commands with their replies (command list, firmware version, usage hints) land in the “Console: …” fact, and if the whole dictionary is rejected — “Console dict: N probed, all rejected”.
- **Wake-on-LAN** — powering the device on over the network from the card.
- **Android device detection** with a 0–100 % confidence score from a combination of traits:
  - open ADB over the network (port 5555) and ADB TLS;
  - mDNS services: Google Cast, Android TV Remote, AirPlay;
  - SSDP/UPnP descriptions (vendor, model, MediaRenderer);
  - HTTP banners mentioning Android/embedded Linux;
  - MAC-based vendor from the IEEE database (40,000+ prefixes: Samsung, Xiaomi, Huawei, Google, TCL, Amlogic and more);
  - host names like `android-*`, Fire TV models (`AFT*`).
- **A full device card**: IP, MAC, vendor, hostname, type (phone/tablet, Android TV/box, media player…), model, open ports, services, traits.
- **Phone over Wi-Fi, no cable** (Android 11+): the “Wi-Fi phone” button — pairing via “Wireless debugging” with the code from the phone screen and a connection on the adb port. The protocol is reproduced from the ADB sources (SPAKE2 on curve25519 + TLS 1.3 with a client certificate + AES-GCM); the adb public key stays on the phone — after that it is the regular ADB protocol inside TLS: info, apps, remote control, screenshots, files. The port comes from the registry and survives an app restart; after a phone reboot just repeat “Connect” with the fresh port.
- **ADB details** (optional): model, brand, Android version, SDK, serial number — works without an installed adb thanks to the built-in client.
- **ADB toolkit** (the “ADB: toolkit” button on the device card) — everything is controlled through the built-in client, no external adb:
  - **Info** — battery, RAM, disk, screen, uptime, device IP; reboot (normal / Recovery / Bootloader);
  - **Hardware** — a full CPU/SoC survey with decoding: the exact chip model (sun50iw9p1 → Allwinner H616/H313/H618/H700, gxl → Amlogic S905X, rk3328 → Rockchip RK3328 — via device-tree, ro.board.platform, ro.hardware and ro.soc.model), cores by ARM codes (0xd03 → Cortex-A53) with frequencies and governor, GPU with its architecture (Mali-G31 → Bifrost), RAM and the eMMC chip with its capacity, partitions, display with refresh rate, battery, temperature sensors, network interfaces, kernel, board model and hardware features; the result is a one-line “Decoding” and a copy-to-clipboard report;
  - **Apps** — list (third-party / system / all), launch, force-stop, uninstall, disable, clear data, version info, APK install from the computer (the file goes over ADB sync). The list is taken by a chain of attempts with different `pm list packages` flags (-3 → -f -3 → -f with a /data filter): on firmwares where `pm` rejects flags or stays silent the list is still obtained, and every raw reply is visible in the log;
  - **Remote** — D-pad, OK, Home, Back, Menu, volume, mute, play/pause, power — controlling a TV box with the mouse; text sending;
  - **Screenshot** — a one-click device screen capture (PNG), saved to a file;
  - **Console** — arbitrary shell commands with history (up/down arrows);
  - **Settings** — one-click developer mode: the `development_settings_enabled` flag (what firmwares like titan-p1 use to hide the “Developer options” menu when 7 taps on “Build number” do nothing): show the current value, enable/disable with a control read, open the menu on the device screen (`am start`); plus arbitrary `settings get/put` in the global/secure/system namespaces — the value is quoted, so “Too many arguments” never happens;
  - **Logcat** — the last N lines with a level filter (V/D/I/W/E), buffer clearing, saving;
  - **Journal** — a file log of actions and replies (journal.log in the settings folder): every shell command with its execution time and the device reply (long replies are trimmed with a size note), connection errors with the exception type, marks of pressed buttons; view, one-click copy and opening the file right from the dialog — attach the journal to a bug report and it shows exactly where things broke;
  - **Security score** — a colored risk verdict: security patch age, a “fake” firmware (Android version does not match the SDK), adbd running as root, su present, ADB authentication disabled (ro.adb.secure=0) — with recommendations.
- **The “Monitor” tab** — live readings of the selected device with 2/5/10 s auto-refresh: CPU (cores and frequencies), RAM, battery, temperatures; after 3 errors the link is auto-paused.
- **The “Actions” tab** — device toggles: Wi-Fi, mobile data, Bluetooth, airplane mode, sleep/wake the screen, stay-on, brightness 5–255 with a state read-back.
- **Built-in ADB client** (pure Python): DroidScout connects to the device’s adbd over the network (port 5555) by itself — no Platform-Tools needed. The RSA keys are compatible with the official adb: `~/.android/adbkey` is used, so already-authorized devices will not ask for confirmation again. The survey runs as a single `getprop` request (no external processes and no console windows on Windows). Binary services (`exec:`, `sync:`) — screenshots and file transfers without corruption.
- **Automatic Platform-Tools setup**: if an external adb is still needed (USB devices, TLS debugging), the app offers to download the official archive from Google’s server and unpacks it automatically (Settings → ADB).
- **Scan history** (SQLite) and **new-device highlighting** (only those with a MAC/ports/names).
- **Report export** to CSV (Excel-friendly) and JSON.
- **Themes**: dark and light, switched on the fly. **Languages**: Russian and English, auto-detected from the locale.
- **Self-update**: the app checks GitHub Releases at startup (can be disabled in settings) and on demand, downloads the new version, installs it over the old one (venv and history untouched) and offers a restart.

## Running without installation

```bash
git clone https://github.com/teliy/droidscout
cd droidscout
python -m venv venv
venv/bin/pip install -r requirements.txt    # Windows: venv\Scripts\pip
venv/bin/python droidscout.py               # Windows: venv\Scripts\python droidscout.py
```

## Updates

- The **“Check for updates”** button or an automatic check at startup.
- The repository is **public** — no token needed: the app downloads the new version from GitHub Releases by itself.
- If you work with your own **private** fork, the app needs a GitHub token (fine-grained, Contents: Read is enough): the installer saves it automatically, or set it manually in “Settings” — otherwise the API returns 404.

## How it works

| Stage | Method | What it gives |
|---|---|---|
| 1 | ICMP ping sweep of the subnet | list of live hosts |
| 2 | Reading the OS ARP table | MAC addresses and vendors |
| 3 | TCP scan of 25 ports | ADB, Cast, HTTP, SSH, UPnP etc. |
| 4 | mDNS (zeroconf) | Google Cast, Android TV Remote, ADB TLS, AirPlay + models |
| 5 | SSDP/UPnP | vendor, model, MediaRenderer |
| 6 | HTTP GET | `Server:` banners, `<title>` |
| 7 | Reverse DNS | host names |
| 8 | Heuristics | device type and the “Android” verdict with confidence |

No administrator rights are required: only the system `ping`, the ARP table and plain TCP connections are used.

## Publishing a private repository

```bash
# 1. Install GitHub CLI and sign in: gh auth login
# 2. From the project root:
./scripts/publish_github.sh YOUR_LOGIN          # Linux/macOS
powershell -File scripts\publish_github.ps1 -Login YOUR_LOGIN   # Windows
```

The script creates a private `droidscout` repository, pushes the code, substitutes the login into all
installers, creates a `v1.0.0` release (so self-updates work right away) and prints ready-made
installation and token-creation commands.

## Project structure

```
droidscout/
├── droidscout.py            # launcher
├── requirements.txt
├── install.sh / install.ps1 # installers (path prompt, venv, dependencies)
├── scripts/                 # publishing a private repo to GitHub
└── droidscout/              # application package
    ├── main.py              # entry point
    ├── scanner.py           # network engine (ping, ARP, ports, mDNS, SSDP, HTTP)
    ├── fingerprint.py       # Android device classification
    ├── oui.py + data/       # MAC vendor database (IEEE, gzip)
    ├── adb_info.py          # Android device survey: built-in client + external adb
    ├── pure_adb.py          # built-in ADB client (TCP, SMART sockets, RSA auth)
    ├── adb_manager.py       # automatic Android Platform-Tools setup from dl.google.com
    ├── storage.py           # SQLite history
    ├── exporter.py          # CSV/JSON
    ├── updater.py           # GitHub update check and install
    ├── config.py / i18n.py  # settings and RU/EN localization
    └── ui/                  # PySide6: window, themes, table model, dialogs
```

## Known limitations

- MAC randomization on modern phones can hide the vendor — in that case Android is detected from services (Cast/ADB/TLS).
- The ADB survey works only if “USB debugging” is enabled on the device and the user has allowed the connection. On the first connection the device screen shows an “Allow USB debugging” dialog — confirm it (better with “Always allow”). The built-in client uses the same keys as the official adb, so already-authorized devices need no second confirmation.
- Windows SmartScreen may warn about running a script downloaded from the internet — normal for PowerShell installers.
- For scanning several /24 subnets use the “All networks” choice.

## License

**GNU General Public License v3.0 (GPL-3.0)** — the full text is in the [LICENSE](LICENSE) file.

This is free software: you may redistribute and/or modify it under the terms of the GNU GPL v3.0 as published by the Free Software Foundation. The program is distributed **without any warranty** — without even the implied warranty of merchantability or fitness for a particular purpose. Derivative works must also be distributed as open source under GPL-3.0.
