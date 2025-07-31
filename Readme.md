# WG-Gesucht-Updater
*English below.*

> ⚠️ **Hinweis:** Automatisierung kann gegen die Nutzungsbedingungen von WG‑Gesucht verstoßen. Nutzung auf eigenes Risiko.

## Kurzüberblick
Schiebt deine Anzeigen nach oben, indem sie **kurz deaktiviert und sofort reaktiviert** werden.

**Features**
- Läuft **ohne** CLI‑Argumente (liest `.env`, sonst Prompts)
- **Status/Stop**: `status`, `status --watch`, `status --open`, `stop`
- **Web‑UI** (lokal, token‑geschützt)
- **Log & PID** liegen **neben dem Skript** (`wgrefresher.log`, `wgrefresher.pid`)
- Retries/Backoff; Re‑Login bei 401/403; Windows/macOS/Linux

## Installation
```bash
git clone https://github.com/CodeLtDave/wg-gesucht-updater.git
cd wg-gesucht-updater

# (optional) venv
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt   # oder: pip install requests
cp .env.template .env             # Windows: copy .env.template .env .env
```

## `.env` (mindestens diese drei)
```ini
EMAIL=dein@mail.tld
PASSWORD=deinPasswort
AD_IDS=123456,654321

# Optional:
# WG_INTERVAL=3600
# WG_CONTROL_PORT=12701
# WG_TIMEOUT=20
# WG_MAX_RETRIES=3
# WG_EMAIL_FILE=
# WG_PASSWORD_FILE=
# WG_AD_ID_FILE=
```

## Start / Status / Stop
```bash
python wg-gesucht-updater.py              # Start
python wg-gesucht-updater.py status       # Status (formatiert)
python wg-gesucht-updater.py status --watch
python wg-gesucht-updater.py status --open
python wg-gesucht-updater.py status --json
python wg-gesucht-updater.py stop         # Stop
```

## Dateipfade
- Log & PID: `./wgrefresher.log`, `./wgrefresher.pid` (Skriptordner)
- Token & Port: Nutzer‑Konfigpfad
  - Linux: `~/.config/wgrefresher/`
  - macOS: `~/Library/Application Support/wgrefresher/`
  - Windows: `%APPDATA%\wgrefresher\`

## ad_id finden
WG‑Gesucht → **„Meine Anzeigen“** → **Anzeigennummer**.

---

# WG-Gesucht-Updater (English)

> ⚠️ **Disclaimer:** Automation may violate WG‑Gesucht’s Terms. Use at your own risk.

## Overview
Bumps your ads by **briefly deactivating and immediately reactivating** them on a schedule.

**Features**
- Runs **without** CLI args (reads `.env`, otherwise prompts)
- **Cross‑platform status/stop**: `status`, `status --watch`, `status --open`, `stop`
- **Web UI** (local, token‑protected)
- **Log & PID** **next to the script** (`wgrefresher.log`, `wgrefresher.pid`)
- Retries/backoff; re‑login on 401/403; Windows/macOS/Linux

## Setup
```bash
git clone https://github.com/CodeLtDave/wg-gesucht-updater.git
cd wg-gesucht-updater

# (optional) venv
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

pip install -r requirements.txt   # or: pip install requests
cp .env.template .env             # Windows: copy .env.template .env
```

## `.env` (at least these)
```ini
EMAIL=your@mail.tld
PASSWORD=yourPassword
AD_IDS=123456,654321

# Optional:
# WG_INTERVAL=3600
# WG_CONTROL_PORT=12701
# WG_TIMEOUT=20
# WG_MAX_RETRIES=3
# WG_EMAIL_FILE=
# WG_PASSWORD_FILE=
# WG_AD_ID_FILE=
```

## Start / Status / Stop
```bash
python wg-gesucht-updater.py              # Start
python wg-gesucht-updater.py status       # Pretty status
python wg-gesucht-updater.py status --watch
python wg-gesucht-updater.py status --open
python wg-gesucht-updater.py status --json
python wg-gesucht-updater.py stop         # Stop
```

## File locations
- Log & PID: `./wgrefresher.log`, `./wgrefresher.pid` (script folder)
- Token & port: user config dir
  - Linux: `~/.config/wgrefresher/`
  - macOS: `~/Library/Application Support/wgrefresher/`
  - Windows: `%APPDATA%\wgrefresher\`
