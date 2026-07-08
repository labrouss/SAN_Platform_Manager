# SAN Management Platform

A cross-platform desktop application for managing Cisco MDS 9000 series Fibre Channel switches. Built with Python, PyQt5, and a Tailwind CSS web frontend embedded via QtWebEngine.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![PyQt5](https://img.shields.io/badge/PyQt5-5.15%2B-green)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Screenshots

| Dashboard | Zone Editor | Performance |
|-----------|------------|-------------|
| Live switch stats and quick navigation | Draft and commit FC zones per VSAN | Port throughput and SFP optical power charts |

---

## Features

- **FC Alias Manager** — Create, edit, sync and search device aliases (WWN to name mapping)
- **Zone Editor** — Draft FC zones and zone sets per VSAN, commit to switch via NX-API; pre-commit snapshots created automatically
- **Fabric Discovery** — FCNS name server database with vendor, FC4 type, and interface details
- **Port Inventory** — Full FC interface list with state, mode, speed, VSAN, peer WWN and alias
- **SFP Health** — Transceiver diagnostics: RX/TX optical power, temperature, voltage, and bias current with colour-coded health indicators
- **Performance Charts** — Port throughput (TX/RX Mbps) and optical power (RX/TX dBm) history via Chart.js
- **Snapshots** — Versioned zoning configuration history with one-click restore
- **User Management** — Role-based access control (Admin / Operator / Viewer)
- **Backup & Restore** — Full JSON export/import via native file dialogs
- **MDS 9000 Simulator** — Built-in simulator with configurable per-port state, throughput ranges, and optical power ranges; no real switch required for development/testing

---

## Architecture

```
main.py              PyQt5 application shell
  └── BridgePage     QWebEnginePage subclass — intercepts console.log IPC
src/app.html         Single-file Tailwind + Chart.js frontend
bridge.py            All Python bridge methods exposed to JS
db/database.py       SQLite schema and CRUD (via stdlib sqlite3)
services/
  mds_client.py      Real NX-API HTTP client
  mds_simulator.py   Built-in MDS 9000 simulator
  client_factory.py  Selects real or simulated client per switch
workers/poller.py    Background polling thread (metrics collection)
```

**IPC mechanism:** JavaScript calls Python by writing a JSON payload to `console.log("__bridge__:...")`. Python's `javaScriptConsoleMessage()` intercepts it, executes the bridge method, and returns the result via `page.runJavaScript("window.__bridgeReply(...)")`. No QWebChannel, no custom URL scheme — works on all platforms.

---

## Requirements

| Dependency | Version |
|-----------|---------|
| Python | 3.9+ |
| PyQt5 | 5.15+ |
| PyQtWebEngine | 5.15+ |
| requests | 2.28+ |

---

## Installation

### From source

```bash
git clone https://github.com/labrouss/san-platform.git
cd san-platform/san-web

# Install dependencies
pip install PyQt5 PyQtWebEngine requests

# Run
python main.py
```

### From release binary

Download the pre-built executable for your platform from the [Releases](../../releases) page.
No Python installation required.

| Platform | File |
|---------|------|
| Windows | `san-platform.exe` |
| Linux | `san-platform` |
| macOS | `san-platform` |

**Windows:** Windows Defender may scan the executable on first run — this is normal for PyInstaller apps.

**macOS:** If Gatekeeper blocks the app, run:
```bash
xattr -cr san-platform
```

**Linux:** Make the binary executable:
```bash
chmod +x san-platform
./san-platform
```

---

## Default Credentials

```
Username: admin
Password: Admin1234!
```

> **Change the admin password immediately after first login** via Settings > Users.

---

## Database

The SQLite database is stored at:

| Platform | Path |
|---------|------|
| Windows | `C:\Users\<you>\.san-platform\san_platform.db` |
| Linux / macOS | `~/.san-platform/san_platform.db` |

To reset the database:
```bash
python main.py --reset-db
```

---

## Simulator Mode

The built-in MDS 9000 simulator lets you use the full application without a real switch.

**Enable:** Settings > MDS 9000 Simulator toggle, then Save Settings.

**Per-port configuration:** Navigate to Simulator in the sidebar to configure each port's:
- State (Up / Down), mode (F/E/TE/FL), speed (4G–64G), VSAN
- SFP presence and degraded flag
- Throughput ranges (TX/RX min/max Mbps)
- Optical power ranges (RX/TX min/max dBm)

Settings are persisted to the database and survive restarts.

---

## Connecting a Real Switch

1. Ensure NX-API is enabled on the MDS switch:
   ```
   switch# conf t
   switch(config)# feature nxapi
   switch(config)# nxapi http port 80
   switch(config)# nxapi https port 443
   ```

2. In the app: Settings > Add Switch > enter IP, username, password > Test Connection > Add Switch.

3. Disable Simulator mode if it was enabled.

---

## Building from Source

The `build.py` script wraps PyInstaller and produces a single-file executable.

```bash
# First time: install build dependencies
python build.py --install-deps

# Build for the current platform
python build.py

# Clean rebuild
python build.py --clean
```

Output is placed in `dist/san-platform` (Linux/macOS) or `dist/san-platform.exe` (Windows).

---

## GitHub Actions — Automated Builds

The included workflow (`.github/workflows/build.yml`) builds release executables for all three platforms whenever a version tag is pushed:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers builds on `ubuntu-latest`, `windows-latest`, and `macos-latest` runners and publishes the executables as GitHub Release assets.

---

## Project Structure

```
san-web/
├── main.py                  Application entry point
├── bridge.py                Python bridge (all methods callable from JS)
├── build.py                 Cross-platform PyInstaller build script
├── requirements.txt         Python dependencies
├── db/
│   └── database.py          SQLite schema and all CRUD operations
├── services/
│   ├── client_factory.py    Routes calls to real or simulated client
│   ├── mds_client.py        Cisco NX-API HTTP client
│   └── mds_simulator.py     Built-in MDS 9000 simulator
├── workers/
│   └── poller.py            Background metrics collection thread
└── src/
    └── app.html             Complete single-file frontend (Tailwind + Chart.js)
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [Cisco DevNet](https://developer.cisco.com/docs/mds/) — NX-API documentation
- [PyQt5](https://www.riverbankcomputing.com/software/pyqt/) — Qt bindings for Python
- [Tailwind CSS](https://tailwindcss.com) — Utility-first CSS framework
- [Chart.js](https://www.chartjs.org) — JavaScript charting library
