# DaggerConnect Control Panel v1.1.0

A secure, browser-based control panel for managing [DaggerConnect](https://github.com/itsFLoKi/daggerconnect) tunnel nodes. Supports server/client role awareness, all transport protocols, live metrics, config management, and HTTPS with two-layer authentication — all served by a hardened nginx reverse proxy.

---

## Table of Contents

- [Features](#features)
- [Server vs Client — Two-VPS Setup](#server-vs-client--two-vps-setup)
- [Requirements](#requirements)
- [Installation](#installation)
- [Subcommands](#subcommands)
- [Useful Commands](#useful-commands)
- [Security Notes](#security-notes)
- [License](#license)

---

## Features

### Monitoring
- **Metrics history** — CPU, RAM, download, and upload graphs with up to 4 hours of history at 5s resolution
- **Bandwidth budget** — track total server traffic usage against a configurable limit
- **Live logs** — real-time `journalctl` tail for both server and client services
- **WebSocket polling** — efficient live updates via WS instead of repeated HTTP polling

### Connections
- **Connections & GeoIP** — role-aware active connection list via `ss`, with geographic IP lookup
- **Port maps** — parsed from `listeners[].maps[]` in server YAML

### Config Management
- **YAML editor** — read, edit, and save `server.yaml` / `client.yaml` with syntax highlighting
- **Diff view** — see exactly what changed before saving
- **Backup & revert** — restore the config to any previous snapshot
- **Config templates** — one-click pre-filled YAML for every transport × role combination
- **Bundle export/import** — pack and transfer the full current config as a single file

### Security & Auth
- **Two-layer auth** — HTTP Basic Auth (nginx) + token auth (panel)
- **Token & Auth** — rotate the panel token at any time from the UI
- **Audit log** — timestamped record of every change made through the panel
- **Rate limiting + security headers** — nginx config includes CSP, HSTS, X-Frame-Options, X-Content-Type-Options, and more

### Service Control
- **Service control** — start / stop / restart / enable / disable via `systemctl`
- **Scheduled restart** — configure automatic restart of the server or client service on a schedule
- **Resource quota** — set CPU/RAM thresholds that trigger an automatic service restart

### Infrastructure
- **Server/client role awareness** — UI, labels, and YAML templates adapt automatically per node
- **TLS cert tool** — generate self-signed certs for DaggerConnect listeners
- **DaggerMux helper** — FEC calculator, TCP flag profiles, one-click iptables NOTRACK rules

---

## Server vs Client — Two-VPS Setup

Install the panel on **both** VPSes. The role is detected automatically:

| YAML file present | Detected role |
|---|---|
| `/etc/DaggerConnect/server.yaml` | `server` — Iran / relay VPS |
| `/etc/DaggerConnect/client.yaml` | `client` — Foreign / exit VPS |

The panel adjusts UI labels, nav highlighting, connection view direction, and YAML templates based on the detected role.

> **Note:** If neither config file is found, the installer will offer to install and configure DaggerConnect for you before proceeding. If you decline, the installer will abort.

---

## Requirements

| Package | Required | Notes |
|---|---|---|
| `socat` | Yes | Backend HTTP socket |
| `python3` | Yes | YAML parsing, timing-safe auth |
| `python3-yaml` | Yes | Config read/write |
| `nginx` | Yes | HTTPS reverse proxy |
| `apache2-utils` | Yes | `htpasswd` for Basic Auth |
| `openssl` | Yes | PSK + TLS cert generation |
| `libpcap-dev` | daggermux only | `apt install libpcap-dev` |

All required packages (except `libpcap-dev`) are installed automatically by the installer.

---

## Installation

### One-command install (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main/install.sh)
```

The installer will:

1. Detect whether DaggerConnect is already installed
   - If not found, offer to install it automatically before continuing
2. Install all required dependencies (`socat`, `nginx`, `apache2-utils`, `python3`, `python3-yaml`, `openssl`)
3. Prompt you to choose an HTTPS port (default: `8443`)
4. Prompt you to set a username and password for HTTP Basic Auth
5. Generate a self-signed TLS certificate
6. Configure nginx as a reverse proxy with security headers and rate limiting
7. Install and start a `systemd` service (`daggerconnect-panel`) that survives reboots
8. Open the chosen port (and port 80 for HTTP→HTTPS redirect) in `ufw` if available

### Running the installer again

If the panel is already installed, re-running the installer will present a menu:

- **Update** — pull the latest panel files and restart the service (preserves existing port, credentials, and cert)
- **Uninstall** — remove the panel, nginx config, TLS cert, and auth token (DaggerConnect config is untouched)
- **Cancel**

---

## Subcommands

```bash
# Change the panel web login password
sudo bash install.sh change-password

# Uninstall the panel
sudo bash install.sh uninstall
```

---

## Useful Commands

```bash
# Check panel status
systemctl status daggerconnect-panel

# Stop / start / restart panel
systemctl stop daggerconnect-panel
systemctl start daggerconnect-panel
systemctl restart daggerconnect-panel

# Follow panel logs
journalctl -u daggerconnect-panel -f

# Follow nginx access log
tail -f /var/log/nginx/dagger-panel-access.log

# Follow nginx error log
tail -f /var/log/nginx/dagger-panel-error.log
```

---

## Security Notes

- The socat backend binds to `127.0.0.1:7070` only — it must **never** be opened in the firewall
- nginx config includes: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, rate limiting (10 req/s, burst 20)
- All config changes are recorded in the audit log with timestamps
- Config backups are rotated automatically — revert to any previous snapshot from the panel UI
- The panel TLS certificate is self-signed by default — your browser will warn on first visit; click **Advanced → Proceed** to continue
- Replace the self-signed cert with a real one via certbot for production use

---

## License

MIT — see [LICENSE](LICENSE) for details.