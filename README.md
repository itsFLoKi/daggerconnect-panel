# DaggerConnect Control Panel v1.0.0

A secure, browser-based control panel for managing [DaggerConnect](https://github.com/your-repo/daggerconnect) tunnel nodes. Supports server/client role awareness, all transport protocols, live metrics, config editing, and HTTPS with two-layer authentication — all served by a hardened nginx reverse proxy.

---

## Features

- **Browser UI** — manage your DaggerConnect node from any browser over HTTPS
- **Two-layer auth** — HTTP Basic Auth (nginx) + token auth (panel)
- **Server/client role awareness** — UI, labels, and YAML templates adapt per node
- **YAML editor** — read, edit, and save `server.yaml` / `client.yaml` with backup rotation
- **Config templates** — one-click pre-filled YAML for every transport × role combination
- **Live metrics** — CPU, RAM, bandwidth history (up to 4 hours at 5s resolution)
- **Connections view** — role-aware active connection list via `ss`
- **Port maps** — parsed from `listeners[].maps[]` in server YAML
- **TLS cert tool** — generate self-signed certs for DaggerConnect listeners
- **DaggerMux helper** — FEC calculator, TCP flag profiles, one-click iptables NOTRACK rules
- **Service control** — start / stop / restart / enable / disable via `systemctl`
- **Live logs** — `journalctl` tail for server and client services
- **Rate limiting + security headers** — nginx config includes CSP, HSTS, X-Frame-Options, and more

---

## File Layout

```
daggerconnect-panel/
├── panel.html        ← Browser UI (served by nginx at HTTPS :8443)
├── api.sh            ← Bash API handler (called by socat on 127.0.0.1:7070)
├── start.sh          ← Starts the socat backend, manages token
├── install.sh        ← One-command installer
└── README.md
```

---

## Architecture

```
Internet
   │  HTTPS :8443
   ▼
nginx (reverse proxy)
   │  HTTP Basic Auth  ← username + password (browser native prompt)
   │  TLS termination, rate limiting, security headers
   │
   │  proxy_pass → 127.0.0.1:7070/api/
   ▼
socat  (loopback only — port 7070 is NEVER exposed in the firewall)
   │  Token auth (X-Auth-Token header)
   ▼
api.sh (bash)
   ├── systemctl  start/stop/restart/enable/disable
   ├── journalctl  (logs)
   ├── read/write  /etc/DaggerConnect/server.yaml + client.yaml
   ├── ps / /proc/stat  (stats + metrics history)
   ├── ss  (active connections)
   ├── openssl  (cert + PSK generation)
   ├── role management  (/etc/DaggerConnect/panel.role)
   └── iptables NOTRACK rules  (daggermux)
```

**Two auth layers:**
| Layer | Mechanism | Where |
|---|---|---|
| 1 | HTTP Basic Auth | nginx — browser native prompt |
| 2 | Token auth | Panel UI — token printed by `start.sh token`, sent as `X-Auth-Token` |

---

## Server vs Client — Two-VPS Setup

Install the panel on **both** VPSes. The role is detected automatically:

| YAML file present | Detected role |
|---|---|
| `/etc/DaggerConnect/server.yaml` | `server` — Iran / relay VPS |
| `/etc/DaggerConnect/client.yaml` | `client` — Foreign / exit VPS |

The panel will refuse to start if neither file exists. Install and configure DaggerConnect first, then run the panel installer.

The panel adjusts UI labels, nav highlighting, connection view direction, and YAML templates based on the detected role.

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

---

## Installation

### One-command install (recommended)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main/install.sh)
```

This will: install dependencies, clone the repo to `/opt/daggerconnect-panel`, start the socat backend, configure nginx with TLS and Basic Auth, and install a systemd service so the panel survives reboots.

> **Prerequisite:** DaggerConnect must already be installed and either `/etc/DaggerConnect/server.yaml` or `/etc/DaggerConnect/client.yaml` must exist. The installer will abort if neither is found.

---

### Manual setup

#### 1. Download the files

```bash
mkdir -p /opt/daggerconnect-panel
cd /opt/daggerconnect-panel
for FILE in panel.html api.sh start.sh; do
  curl -fsSL "https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main/${FILE}" -o "${FILE}"
done
chmod +x *.sh
```

#### 2. Install dependencies

```bash
apt install socat nginx apache2-utils python3 python3-yaml openssl -y

# daggermux only:
apt install libpcap-dev -y
```

#### 3. Install the systemd service

```bash
cat > /etc/systemd/system/daggerconnect-panel.service <<EOF
[Unit]
Description=DaggerConnect Control Panel
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/daggerconnect-panel/start.sh
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now daggerconnect-panel
```

The role is detected automatically from your DaggerConnect config. Retrieve the auth token with:

```bash
sudo /opt/daggerconnect-panel/start.sh token
```

#### 4. Set up nginx

Run the installer which handles TLS cert generation, HTTP Basic Auth setup, nginx config, and firewall rules:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main/install.sh)
```

#### 5. Open the panel

```
https://YOUR_VPS_IP:8443
```

Your browser will warn about the self-signed certificate — click **Advanced → Proceed**. Enter the Basic Auth credentials, then enter the token from step 3.

> For a trusted certificate: `certbot --nginx -d yourdomain.com`

---

## Useful Commands

```bash
# View the auth token
sudo /opt/daggerconnect-panel/start.sh token

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

# Change nginx Basic Auth password
sudo bash /opt/daggerconnect-panel/install.sh change-password

# Regenerate auth token
sudo rm /etc/DaggerConnect/panel.token
systemctl restart daggerconnect-panel
sudo /opt/daggerconnect-panel/start.sh token
```

---

## Security Notes

- The socat backend binds to `127.0.0.1:7070` only — it must **never** be opened in the firewall
- Auth token comparison uses `hmac.compare_digest` (timing-safe)
- nginx config includes: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, rate limiting (10 req/s, burst 20)
- Config backups are rotated automatically (5 most recent kept)
- The panel TLS certificate is self-signed by default — replace with a real cert via certbot for production use

---

## License

MIT — see [LICENSE](LICENSE) for details.