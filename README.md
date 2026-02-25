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
- **PSK generator** — cryptographically random pre-shared key generation
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
├── start.sh          ← Starts the socat backend, manages token and role
├── setup-nginx.sh    ← Installs nginx, TLS cert, Basic Auth, reverse proxy config
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
| 2 | Token auth | Panel UI — token printed by `start.sh`, sent as `X-Auth-Token` |

---

## Server vs Client — Two-VPS Setup

Install the panel on **both** VPSes. The **role** tells the panel which side it is on.

| Role | VPS | DaggerConnect mode |
|---|---|---|
| `server` | Iran / relay VPS | `mode: "server"` — receives tunnel connections |
| `client` | Foreign / exit VPS | `mode: "client"` — connects outward to the server |

The role is set interactively on first start, or manually:

```bash
sudo ./start.sh role server    # Iran VPS
sudo ./start.sh role client    # Foreign VPS
```

The panel adjusts UI labels, nav highlighting, connection view direction, and YAML templates based on the role.

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

## Setup

### 1. Upload to both VPSes

```bash
scp -r daggerconnect-panel/ root@IRAN_VPS:/opt/daggerconnect-panel/
scp -r daggerconnect-panel/ root@FOREIGN_VPS:/opt/daggerconnect-panel/
```

### 2. Make scripts executable

```bash
chmod +x /opt/daggerconnect-panel/*.sh
```

### 3. Install dependencies

```bash
apt install socat nginx apache2-utils python3 python3-yaml openssl -y

# daggermux only:
apt install libpcap-dev -y
```

### 4. Start the socat backend

```bash
sudo /opt/daggerconnect-panel/start.sh
```

On first run you will be asked whether this is the **server** (Iran/relay) or **client** (foreign/exit) VPS. The role is saved to `/etc/DaggerConnect/panel.role`. The auth token is printed to the terminal and saved to `/etc/DaggerConnect/panel.token`.

### 5. Set up nginx

```bash
sudo /opt/daggerconnect-panel/setup-nginx.sh
```

This script automatically:
- Generates a self-signed TLS certificate (skipped if one already exists)
- Prompts for an HTTP Basic Auth username and password
- Writes and enables the nginx config
- Opens ports 8443 and 80 in ufw (if available)
- Runs a post-setup healthcheck

### 6. Open the panel

```
https://YOUR_VPS_IP:8443
```

Your browser will warn about the self-signed certificate — click **Advanced → Proceed**. Enter the Basic Auth credentials you set in step 5, then enter the token printed in step 4.

> For a trusted certificate: `certbot --nginx -d yourdomain.com`

---

## Persistent Service (survives reboot)

The panel process will stop on reboot unless you add a systemd unit. `start.sh` prints the exact unit file on first run. To apply it:

```bash
cat > /etc/systemd/system/daggerconnect-panel.service <<EOF
[Unit]
Description=DaggerConnect Control Panel
After=network.target

[Service]
ExecStart=/bin/bash /opt/daggerconnect-panel/start.sh
ExecStop=/bin/bash /opt/daggerconnect-panel/start.sh stop
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now daggerconnect-panel
```

---

## Useful Commands

```bash
# Set / check node role
sudo /opt/daggerconnect-panel/start.sh role
sudo /opt/daggerconnect-panel/start.sh role server
sudo /opt/daggerconnect-panel/start.sh role client

# View the auth token
sudo /opt/daggerconnect-panel/start.sh token

# Check panel status
sudo /opt/daggerconnect-panel/start.sh status

# Stop / start panel
sudo /opt/daggerconnect-panel/start.sh stop
sudo /opt/daggerconnect-panel/start.sh

# Follow panel logs
sudo /opt/daggerconnect-panel/start.sh logs
# or:
tail -f /tmp/daggerconnect-panel.log

# Follow nginx access log
tail -f /var/log/nginx/dagger-panel-access.log

# Change nginx Basic Auth password
sudo /opt/daggerconnect-panel/setup-nginx.sh change-password

# Regenerate auth token
sudo rm /etc/DaggerConnect/panel.token
sudo /opt/daggerconnect-panel/start.sh
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