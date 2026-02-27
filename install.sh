#!/bin/bash
# ============================================================
# DaggerConnect Control Panel — Installer / Updater / Uninstaller
# Usage:
#   Install / Update : sudo bash daggerconnect-panel.sh
#   Uninstall        : sudo bash daggerconnect-panel.sh uninstall
#   Change password  : sudo bash daggerconnect-panel.sh change-password
# ============================================================

INSTALL_DIR="/opt/daggerconnect-panel"
GITHUB_REPO="itsFLoKi/daggerconnect-panel"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
FILES=(panel.html api.sh start.sh)

SOCAT_PORT=7070
HTPASSWD_FILE="/etc/nginx/.dagger-htpasswd"
CERT_DIR="/etc/DaggerConnect/panel-tls"
NGINX_CONF="/etc/nginx/sites-available/daggerconnect-panel"
NGINX_LINK="/etc/nginx/sites-enabled/daggerconnect-panel"
TOKEN_FILE="/etc/DaggerConnect/panel.token"
ROLE_FILE="/etc/DaggerConnect/panel.role"
PID_FILE="/tmp/daggerconnect-panel.pid"
LOG_FILE="/tmp/daggerconnect-panel.log"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

die()      { echo -e "${RED}✗ $1${NC}"; exit 1; }
ok_msg()   { echo -e "${GRN}✓ $1${NC}"; }
warn_msg() { echo -e "${YLW}⚠ $1${NC}"; }
section()  { echo ""; echo -e "${CYN}── $1 ──${NC}"; }

[[ $EUID -ne 0 ]] && die "Must run as root: sudo bash daggerconnect-panel.sh"

echo -e "${CYN}"
echo "  ██████╗  █████╗  ██████╗  ██████╗ ███████╗██████╗ "
echo "  ██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗"
echo "  ██║  ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝"
echo "  ██║  ██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗"
echo "  ██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo -e "${NC}"

# ============================================================
# UNINSTALL
# ============================================================
if [[ "$1" == "uninstall" ]]; then
  echo -e "  Control Panel ${RED}Uninstaller${NC} v1.1.0"
  echo ""
  echo -e "${YLW}This will remove the control panel, nginx config, TLS cert, and auth token."
  echo -e "Your DaggerConnect config files will NOT be touched.${NC}"
  echo ""
  read -rp "  Are you sure? [y/N]: " CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

  # ── Stop and disable systemd service ───────────────────────
  section "Stopping service"
  if systemctl is-active --quiet daggerconnect-panel 2>/dev/null; then
    systemctl stop daggerconnect-panel && ok_msg "Service stopped"
  else
    warn_msg "Service was not running"
  fi
  systemctl disable daggerconnect-panel 2>/dev/null && ok_msg "Service disabled"
  rm -f /etc/systemd/system/daggerconnect-panel.service
  systemctl daemon-reload
  ok_msg "systemd unit removed"

  # ── Kill any leftover socat process ────────────────────────
  if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    COMM=$(ps -p "$PID" -o comm= 2>/dev/null | tr -d '[:space:]')
    if [[ "$COMM" == "socat" ]]; then
      kill "$PID" 2>/dev/null && ok_msg "socat process killed (PID $PID)"
    fi
    rm -f "$PID_FILE"
  fi

  # ── Remove nginx config ─────────────────────────────────────
  section "Removing nginx config"
  rm -f "$NGINX_LINK"    && ok_msg "Removed sites-enabled symlink"
  rm -f "$NGINX_CONF"    && ok_msg "Removed sites-available config"
  rm -f "$HTPASSWD_FILE" && ok_msg "Removed htpasswd file"

  if [[ -z "$(ls /etc/nginx/sites-enabled/ 2>/dev/null)" ]]; then
    ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null
    warn_msg "No other nginx sites active — restored default site"
  fi

  if nginx -t 2>/dev/null; then
    systemctl reload nginx 2>/dev/null && ok_msg "nginx reloaded"
  else
    warn_msg "nginx config has errors after removal — check manually"
  fi

  # ── Remove panel TLS cert ───────────────────────────────────
  section "Removing panel TLS certificate"
  rm -rf "$CERT_DIR" && ok_msg "Removed $CERT_DIR"

  # ── Remove panel token, role, logs ─────────────────────────
  section "Removing panel data"
  rm -f "$TOKEN_FILE" && ok_msg "Removed panel token"
  rm -f "$ROLE_FILE"  && ok_msg "Removed role file"
  rm -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null && ok_msg "Removed log files"

  # ── Remove panel files ──────────────────────────────────────
  section "Removing panel files"
  rm -rf "$INSTALL_DIR" && ok_msg "Removed $INSTALL_DIR"

  # ── Close firewall ports ────────────────────────────────────
  section "Firewall"
  if command -v ufw &>/dev/null; then
    ufw delete allow 8443/tcp 2>/dev/null && ok_msg "ufw: removed port 8443"
    ufw delete allow 80/tcp   2>/dev/null && ok_msg "ufw: removed port 80"
  else
    warn_msg "ufw not found — remove ports 8443 and 80 manually if needed"
  fi

  echo ""
  echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GRN}  ✓ Panel uninstalled completely.${NC}"
  echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo -e "  ${YLW}Note:${NC} DaggerConnect itself and its config files were not touched."
  echo -e "        To reinstall the panel: sudo bash daggerconnect-panel.sh"
  echo ""
  exit 0
fi

# ============================================================
# CHANGE PASSWORD (subcommand)
# ============================================================
if [[ "$1" == "change-password" ]]; then
  section "Change panel password"
  if ! command -v htpasswd &>/dev/null; then
    die "htpasswd not found — install apache2-utils"
  fi
  if [[ ! -f "$HTPASSWD_FILE" ]]; then
    die "htpasswd file not found at $HTPASSWD_FILE — run setup first"
  fi
  echo -e "${YLW}Username to update (leave blank to list existing):${NC}"
  read -rp "  Username: " CHPW_USER
  if [[ -z "$CHPW_USER" ]]; then
    echo "Existing users:"
    cut -d: -f1 "$HTPASSWD_FILE"
    exit 0
  fi
  while true; do
    echo -e "${YLW}New password (hidden):${NC}"
    read -rsp "  Password: " P1; echo ""
    read -rsp "  Confirm:  " P2; echo ""
    if [[ "$P1" != "$P2" ]]; then
      warn_msg "Passwords do not match — try again"
    elif [[ ${#P1} -lt 8 ]]; then
      warn_msg "Password must be at least 8 characters — try again"
    else
      break
    fi
  done
  htpasswd -b "$HTPASSWD_FILE" "$CHPW_USER" "$P1" 2>/dev/null \
    && ok_msg "Password updated for '$CHPW_USER'" \
    || die "htpasswd update failed"
  systemctl reload nginx 2>/dev/null && ok_msg "nginx reloaded"
  exit 0
fi

# ============================================================
# INSTALL / UPDATE
# ============================================================

# ── Detect: fresh install or update ──────────────────────────
IS_UPDATE=false
if [[ -f "$INSTALL_DIR/start.sh" ]] && \
   systemctl is-enabled --quiet daggerconnect-panel 2>/dev/null && \
   systemctl is-active  --quiet daggerconnect-panel 2>/dev/null && \
   [[ -f "$NGINX_CONF" ]] && \
   [[ -f "$HTPASSWD_FILE" ]]; then
  IS_UPDATE=true
fi

if $IS_UPDATE; then
  echo -e "  Control Panel — ${YLW}Already Installed${NC}"
  echo ""
  echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  The DaggerConnect Control Panel is already installed."
  echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo -e "  What would you like to do?"
  echo ""
  echo -e "  ${GRN}[1]${NC} Update   — pull latest panel files and restart service"
  echo -e "  ${RED}[2]${NC} Uninstall — remove panel, nginx config, TLS cert & token"
  echo -e "  ${YLW}[3]${NC} Cancel"
  echo ""
  while true; do
    read -rp "  Your choice [1/2/3]: " MENU_CHOICE
    case "$MENU_CHOICE" in
      1)
        echo ""
        echo -e "  Control Panel ${YLW}Updater${NC} v1.1.0"
        echo ""
        break
        ;;
      2)
        echo ""
        # ── Inline uninstall ──────────────────────────────────
        echo -e "  Control Panel ${RED}Uninstaller${NC} v1.1.0"
        echo ""
        echo -e "${YLW}This will remove the control panel, nginx config, TLS cert, and auth token."
        echo -e "Your DaggerConnect config files will NOT be touched.${NC}"
        echo ""
        read -rp "  Are you sure? [y/N]: " CONFIRM
        [[ "$CONFIRM" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

        section "Stopping service"
        if systemctl is-active --quiet daggerconnect-panel 2>/dev/null; then
          systemctl stop daggerconnect-panel && ok_msg "Service stopped"
        else
          warn_msg "Service was not running"
        fi
        systemctl disable daggerconnect-panel 2>/dev/null && ok_msg "Service disabled"
        rm -f /etc/systemd/system/daggerconnect-panel.service
        systemctl daemon-reload
        ok_msg "systemd unit removed"

        if [[ -f "$PID_FILE" ]]; then
          PID=$(cat "$PID_FILE")
          COMM=$(ps -p "$PID" -o comm= 2>/dev/null | tr -d '[:space:]')
          if [[ "$COMM" == "socat" ]]; then
            kill "$PID" 2>/dev/null && ok_msg "socat process killed (PID $PID)"
          fi
          rm -f "$PID_FILE"
        fi

        section "Removing nginx config"
        rm -f "$NGINX_LINK"    && ok_msg "Removed sites-enabled symlink"
        rm -f "$NGINX_CONF"    && ok_msg "Removed sites-available config"
        rm -f "$HTPASSWD_FILE" && ok_msg "Removed htpasswd file"

        if [[ -z "$(ls /etc/nginx/sites-enabled/ 2>/dev/null)" ]]; then
          ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null
          warn_msg "No other nginx sites active — restored default site"
        fi
        if nginx -t 2>/dev/null; then
          systemctl reload nginx 2>/dev/null && ok_msg "nginx reloaded"
        else
          warn_msg "nginx config has errors after removal — check manually"
        fi

        section "Removing panel TLS certificate"
        rm -rf "$CERT_DIR" && ok_msg "Removed $CERT_DIR"

        section "Removing panel data"
        rm -f "$TOKEN_FILE" && ok_msg "Removed panel token"
        rm -f "$ROLE_FILE"  && ok_msg "Removed role file"
        rm -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null && ok_msg "Removed log files"

        section "Removing panel files"
        rm -rf "$INSTALL_DIR" && ok_msg "Removed $INSTALL_DIR"

        section "Firewall"
        if command -v ufw &>/dev/null; then
          ufw delete allow 8443/tcp 2>/dev/null && ok_msg "ufw: removed port 8443"
          ufw delete allow 80/tcp   2>/dev/null && ok_msg "ufw: removed port 80"
        else
          warn_msg "ufw not found — remove ports 8443 and 80 manually if needed"
        fi

        echo ""
        echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GRN}  ✓ Panel uninstalled completely.${NC}"
        echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "  ${YLW}Note:${NC} DaggerConnect itself and its config files were not touched."
        echo -e "        To reinstall the panel: sudo bash $0"
        echo ""
        exit 0
        ;;
      3|"")
        echo "Aborted."
        exit 0
        ;;
      *)
        warn_msg "Invalid choice — enter 1, 2, or 3"
        ;;
    esac
  done
else
  echo -e "  Control Panel ${GRN}Installer${NC} v1.1.0"
  echo ""

  # ── Pre-install cleanup: remove any leftover partial install ─
  section "Pre-install cleanup"
  _panel_cleanup() {
    # Stop & remove service
    if systemctl is-active --quiet daggerconnect-panel 2>/dev/null; then
      systemctl stop daggerconnect-panel 2>/dev/null && ok_msg "Stopped existing service"
    fi
    systemctl disable daggerconnect-panel 2>/dev/null
    rm -f /etc/systemd/system/daggerconnect-panel.service
    systemctl daemon-reload 2>/dev/null

    # Kill leftover socat
    if [[ -f "$PID_FILE" ]]; then
      PID=$(cat "$PID_FILE")
      COMM=$(ps -p "$PID" -o comm= 2>/dev/null | tr -d '[:space:]')
      [[ "$COMM" == "socat" ]] && kill "$PID" 2>/dev/null
      rm -f "$PID_FILE"
    fi

    # Remove nginx config
    rm -f "$NGINX_LINK" "$NGINX_CONF" "$HTPASSWD_FILE" 2>/dev/null
    if [[ -z "$(ls /etc/nginx/sites-enabled/ 2>/dev/null)" ]]; then
      ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default 2>/dev/null
    fi
    nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null

    # Remove certs, tokens, logs, files
    rm -rf "$CERT_DIR" 2>/dev/null
    rm -f "$TOKEN_FILE" "$ROLE_FILE" "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null
    rm -rf "$INSTALL_DIR" 2>/dev/null

    # Remove firewall rules silently
    if command -v ufw &>/dev/null; then
      ufw delete allow 8443/tcp 2>/dev/null
      ufw delete allow 80/tcp   2>/dev/null
    fi
  }

  # Only run cleanup if there's actually something to clean
  if [[ -d "$INSTALL_DIR" ]] || \
     systemctl is-enabled --quiet daggerconnect-panel 2>/dev/null || \
     [[ -f "$NGINX_CONF" ]] || \
     [[ -f "$HTPASSWD_FILE" ]]; then
    warn_msg "Existing panel files detected — cleaning up before fresh install..."
    _panel_cleanup
    ok_msg "Cleanup complete"
  else
    ok_msg "No previous installation found — clean slate"
  fi
fi

# ── Check DaggerConnect installed / config exists ─────────────
section "Checking DaggerConnect"
_dagger_config_found() {
  [[ -f "/etc/DaggerConnect/server.yaml" ]] || [[ -f "/etc/DaggerConnect/client.yaml" ]]
}

if [[ -f "/etc/DaggerConnect/server.yaml" ]]; then
  ok_msg "Found server.yaml — this node will run as SERVER"
elif [[ -f "/etc/DaggerConnect/client.yaml" ]]; then
  ok_msg "Found client.yaml — this node will run as CLIENT"
else
  warn_msg "DaggerConnect does not appear to be installed (no server.yaml or client.yaml found)."
  echo ""
  echo -e "  ${YLW}DaggerConnect is required before the panel can be installed.${NC}"
  echo -e "  ${CYN}Install it now? [Y/n]:${NC}"
  read -rp "  " INSTALL_DAGGER
  INSTALL_DAGGER="${INSTALL_DAGGER:-y}"

  if [[ "$INSTALL_DAGGER" =~ ^[Yy]$ ]]; then
    section "Installing DaggerConnect"
    TMP_SETUP=$(mktemp /tmp/dagger-setup-XXXX.sh)
    curl -fsSL "https://raw.githubusercontent.com/itsFLoKi/DaggerConnect/main/setup.sh" \
      -o "$TMP_SETUP" \
      || die "Failed to download DaggerConnect setup.sh — check your internet connection"
    chmod +x "$TMP_SETUP"
    bash "$TMP_SETUP" || die "DaggerConnect setup failed — resolve the issue above and re-run this installer"
    rm -f "$TMP_SETUP"

    # Re-check after install
    if _dagger_config_found; then
      ok_msg "DaggerConnect installed and config detected — continuing..."
    else
      die "DaggerConnect was installed but no config file found yet.\nConfigure DaggerConnect first (server.yaml or client.yaml), then re-run this installer."
    fi
  else
    die "DaggerConnect is required. Install and configure it, then re-run this installer."
  fi
fi

# ── Panel port selection ──────────────────────────────────────
DEFAULT_PANEL_PORT=8443
if $IS_UPDATE && [[ -f "$NGINX_CONF" ]]; then
  EXISTING_PORT=$(grep -oP 'listen \K[0-9]+(?= ssl)' "$NGINX_CONF" 2>/dev/null | head -1)
  [[ -n "$EXISTING_PORT" ]] && DEFAULT_PANEL_PORT="$EXISTING_PORT"
fi

if ! $IS_UPDATE; then
  section "Panel port"
  echo -e "${YLW}Choose the HTTPS port for the panel (press Enter for default):${NC}"
  while true; do
    read -rp "  Panel port [${DEFAULT_PANEL_PORT}]: " INPUT_PORT
    INPUT_PORT="${INPUT_PORT:-$DEFAULT_PANEL_PORT}"
    if [[ "$INPUT_PORT" =~ ^[0-9]+$ ]] && (( INPUT_PORT >= 1 && INPUT_PORT <= 65535 )); then
      PANEL_PORT="$INPUT_PORT"
      ok_msg "Panel will be served on port $PANEL_PORT"
      break
    else
      warn_msg "Invalid port '$INPUT_PORT' — enter a number between 1 and 65535"
    fi
  done
else
  PANEL_PORT="$DEFAULT_PANEL_PORT"
  ok_msg "Keeping existing panel port: $PANEL_PORT"
fi

# ── Dependencies ─────────────────────────────────────────────
if $IS_UPDATE; then
  section "Checking dependencies"
  MISSING=()
  for cmd in socat nginx htpasswd python3 openssl; do
    command -v "$cmd" &>/dev/null && ok_msg "$cmd" || MISSING+=("$cmd")
  done
  if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn_msg "Missing: ${MISSING[*]} — installing..."
    apt-get install -y socat nginx apache2-utils python3 python3-yaml openssl \
      || die "Failed to install missing dependencies"
  fi
else
  section "Installing dependencies"
  apt-get update -qq || warn_msg "apt update failed — continuing anyway"
  apt-get install -y socat nginx apache2-utils python3 python3-yaml openssl \
    || die "Failed to install dependencies"
  ok_msg "Dependencies installed"
fi

# ── Download panel files (latest release) ────────────────────
$IS_UPDATE && section "Updating panel files" || section "Downloading panel files"

mkdir -p "$INSTALL_DIR"

# Resolve the latest release tag and build the raw base URL
LATEST_TAG=$(curl -fsSL "$GITHUB_API" 2>/dev/null \
  | grep '"tag_name"' | head -1 \
  | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [[ -z "$LATEST_TAG" ]]; then
  warn_msg "Could not fetch latest release tag from GitHub — falling back to 'main'"
  RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/main"
else
  ok_msg "Latest release: $LATEST_TAG"
  RAW_BASE="https://raw.githubusercontent.com/${GITHUB_REPO}/${LATEST_TAG}"
fi

for FILE in "${FILES[@]}"; do
  curl -fsSL "${RAW_BASE}/${FILE}" -o "${INSTALL_DIR}/${FILE}" \
    && ok_msg "${FILE}" \
    || die "Failed to download ${FILE} — check your internet connection"
done
chmod +x "$INSTALL_DIR"/*.sh

# ── Service: restart on update, full setup on fresh install ──
if $IS_UPDATE; then
  section "Restarting service"
  systemctl restart daggerconnect-panel 2>/dev/null \
    && ok_msg "Service restarted" \
    || die "Service failed to restart — check: journalctl -u daggerconnect-panel"
else
  section "Installing systemd service"
  cat > /etc/systemd/system/daggerconnect-panel.service <<EOF
[Unit]
Description=DaggerConnect Control Panel
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_DIR}/start.sh
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable daggerconnect-panel 2>/dev/null
  systemctl restart daggerconnect-panel 2>/dev/null \
    && ok_msg "Service enabled and started" \
    || die "Service failed to start — check: journalctl -u daggerconnect-panel"

  # ── nginx setup ─────────────────────────────────────────────
  section "Setting up nginx"

  # ── Panel TLS cert ──────────────────────────────────────────
  section "Panel TLS certificate"
  mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"

  SERVER_IP_RAW=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
    || ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')

  if [[ "$SERVER_IP_RAW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    SERVER_IP="$SERVER_IP_RAW"
    ok_msg "Detected server IP: $SERVER_IP"
  else
    SERVER_IP="localhost"
    warn_msg "Could not detect public IP (got: '$SERVER_IP_RAW') — using 'localhost' for cert CN"
  fi

  if [[ -f "$CERT_DIR/panel.crt" && -f "$CERT_DIR/panel.key" ]]; then
    warn_msg "TLS cert already exists at $CERT_DIR — skipping generation"
    echo "  To regenerate: rm $CERT_DIR/panel.crt $CERT_DIR/panel.key && sudo $0"
  else
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$CERT_DIR/panel.key" \
      -out    "$CERT_DIR/panel.crt" \
      -days   365 \
      -subj   "/CN=$SERVER_IP/O=DaggerConnect Panel" \
      2>/dev/null && ok_msg "TLS cert → $CERT_DIR/panel.crt" \
                 || die "openssl failed"
    chmod 600 "$CERT_DIR/panel.key"
  fi

  # ── HTTP Basic Auth ─────────────────────────────────────────
  section "HTTP Basic Auth"
  echo ""
  echo -e "${YLW}Choose a username for the panel web login:${NC}"
  read -rp "  Username [admin]: " PANEL_USER
  PANEL_USER="${PANEL_USER:-admin}"

  while true; do
    echo -e "${YLW}Choose a password (input hidden):${NC}"
    read -rsp "  Password: " PANEL_PASS; echo ""
    read -rsp "  Confirm:  " PANEL_PASS2; echo ""

    if [[ "$PANEL_PASS" != "$PANEL_PASS2" ]]; then
      warn_msg "Passwords do not match — try again"
    elif [[ ${#PANEL_PASS} -lt 8 ]]; then
      warn_msg "Password must be at least 8 characters — try again"
    else
      break
    fi
  done

  if [[ -f "$HTPASSWD_FILE" ]]; then
    htpasswd -b "$HTPASSWD_FILE" "$PANEL_USER" "$PANEL_PASS" 2>/dev/null \
      && ok_msg "htpasswd updated for user '$PANEL_USER'" \
      || die "htpasswd failed"
  else
    htpasswd -cb "$HTPASSWD_FILE" "$PANEL_USER" "$PANEL_PASS" 2>/dev/null \
      && ok_msg "htpasswd created for user '$PANEL_USER'" \
      || die "htpasswd failed"
  fi
  chmod 600 "$HTPASSWD_FILE"
  chown www-data:www-data "$HTPASSWD_FILE" 2>/dev/null \
    && ok_msg "htpasswd ownership → www-data" \
    || warn_msg "chown www-data failed for $HTPASSWD_FILE (nginx may not read it)"

  # ── nginx config ────────────────────────────────────────────
  section "Writing nginx config"

  cat > "$NGINX_CONF" <<NGINX
# DaggerConnect Panel — nginx reverse proxy
# Auto-generated by daggerconnect-panel.sh

limit_req_zone \$binary_remote_addr zone=panel:10m rate=10r/s;

server {
    listen ${PANEL_PORT} ssl;
    server_name _;

    ssl_certificate     ${CERT_DIR}/panel.crt;
    ssl_certificate_key ${CERT_DIR}/panel.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header Content-Security-Policy "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:;";

    limit_req zone=panel burst=20 nodelay;
    limit_req_status 429;

    auth_basic "DaggerConnect Panel";
    auth_basic_user_file ${HTPASSWD_FILE};

    root ${INSTALL_DIR};
    index panel.html;

    location = / {
        try_files /panel.html =404;
    }

    location /panel {
        try_files /panel.html =404;
    }

    location /api/ {
        proxy_pass         http://127.0.0.1:${SOCAT_PORT};
        proxy_http_version 1.0;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
        proxy_read_timeout 35s;
        proxy_connect_timeout 5s;
        proxy_pass_request_headers on;
    }

    location / {
        return 404;
    }

    access_log /var/log/nginx/dagger-panel-access.log;
    error_log  /var/log/nginx/dagger-panel-error.log warn;
}

# Redirect HTTP → HTTPS on port 80
server {
    listen 80;
    server_name _;
    return 301 https://\$host:${PANEL_PORT}\$request_uri;
}
NGINX

  ok_msg "nginx config written to $NGINX_CONF"

  ln -sf "$NGINX_CONF" "$NGINX_LINK"
  rm -f /etc/nginx/sites-enabled/default 2>/dev/null

  # ── Test nginx config ───────────────────────────────────────
  section "Testing nginx config"
  NGINX_TEST=$(nginx -t 2>&1)
  if echo "$NGINX_TEST" | grep -q "test is successful"; then
    ok_msg "nginx config valid"
  else
    echo "$NGINX_TEST"
    die "nginx config test failed — see output above"
  fi

  # ── Start/reload nginx ──────────────────────────────────────
  section "Starting nginx"
  systemctl enable nginx 2>/dev/null
  if systemctl is-active --quiet nginx 2>/dev/null; then
    systemctl reload nginx && ok_msg "nginx reloaded (graceful)" || die "nginx reload failed"
  else
    systemctl start nginx && ok_msg "nginx started" || die "nginx failed to start"
  fi

  # ── Firewall ────────────────────────────────────────────────
  section "Firewall"
  if command -v ufw &>/dev/null; then
    ufw allow "$PANEL_PORT"/tcp comment "DaggerConnect Panel HTTPS" 2>/dev/null \
      && ok_msg "ufw: allowed port $PANEL_PORT" \
      || warn_msg "ufw rule failed — add manually: ufw allow $PANEL_PORT/tcp"
    ufw allow 80/tcp comment "DaggerConnect Panel HTTP redirect" 2>/dev/null || true
    ufw status | grep -q "Status: inactive" \
      && warn_msg "ufw is inactive — ports are open but ufw not enforced"
  else
    warn_msg "ufw not found — open ports $PANEL_PORT and 80 in your cloud provider's firewall"
  fi

  # ── Post-setup healthcheck ──────────────────────────────────
  section "Healthcheck"
  sleep 1
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    --max-time 5 "https://localhost:${PANEL_PORT}/" 2>/dev/null || echo "000")
  if [[ "$HTTP_CODE" == "401" ]]; then
    ok_msg "Panel responding (401 = auth prompt working ✓)"
  elif [[ "$HTTP_CODE" == "200" ]]; then
    ok_msg "Panel responding (200 — auth may not be enforced, check htpasswd)"
  else
    warn_msg "Panel not responding on :$PANEL_PORT (got HTTP $HTTP_CODE) — check: nginx -t && systemctl status nginx"
  fi
fi

# ── Done ──────────────────────────────────────────────────────
SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
  || ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')
[[ -z "$SERVER_IP" ]] && SERVER_IP="YOUR_VPS_IP"

echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
$IS_UPDATE \
  && echo -e "${GRN}  ✓ Update complete!${NC}" \
  || echo -e "${GRN}  ✓ Installation complete!${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YLW}Panel URL:${NC}  https://${SERVER_IP}:${PANEL_PORT}"
if ! $IS_UPDATE; then
  echo -e "  ${YLW}User:${NC}       $PANEL_USER"
  echo -e "  ${YLW}Token:${NC}      $(cat /etc/DaggerConnect/panel.token 2>/dev/null | tr -d '[:space:]' || echo "run: sudo ${INSTALL_DIR}/start.sh token")"
  echo ""
  echo -e "  ${YLW}Note:${NC} Your browser will warn about the self-signed cert."
  echo -e "        Click ${CYN}Advanced → Proceed${NC} to continue."
fi
echo ""
echo -e "  ${YLW}Useful commands:${NC}"
echo "    sudo ${INSTALL_DIR}/start.sh token"
echo "    sudo $0 change-password"
echo "    sudo $0 uninstall"
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"