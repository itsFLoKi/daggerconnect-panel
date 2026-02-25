#!/bin/bash
# ============================================================
# DaggerConnect Panel — nginx HTTPS + Auth Setup
# Fixed: sed idempotency, SERVER_IP validation, htpasswd
#        idempotency, TLS cert skip if exists, HTTP redirect
#        port changed to 80, reload vs restart, nginx -t scope,
#        post-setup healthcheck added.
# ============================================================

PANEL_PORT=8443
SOCAT_PORT=7070
PANEL_DIR="/opt/daggerconnect-panel"
NGINX_CONF="/etc/nginx/sites-available/daggerconnect-panel"
NGINX_LINK="/etc/nginx/sites-enabled/daggerconnect-panel"
HTPASSWD_FILE="/etc/nginx/.dagger-htpasswd"
CERT_DIR="/etc/DaggerConnect/panel-tls"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

die()      { echo -e "${RED}✗ $1${NC}"; exit 1; }
ok_msg()   { echo -e "${GRN}✓ $1${NC}"; }
warn_msg() { echo -e "${YLW}⚠ $1${NC}"; }
section()  { echo ""; echo -e "${CYN}── $1 ──${NC}"; }

[[ $EUID -ne 0 ]] && die "Must run as root: sudo $0"

# ── Subcommand: change-password ───────────────────────────────
if [[ "$1" == "change-password" ]]; then
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
  echo -e "${YLW}New password (hidden):${NC}"
  read -rsp "  Password: " P1; echo ""
  read -rsp "  Confirm:  " P2; echo ""
  [[ "$P1" != "$P2" ]] && die "Passwords do not match"
  [[ ${#P1} -lt 8 ]] && die "Password must be at least 8 characters"
  htpasswd -b "$HTPASSWD_FILE" "$CHPW_USER" "$P1" 2>/dev/null \
    && ok_msg "Password updated for '$CHPW_USER'" \
    || die "htpasswd update failed"
  systemctl reload nginx 2>/dev/null && ok_msg "nginx reloaded"
  exit 0
fi

# ── Install nginx ─────────────────────────────────────────────
section "Installing nginx"
if command -v nginx &>/dev/null; then
  ok_msg "nginx already installed"
else
  apt-get update -qq && apt-get install -y nginx apache2-utils || die "apt install failed"
  ok_msg "nginx installed"
fi

if ! command -v htpasswd &>/dev/null; then
  apt-get install -y apache2-utils -qq || die "Failed to install apache2-utils"
  ok_msg "apache2-utils installed"
fi

# ── Panel TLS cert ────────────────────────────────────────────
section "Panel TLS certificate"
mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"

# Validate SERVER_IP — must be a real IPv4 address
SERVER_IP_RAW=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
  || ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')

# Validate: must look like an IPv4 address
if [[ "$SERVER_IP_RAW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  SERVER_IP="$SERVER_IP_RAW"
  ok_msg "Detected server IP: $SERVER_IP"
else
  SERVER_IP="localhost"
  warn_msg "Could not detect public IP (got: '$SERVER_IP_RAW') — using 'localhost' for cert CN"
fi

# Only generate cert if it doesn't already exist (idempotent)
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

# ── htpasswd (HTTP Basic Auth) ────────────────────────────────
section "HTTP Basic Auth"
echo ""
echo -e "${YLW}Choose a username for the panel web login:${NC}"
read -rp "  Username [admin]: " PANEL_USER
PANEL_USER="${PANEL_USER:-admin}"

echo -e "${YLW}Choose a password (input hidden):${NC}"
read -rsp "  Password: " PANEL_PASS; echo ""
read -rsp "  Confirm:  " PANEL_PASS2; echo ""

[[ "$PANEL_PASS" != "$PANEL_PASS2" ]] && die "Passwords do not match"
[[ ${#PANEL_PASS} -lt 8 ]] && die "Password must be at least 8 characters"

# Idempotent: use -b (no -c) if file already exists to avoid wiping other users
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

# ── nginx config ──────────────────────────────────────────────
section "Writing nginx config"

cat > "$NGINX_CONF" <<NGINX
# DaggerConnect Panel — nginx reverse proxy
# Auto-generated by setup-nginx.sh

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

    # Serve panel.html
    root ${PANEL_DIR};
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

# ── Enable site ───────────────────────────────────────────────
ln -sf "$NGINX_CONF" "$NGINX_LINK"
rm -f /etc/nginx/sites-enabled/default 2>/dev/null

# ── Test nginx config (whole config) ─────────────────────────
section "Testing nginx config"
NGINX_TEST=$(nginx -t 2>&1)
if echo "$NGINX_TEST" | grep -q "test is successful"; then
  ok_msg "nginx config valid"
else
  echo "$NGINX_TEST"
  # Check if it's the DaggerConnect config or a pre-existing broken config
  if nginx -t -c "$NGINX_CONF" 2>&1 | grep -q "test is successful" 2>/dev/null; then
    warn_msg "DaggerConnect config is valid, but another nginx config on this system has errors."
    warn_msg "Check /etc/nginx/conf.d/ and other sites-enabled entries."
  fi
  die "nginx config test failed — see output above"
fi

# ── Start/reload nginx ────────────────────────────────────────
section "Starting nginx"
systemctl enable nginx 2>/dev/null
if systemctl is-active --quiet nginx 2>/dev/null; then
  # nginx already running — use reload (graceful, no connection drops)
  systemctl reload nginx && ok_msg "nginx reloaded (graceful)" || die "nginx reload failed"
else
  systemctl start nginx && ok_msg "nginx started" || die "nginx failed to start"
fi

# ── Open firewall ─────────────────────────────────────────────
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

# ── Post-setup healthcheck ────────────────────────────────────
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

# ── Summary ───────────────────────────────────────────────────
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GRN}  ✓ DaggerConnect Panel is ready!${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YLW}URL:${NC}      https://${SERVER_IP}:${PANEL_PORT}"
echo -e "  ${YLW}User:${NC}     $PANEL_USER"
echo -e "  ${YLW}Password:${NC} (what you just set)"
echo -e "  ${YLW}Token:${NC}    $(cat /etc/DaggerConnect/panel.token 2>/dev/null | tr -d '[:space:]' || echo 'run: sudo start.sh token')"
echo ""
echo -e "  ${YLW}Note:${NC} Browser will warn about self-signed cert — click Advanced → Proceed."
echo -e "  For a real cert: ${CYN}certbot --nginx -d yourdomain.com${NC}"
echo ""
echo -e "  ${YLW}Change password:${NC}  sudo $0 change-password"
echo ""
echo -e "  ${YLW}Logs:${NC}"
echo "    nginx:  tail -f /var/log/nginx/dagger-panel-access.log"
echo "    socat:  tail -f /tmp/daggerconnect-panel.log"
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
