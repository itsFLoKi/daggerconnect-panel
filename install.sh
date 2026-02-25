#!/bin/bash
# ============================================================
# DaggerConnect Control Panel — Installer / Updater
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main/install.sh)
# ============================================================

INSTALL_DIR="/opt/daggerconnect-panel"
RAW_BASE="https://raw.githubusercontent.com/itsFLoKi/daggerconnect-panel/main"
FILES=(panel.html api.sh start.sh setup-nginx.sh)

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

die()      { echo -e "${RED}✗ $1${NC}"; exit 1; }
ok_msg()   { echo -e "${GRN}✓ $1${NC}"; }
warn_msg() { echo -e "${YLW}⚠ $1${NC}"; }
section()  { echo ""; echo -e "${CYN}── $1 ──${NC}"; }

echo -e "${CYN}"
echo "  ██████╗  █████╗  ██████╗  ██████╗ ███████╗██████╗ "
echo "  ██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗"
echo "  ██║  ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝"
echo "  ██║  ██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗"
echo "  ██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo -e "${NC}"

# ── Root check ───────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Must run as root: sudo bash install.sh"

# ── Detect: fresh install or update ──────────────────────────
IS_UPDATE=false
if [[ -f "$INSTALL_DIR/start.sh" ]] && \
   systemctl is-enabled --quiet daggerconnect-panel 2>/dev/null; then
  IS_UPDATE=true
fi

if $IS_UPDATE; then
  echo -e "  Control Panel ${YLW}Updater${NC} v1.0.0"
else
  echo -e "  Control Panel ${GRN}Installer${NC} v1.0.0"
fi
echo ""

# ── Check DaggerConnect config exists ────────────────────────
section "Checking DaggerConnect"
if [[ -f "/etc/DaggerConnect/server.yaml" ]]; then
  ok_msg "Found server.yaml — this node will run as SERVER"
elif [[ -f "/etc/DaggerConnect/client.yaml" ]]; then
  ok_msg "Found client.yaml — this node will run as CLIENT"
else
  die "Neither /etc/DaggerConnect/server.yaml nor client.yaml found.\nPlease install and configure DaggerConnect before running this installer."
fi

# ── Dependencies: full install on fresh, check-only on update ─
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

# ── Download panel files ──────────────────────────────────────
$IS_UPDATE && section "Updating panel files" || section "Downloading panel files"

mkdir -p "$INSTALL_DIR"
for FILE in "${FILES[@]}"; do
  curl -fsSL "${RAW_BASE}/${FILE}" -o "${INSTALL_DIR}/${FILE}" \
    && ok_msg "${FILE}" \
    || die "Failed to download ${FILE} — check your internet connection"
done
chmod +x "$INSTALL_DIR"/*.sh

# ── Service: restart on update, full setup on fresh install ───
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

  section "Setting up nginx"
  bash "$INSTALL_DIR/setup-nginx.sh" \
    || die "setup-nginx.sh failed — check output above"
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
echo -e "  ${YLW}Panel URL:${NC}  https://${SERVER_IP}:8443"
if ! $IS_UPDATE; then
  echo -e "  ${YLW}Token:${NC}      $(cat /etc/DaggerConnect/panel.token 2>/dev/null | tr -d '[:space:]' || echo "run: sudo ${INSTALL_DIR}/start.sh token")"
  echo ""
  echo -e "  ${YLW}Note:${NC} Your browser will warn about the self-signed cert."
  echo -e "        Click ${CYN}Advanced → Proceed${NC} to continue."
fi
echo ""
echo -e "  ${YLW}Useful commands:${NC}"
echo "    sudo ${INSTALL_DIR}/start.sh status"
echo "    sudo ${INSTALL_DIR}/start.sh token"
echo "    sudo ${INSTALL_DIR}/start.sh logs"
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"