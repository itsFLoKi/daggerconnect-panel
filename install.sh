#!/bin/bash
# ============================================================
# DaggerConnect Control Panel — Installer
# Clones the repo, installs dependencies, starts the panel,
# and sets up nginx.
# Usage: bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USER/daggerconnect-panel/main/install.sh)
# ============================================================

INSTALL_DIR="/opt/daggerconnect-panel"
REPO_URL="https://github.com/YOUR_USER/daggerconnect-panel"
PANEL_BRANCH="main"

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
echo -e "${NC}  Control Panel Installer v1.0.0"
echo ""

# ── Root check ───────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Must run as root: sudo bash install.sh"

# ── Check DaggerConnect config exists ────────────────────────
section "Checking DaggerConnect"
if [[ -f "/etc/DaggerConnect/server.yaml" ]]; then
  ok_msg "Found server.yaml — this node will run as SERVER"
elif [[ -f "/etc/DaggerConnect/client.yaml" ]]; then
  ok_msg "Found client.yaml — this node will run as CLIENT"
else
  die "Neither /etc/DaggerConnect/server.yaml nor client.yaml found.\nPlease install and configure DaggerConnect before running this installer."
fi

# ── Install dependencies ──────────────────────────────────────
section "Installing dependencies"
apt-get update -qq || warn_msg "apt update failed — continuing anyway"
apt-get install -y socat nginx apache2-utils python3 python3-yaml openssl git \
  || die "Failed to install dependencies"
ok_msg "Dependencies installed"

# ── Clone or update repo ──────────────────────────────────────
section "Installing panel files"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  echo "Existing installation found — pulling latest..."
  git -C "$INSTALL_DIR" pull --ff-only \
    && ok_msg "Updated to latest" \
    || warn_msg "git pull failed — continuing with existing files"
else
  git clone --depth 1 --branch "$PANEL_BRANCH" "$REPO_URL" "$INSTALL_DIR" \
    || die "git clone failed — check the repo URL in this script"
  ok_msg "Cloned to $INSTALL_DIR"
fi

chmod +x "$INSTALL_DIR"/*.sh

# ── Start socat backend ───────────────────────────────────────
section "Starting panel backend"
bash "$INSTALL_DIR/start.sh" \
  || die "start.sh failed — check output above"

# ── Set up nginx ──────────────────────────────────────────────
section "Setting up nginx"
bash "$INSTALL_DIR/setup-nginx.sh" \
  || die "setup-nginx.sh failed — check output above"

# ── Install systemd unit ──────────────────────────────────────
section "Installing systemd service"
cat > /etc/systemd/system/daggerconnect-panel.service <<EOF
[Unit]
Description=DaggerConnect Control Panel
After=network.target

[Service]
ExecStart=/bin/bash ${INSTALL_DIR}/start.sh
ExecStop=/bin/bash ${INSTALL_DIR}/start.sh stop
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable daggerconnect-panel 2>/dev/null \
  && ok_msg "systemd service enabled (auto-starts on reboot)"

# ── Done ──────────────────────────────────────────────────────
SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null \
  || ip route get 8.8.8.8 2>/dev/null | awk '/src/{print $7; exit}')
[[ -z "$SERVER_IP" ]] && SERVER_IP="YOUR_VPS_IP"

echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GRN}  ✓ Installation complete!${NC}"
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${YLW}Panel URL:${NC}  https://${SERVER_IP}:8443"
echo -e "  ${YLW}Token:${NC}      $(cat /etc/DaggerConnect/panel.token 2>/dev/null | tr -d '[:space:]' || echo 'run: sudo start.sh token')"
echo ""
echo -e "  ${YLW}Note:${NC} Your browser will warn about the self-signed cert."
echo -e "        Click ${CYN}Advanced → Proceed${NC} to continue."
echo ""
echo -e "  ${YLW}Useful commands:${NC}"
echo "    sudo ${INSTALL_DIR}/start.sh status"
echo "    sudo ${INSTALL_DIR}/start.sh token"
echo "    sudo ${INSTALL_DIR}/start.sh logs"
echo "    sudo ${INSTALL_DIR}/start.sh stop"
echo ""
echo -e "${CYN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
