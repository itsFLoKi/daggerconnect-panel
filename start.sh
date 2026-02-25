#!/bin/bash
# ============================================================
# DaggerConnect Panel — Start Script
# Managed by systemd. Run manually only to view the auth token.
# Usage: sudo bash start.sh token
# ============================================================

PORT=7070
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
API_SCRIPT="$SCRIPT_DIR/api.sh"
TOKEN_FILE="/etc/DaggerConnect/panel.token"

RED='\033[0;31m'; GRN='\033[0;32m'; CYN='\033[0;36m'; NC='\033[0m'

die()    { echo -e "${RED}✗ $1${NC}"; exit 1; }
ok_msg() { echo -e "${GRN}✓ $1${NC}"; }

# ── Subcommand: token ────────────────────────────────────────
if [[ "$1" == "token" ]]; then
  if [[ -f "$TOKEN_FILE" ]]; then
    echo "Current token: $(tr -d '[:space:]' < "$TOKEN_FILE")"
  else
    echo "No token set. Run as root to generate one."
  fi
  exit 0
fi

# ── Root check ───────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Must run as root. Use: sudo $0"

# ── Generate or load auth token ──────────────────────────────
mkdir -p /etc/DaggerConnect
if [[ ! -f "$TOKEN_FILE" ]]; then
  TOKEN=$(openssl rand -hex 32)
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  ok_msg "Token saved to $TOKEN_FILE"
else
  TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
  ok_msg "Loaded existing token from $TOKEN_FILE"
fi

# ── Detect node role ─────────────────────────────────────────
if [[ -f "/etc/DaggerConnect/server.yaml" ]]; then
  NODE_ROLE="server"
elif [[ -f "/etc/DaggerConnect/client.yaml" ]]; then
  NODE_ROLE="client"
else
  die "Could not detect role — neither server.yaml nor client.yaml found."
fi

printf '%s\n' "$NODE_ROLE" > /etc/DaggerConnect/panel.role
chmod 644 /etc/DaggerConnect/panel.role

chmod +x "$API_SCRIPT"

# ── Start socat (foreground for systemd, background otherwise) ─
if [[ -n "$INVOCATION_ID" ]]; then
  exec socat \
    TCP-LISTEN:${PORT},bind=127.0.0.1,reuseaddr,fork \
    EXEC:"$API_SCRIPT"
fi

socat \
  TCP-LISTEN:${PORT},bind=127.0.0.1,reuseaddr,fork \
  EXEC:"$API_SCRIPT" &

ok_msg "socat listening on 127.0.0.1:$PORT (PID $!)"