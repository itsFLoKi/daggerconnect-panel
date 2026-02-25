#!/bin/bash
# ============================================================
# DaggerConnect Panel — Start Script
# Fixed: PID safety check, token file newline, log rotation,
#        port release wait, role validation on empty input,
#        added: status/logs subcommands, systemd unit hint.
# ============================================================

PORT=7070
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
API_SCRIPT="$SCRIPT_DIR/api.sh"
TOKEN_FILE="/etc/DaggerConnect/panel.token"
ROLE_FILE="/etc/DaggerConnect/panel.role"
PID_FILE="/tmp/daggerconnect-panel.pid"
LOG_FILE="/tmp/daggerconnect-panel.log"
LOG_MAX_BYTES=10485760  # 10 MB

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'

banner() {
echo -e "${CYN}"
echo "  ██████╗  █████╗  ██████╗  ██████╗ ███████╗██████╗ "
echo "  ██╔══██╗██╔══██╗██╔════╝ ██╔════╝ ██╔════╝██╔══██╗"
echo "  ██║  ██║███████║██║  ███╗██║  ███╗█████╗  ██████╔╝"
echo "  ██║  ██║██╔══██║██║   ██║██║   ██║██╔══╝  ██╔══██╗"
echo "  ██████╔╝██║  ██║╚██████╔╝╚██████╔╝███████╗██║  ██║"
echo "  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo -e "${NC}  Control Panel — socat backend v1.0.0"
echo ""
}

die()      { echo -e "${RED}✗ $1${NC}"; exit 1; }
ok_msg()   { echo -e "${GRN}✓ $1${NC}"; }
warn_msg() { echo -e "${YLW}⚠ $1${NC}"; }

# ── Log rotation ─────────────────────────────────────────────
rotate_log() {
  if [[ -f "$LOG_FILE" ]]; then
    local size
    size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    if [[ "$size" -gt "$LOG_MAX_BYTES" ]]; then
      mv "$LOG_FILE" "${LOG_FILE}.1"
      warn_msg "Log rotated (was >10 MB) → ${LOG_FILE}.1"
    fi
  fi
}

# ── Safe kill — verify PID belongs to socat before killing ───
safe_kill() {
  local pid="$1"
  if [[ -z "$pid" || "$pid" -le 1 ]]; then return 1; fi
  local comm
  comm=$(ps -p "$pid" -o comm= 2>/dev/null | tr -d '[:space:]')
  if [[ "$comm" == "socat" ]]; then
    kill "$pid" 2>/dev/null
    return $?
  else
    warn_msg "PID $pid is '$comm', not socat — skipping kill"
    return 1
  fi
}

# ── Subcommand: stop ─────────────────────────────────────────
if [[ "$1" == "stop" ]]; then
  if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if safe_kill "$PID"; then
      echo "Panel stopped (PID $PID)"
    else
      echo "Already stopped or PID mismatch"
    fi
    rm -f "$PID_FILE"
  else
    echo "Panel not running (no PID file)"
  fi
  exit 0
fi

# ── Subcommand: status ───────────────────────────────────────
if [[ "$1" == "status" ]]; then
  echo ""
  if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    comm=$(ps -p "$PID" -o comm= 2>/dev/null | tr -d '[:space:]')
    if [[ "$comm" == "socat" ]]; then
      echo -e "  ${GRN}Panel:${NC}  running (PID $PID)"
    else
      echo -e "  ${RED}Panel:${NC}  PID file exists but process '$comm' (PID $PID) is not socat"
    fi
  else
    echo -e "  ${RED}Panel:${NC}  not running"
  fi
  BOUND=$(ss -tlnp 2>/dev/null | grep ":$PORT " | head -1)
  if [[ -n "$BOUND" ]]; then
    echo -e "  ${GRN}socat:${NC}  bound on :$PORT"
  else
    echo -e "  ${RED}socat:${NC}  port $PORT not listening"
  fi
  ROLE=$(cat "$ROLE_FILE" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$ROLE" ]] && ROLE="not set"
  echo -e "  ${CYN}Role:${NC}   $ROLE"
  TOKEN_SET="(not set)"
  [[ -f "$TOKEN_FILE" ]] && TOKEN_SET="(set)"
  echo -e "  ${CYN}Token:${NC}  $TOKEN_SET"
  echo ""
  exit 0
fi

# ── Subcommand: token ────────────────────────────────────────
if [[ "$1" == "token" ]]; then
  if [[ -f "$TOKEN_FILE" ]]; then
    echo "Current token: $(cat "$TOKEN_FILE")"
  else
    echo "No token set. Run as root to generate one."
  fi
  exit 0
fi

# ── Subcommand: logs ─────────────────────────────────────────
if [[ "$1" == "logs" ]]; then
  if [[ -f "$LOG_FILE" ]]; then
    exec tail -f "$LOG_FILE"
  else
    echo "No log file yet: $LOG_FILE"
  fi
  exit 0
fi

# ── Subcommand: role ─────────────────────────────────────────
if [[ "$1" == "role" ]]; then
  if [[ "$2" == "server" || "$2" == "client" ]]; then
    mkdir -p /etc/DaggerConnect
    printf '%s\n' "$2" > "$ROLE_FILE"
    chmod 644 "$ROLE_FILE"
    echo "Node role set to: $2"
    echo "Restart the panel for the change to take effect."
  else
    CURRENT=$(cat "$ROLE_FILE" 2>/dev/null | tr -d '[:space:]' || echo "not set")
    echo "Current role: $CURRENT"
    echo "Usage: sudo $0 role [server|client]"
  fi
  exit 0
fi

banner

# ── Root check ───────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Must run as root. Use: sudo $0"

# ── Dependency check ─────────────────────────────────────────
echo "Checking dependencies..."
for cmd in socat openssl ss ip python3; do
  if command -v "$cmd" &>/dev/null; then
    ok_msg "$cmd"
  else
    warn_msg "$cmd not found"
    case "$cmd" in
      socat)   echo "   → apt install socat" ;;
      python3) echo "   → apt install python3 python3-yaml" ;;
      ss)      echo "   → apt install iproute2" ;;
    esac
    [[ "$cmd" == "socat" || "$cmd" == "python3" ]] && die "socat and python3 are required"
  fi
done

# Check python3-yaml (needed for reliable YAML parsing in api.sh)
if ! python3 -c "import yaml" 2>/dev/null; then
  warn_msg "python3-yaml not installed — portmaps and connections may not work"
  echo "   → apt install python3-yaml   (or: pip3 install pyyaml)"
fi
echo ""

# ── Generate or load auth token ──────────────────────────────
mkdir -p /etc/DaggerConnect
if [[ ! -f "$TOKEN_FILE" ]]; then
  echo "Generating auth token..."
  TOKEN=$(openssl rand -hex 32)
  # Store with newline for compatibility with cat/other tools
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  ok_msg "Token saved to $TOKEN_FILE"
else
  TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
  ok_msg "Loaded existing token from $TOKEN_FILE"
fi

# ── Detect or prompt for node role ───────────────────────────
NODE_ROLE=$(cat "$ROLE_FILE" 2>/dev/null | tr -d '[:space:]')
if [[ "$NODE_ROLE" != "server" && "$NODE_ROLE" != "client" ]]; then
  echo ""
  echo -e "  ${YLW}Is this the SERVER (Iran/relay) VPS or the CLIENT (foreign/exit) VPS?${NC}"
  select ROLE_CHOICE in "server — Iran/relay VPS (receives tunnel)" "client — Foreign/exit VPS (connects out)"; do
    case "$ROLE_CHOICE" in
      server*) NODE_ROLE="server"; break ;;
      client*) NODE_ROLE="client"; break ;;
    esac
  done
  # Guard against Ctrl+C or empty selection
  if [[ -z "$NODE_ROLE" ]]; then
    die "Role not selected — exiting. Run again and choose server or client."
  fi
  printf '%s\n' "$NODE_ROLE" > "$ROLE_FILE"
  chmod 644 "$ROLE_FILE"
  ok_msg "Role saved: $NODE_ROLE"
fi

echo ""
echo -e "  ${CYN}Node role:${NC} ${YLW}${NODE_ROLE^^}${NC}"
echo ""
echo -e "  ${YLW}Auth token (put this in the panel login):${NC}"
echo -e "  ${CYN}$TOKEN${NC}"
echo ""

# ── Stop any existing socat (safe) ───────────────────────────
if [[ -f "$PID_FILE" ]]; then
  OLD=$(cat "$PID_FILE")
  safe_kill "$OLD"
  sleep 0.5
  # Wait up to 2s for port to be released
  for i in 1 2 3 4; do
    ss -tlnp 2>/dev/null | grep -q ":$PORT " || break
    sleep 0.5
  done
fi

# ── Rotate log if too large ───────────────────────────────────
rotate_log

# ── Start socat bound to loopback only ───────────────────────
chmod +x "$API_SCRIPT"

socat \
  TCP-LISTEN:${PORT},bind=127.0.0.1,reuseaddr,fork \
  EXEC:"$API_SCRIPT" \
  >>"$LOG_FILE" 2>&1 &

SOCAT_PID=$!
printf '%s\n' "$SOCAT_PID" > "$PID_FILE"
sleep 0.5

if ! kill -0 "$SOCAT_PID" 2>/dev/null; then
  die "socat failed to start. Log: $LOG_FILE"
fi

ok_msg "socat listening on 127.0.0.1:$PORT (PID $SOCAT_PID)"
echo ""
echo -e "  ${CYN}Next step — set up nginx:${NC}"
echo -e "  sudo bash $SCRIPT_DIR/setup-nginx.sh"
echo ""
echo "  Logs:   tail -f $LOG_FILE   (or: sudo $0 logs)"
echo "  Status: sudo $0 status"
echo "  Stop:   sudo $0 stop"
echo "  Token:  sudo $0 token"
echo "  Role:   sudo $0 role [server|client]"
echo ""

# ── Systemd hint (no unit file provided yet) ─────────────────
if ! systemctl is-active --quiet daggerconnect-panel 2>/dev/null; then
  echo -e "  ${YLW}Tip:${NC} The panel will stop on reboot. To make it persistent:"
  cat <<UNIT

  Create /etc/systemd/system/daggerconnect-panel.service:

    [Unit]
    Description=DaggerConnect Control Panel
    After=network.target

    [Service]
    ExecStart=/bin/bash ${SCRIPT_DIR}/start.sh
    ExecStop=/bin/bash ${SCRIPT_DIR}/start.sh stop
    Restart=on-failure
    RestartSec=5
    User=root

    [Install]
    WantedBy=multi-user.target

  Then run:
    sudo systemctl daemon-reload
    sudo systemctl enable --now daggerconnect-panel
UNIT
fi
