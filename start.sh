#!/bin/bash
# ============================================================
# DaggerConnect Panel — launcher
# Starts:
#   1. socat API backend (port 7070)  ← handles all /api/ calls
#   2. Background metrics collector   ← runs every 5s, always,
#      regardless of whether the panel is open in a browser
#
# Both run in the same systemd unit (daggerconnect-panel.service)
# so no extra service file is needed.
# ============================================================

PANEL_DIR="/opt/daggerconnect-panel"
CONFIG_DIR="/etc/DaggerConnect"
API_SCRIPT="$PANEL_DIR/api.sh"
METRICS_DB="$CONFIG_DIR/metrics.db"
ROLE_FILE="$CONFIG_DIR/panel.role"
API_PORT=7070

# ── Ensure config dir exists ──────────────────────────────────
mkdir -p "$CONFIG_DIR"

# ── Init SQLite metrics DB (idempotent) ───────────────────────
python3 - <<'PY' 2>/dev/null
import sqlite3, os
db = '/etc/DaggerConnect/metrics.db'
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS metrics_raw (
  ts INTEGER PRIMARY KEY, cpu INTEGER, ram INTEGER, ram_mb INTEGER,
  rx INTEGER, tx INTEGER, conns INTEGER, srv_cpu REAL, srv_mem INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS metrics_hourly (
  hour_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS metrics_daily (
  day_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
conn.commit(); conn.close()
PY

# ── Background metrics collector ──────────────────────────────
# Runs as a background subshell within this process.
# Collects one sample every 5s and writes to SQLite + jsonl.
# Automatically stops when the panel service stops (same PID group).
_metrics_collector() {
  local INTERVAL=5

  # Parse server listener ports
  _get_server_ports() {
    python3 - <<'PY' 2>/dev/null
import yaml
try:
    with open('/etc/DaggerConnect/server.yaml') as f:
        data = yaml.safe_load(f) or {}
    for l in data.get('listeners', []):
        addr = l.get('addr', '')
        if ':' in addr:
            p = addr.rsplit(':', 1)[-1]
            if p.isdigit(): print(p)
except Exception: pass
PY
  }

  # Parse client remote ports
  _get_client_ports() {
    python3 - <<'PY' 2>/dev/null
import yaml
try:
    with open('/etc/DaggerConnect/client.yaml') as f:
        data = yaml.safe_load(f) or {}
    for p in data.get('paths', []):
        addr = p.get('addr', '')
        if ':' in addr:
            port = addr.rsplit(':', 1)[-1]
            if port.isdigit(): print(port)
except Exception: pass
PY
  }

  # CPU+RSS for a PID and all its children
  _proc_stats() {
    local pid="$1"
    [[ "$pid" -le 1 ]] && { echo "0 0"; return; }
    local pids=() queue=("$pid")
    while [[ ${#queue[@]} -gt 0 ]]; do
      local p="${queue[0]}"; queue=("${queue[@]:1}"); pids+=("$p")
      while IFS= read -r c; do [[ -n "$c" ]] && queue+=("$c"); done \
        < <(awk -v pp="$p" '$4==pp{print $1}' /proc/[0-9]*/stat 2>/dev/null)
    done
    local pl; pl=$(IFS=,; echo "${pids[*]}")
    ps -p "$pl" -o %cpu,rss --no-headers 2>/dev/null \
      | awk '{c+=$1;r+=$2} END{printf "%.1f %d",c,int(r/1024)}'
  }

  # Write one sample to SQLite — self-healing: creates tables if missing
  _write_sample() {
    python3 - "$@" <<'PY'
import sqlite3, sys, os
ts,cpu,ram,ram_mb,rx,tx,conns,srv_cpu,srv_mem = sys.argv[1:]
db = '/etc/DaggerConnect/metrics.db'
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db, timeout=10)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS metrics_raw (
  ts INTEGER PRIMARY KEY, cpu INTEGER, ram INTEGER, ram_mb INTEGER,
  rx INTEGER, tx INTEGER, conns INTEGER, srv_cpu REAL, srv_mem INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS metrics_hourly (
  hour_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
c.execute('''CREATE TABLE IF NOT EXISTS metrics_daily (
  day_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
try:
    c.execute('INSERT OR REPLACE INTO metrics_raw VALUES (?,?,?,?,?,?,?,?,?)',
      (int(ts),int(cpu),int(ram),int(ram_mb),int(rx),int(tx),int(conns),float(srv_cpu),int(srv_mem)))
    c.execute('DELETE FROM metrics_raw WHERE ts < ?', (int(ts)-90000000,))
    h = (int(ts)//3600000)*3600000
    c.execute('''INSERT OR REPLACE INTO metrics_hourly
      SELECT ?,AVG(cpu),MAX(cpu),AVG(ram),MAX(ram),
             MIN(rx),MAX(rx),MIN(tx),MAX(tx),AVG(conns),MAX(conns),COUNT(*)
      FROM metrics_raw WHERE ts>=? AND ts<?+3600000''', (h,h,h))
    c.execute('DELETE FROM metrics_hourly WHERE hour_ts<?', (int(ts)-2678400000,))
    d = (int(ts)//86400000)*86400000
    c.execute('''INSERT OR REPLACE INTO metrics_daily
      SELECT ?,AVG(cpu_avg),MAX(cpu_max),AVG(ram_avg),MAX(ram_max),
             MIN(rx_min),MAX(rx_max),MIN(tx_min),MAX(tx_max),
             AVG(conns_avg),MAX(conns_max),SUM(sample_count)
      FROM metrics_hourly WHERE hour_ts>=? AND hour_ts<?+86400000''', (d,d,d))
    c.execute('DELETE FROM metrics_daily WHERE day_ts<?', (int(ts)-7948800000,))
    conn.commit()
except Exception:
    conn.rollback()
finally:
    conn.close()
PY
  }

  echo "[metrics] Collector started (interval=${INTERVAL}s)"

  while true; do
    T0=$(date +%s%3N)

    # CPU — 0.4s sample (leaves ~4.6s sleep at 5s interval)
    read -r _ u1 n1 s1 i1 _ _ _ _ _ < /proc/stat
    sleep 0.4
    read -r _ u2 n2 s2 i2 _ _ _ _ _ < /proc/stat
    DT=$(( (u2+n2+s2+i2)-(u1+n1+s1+i1) ))
    DI=$(( i2-i1 ))
    CPU=0; [[ $DT -gt 0 ]] && CPU=$(( 100*(DT-DI)/DT ))

    # RAM
    read -r _ TOTAL USED _ < <(free -m | awk '/^Mem:/{print $1,$2,$3}')
    RAM=0; [[ ${TOTAL:-0} -gt 0 ]] && RAM=$(( 100*${USED:-0}/TOTAL ))

    # Network counters
    IFACE=$(ip route get 8.8.8.8 2>/dev/null \
      | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    RX=0; TX=0
    [[ -n "$IFACE" && -f "/sys/class/net/$IFACE/statistics/rx_bytes" ]] && {
      RX=$(< "/sys/class/net/$IFACE/statistics/rx_bytes")
      TX=$(< "/sys/class/net/$IFACE/statistics/tx_bytes")
    }

    # Server process stats
    SRV_PID=$(systemctl show -p MainPID --value DaggerConnect-server 2>/dev/null | tr -d '[:space:]')
    [[ -z "$SRV_PID" || "$SRV_PID" == "0" ]] && SRV_PID=0
    SRV_CPU=0; SRV_MEM=0
    [[ "$SRV_PID" -gt 1 ]] && read -r SRV_CPU SRV_MEM < <(_proc_stats "$SRV_PID")

    # Active connections (role-aware)
    NODE_ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
    CONNS=0
    if [[ "$NODE_ROLE" == "client" ]]; then
      while IFS= read -r PORT; do
        [[ -z "$PORT" ]] && continue
        C=$(ss -tn state established "dport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
        CONNS=$(( CONNS+C ))
      done < <(_get_client_ports)
    else
      while IFS= read -r PORT; do
        [[ -z "$PORT" ]] && continue
        C=$(ss -tn state established "sport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
        CONNS=$(( CONNS+C ))
      done < <(_get_server_ports)
    fi

    TS=$(date +%s%3N)

    # Write to SQLite
    _write_sample "$TS" "$CPU" "$RAM" "${USED:-0}" "$RX" "$TX" "$CONNS" "${SRV_CPU:-0}" "${SRV_MEM:-0}"

    # Sleep for the remainder of the interval
    T1=$(date +%s%3N)
    ELAPSED=$(( T1-T0 ))
    SLEEP_MS=$(( INTERVAL*1000 - ELAPSED ))
    [[ $SLEEP_MS -gt 100 ]] && sleep "$(echo "scale=3; $SLEEP_MS/1000" | bc)"
  done
}

# Launch metrics collector in background (dies with this process automatically)
_metrics_collector &
METRICS_PID=$!
echo "[panel] Metrics collector PID: $METRICS_PID"

# ── socat API backend ─────────────────────────────────────────
echo "[panel] Starting socat API on port $API_PORT"
exec socat \
  TCP-LISTEN:${API_PORT},reuseaddr,fork \
  EXEC:"bash ${API_SCRIPT}"