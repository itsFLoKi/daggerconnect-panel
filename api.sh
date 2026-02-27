#!/bin/bash
# ============================================================
# DaggerConnect Panel — API Handler (socat backend)
# Fixed: connections (role-aware, multi-port, real states),
#        network speed accuracy, YAML parsing via python3,
#        timing-safe auth, config backup rotation, journalctl
#        timeout, openssl CN injection, iptables persist warn,
#        PSK hex encoding, validate endpoint added.
# Updated: removed heatmap/config-compare/canary endpoints,
#          added backup_content preview, scheduled_restarts
#          list+cancel, quota alarm field, custom MTU probe
#          size, improved health checks, uptime_s for client,
#          config/read alias, quota/clear_alarm endpoint.
# ============================================================

CONFIG_DIR="/etc/DaggerConnect"
SERVER_YAML="$CONFIG_DIR/server.yaml"
CLIENT_YAML="$CONFIG_DIR/client.yaml"
SERVER_SVC="DaggerConnect-server"
CLIENT_SVC="DaggerConnect-client"
TOKEN_FILE="/etc/DaggerConnect/panel.token"
ROLE_FILE="/etc/DaggerConnect/panel.role"
LOG_LINES=120
MAX_BACKUPS=5
METRICS_DB="/etc/DaggerConnect/metrics.db"
UPTIME_DB="/etc/DaggerConnect/uptime.db"
AUDIT_DB="/etc/DaggerConnect/audit.db"
QUOTA_DB="/etc/DaggerConnect/quota.db"
SCHEDULE_DB="/etc/DaggerConnect/schedule.db"
GEOIP_DB="/etc/DaggerConnect/GeoLite2-City.mmdb"
ASN_DB="/etc/DaggerConnect/GeoLite2-ASN.mmdb"

# ── Auth token ───────────────────────────────────────────────
EXPECTED_TOKEN=""
if [[ -f "$TOKEN_FILE" ]]; then
  EXPECTED_TOKEN=$(tr -d '[:space:]' < "$TOKEN_FILE")
fi

# ── Helpers ─────────────────────────────────────────────────

json_header() {
  printf "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Auth-Token\r\n\r\n"
}

ok()       { json_header; printf '{"ok":true,"msg":"%s"}\n'  "$1"; }
fail()     { json_header; printf '{"ok":false,"msg":"%s"}\n' "$1"; }
err_auth() {
  printf "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nWWW-Authenticate: Bearer realm=\"DaggerConnect\"\r\n\r\n"
  printf '{"ok":false,"msg":"Unauthorized"}\n'
}
err_404() {
  printf "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
  printf '{"ok":false,"msg":"Unknown route: %s"}\n' "$1"
}

svc_state() { systemctl is-active "$1" 2>/dev/null; }

# Escape a string for embedding in a JSON value (handles newlines too)
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/}"
  s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

# Escape a multi-line file body into a JSON string
escape_multiline() {
  local result=""
  while IFS= read -r line; do
    line="${line//\\/\\\\}"
    line="${line//\"/\\\"}"
    line="${line//$'\t'/\\t}"
    result+="${line}\\n"
  done
  printf '%s' "${result%\\n}"
}

# Timing-safe token comparison via python3 hmac.compare_digest
token_match() {
  python3 -c "
import hmac, sys
try:
    sys.exit(0 if hmac.compare_digest('$1', '$2') else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null
}

# Rotate old config backups — keep only last MAX_BACKUPS
rotate_backups() {
  ls -t "${1}.bak."* 2>/dev/null | tail -n +"$((MAX_BACKUPS + 1))" | xargs rm -f 2>/dev/null
}

# Sum CPU+RSS for a PID and all its descendants
_proc_tree_stats() {
  local root_pid="$1"
  [[ "$root_pid" -le 1 ]] && { echo "0 0"; return; }
  # Get all PIDs in the process tree (root + children recursively)
  local all_pids=()
  local queue=("$root_pid")
  while [[ ${#queue[@]} -gt 0 ]]; do
    local pid="${queue[0]}"; queue=("${queue[@]:1}")
    all_pids+=("$pid")
    # Find direct children
    while IFS= read -r child; do
      [[ -n "$child" ]] && queue+=("$child")
    done < <(awk -v ppid="$pid" '$4==ppid{print $1}' /proc/[0-9]*/stat 2>/dev/null)
  done
  # Sum CPU% and RSS (kB→MB) across all pids
  local pid_list; pid_list=$(IFS=,; echo "${all_pids[*]}")
  ps -p "$pid_list" -o %cpu,rss --no-headers 2>/dev/null | awk '{cpu+=$1; rss+=$2} END{printf "%.1f %d", cpu, int(rss/1024)}'
}


# Parse all listener ports from server.yaml via python3
get_server_ports() {
  python3 - <<'PY' 2>/dev/null
import yaml
try:
    data = yaml.safe_load(open('/etc/DaggerConnect/server.yaml')) or {}
    seen = set()
    for listener in data.get('listeners', []):
        for m in listener.get('maps', []):
            bind = m.get('bind', '')
            if ':' in bind:
                p = bind.rsplit(':', 1)[-1]
                if p.isdigit() and p not in seen:
                    seen.add(p); print(p)
    if not seen:
        for l in data.get('listeners', []):
            addr = l.get('addr', '')
            if ':' in addr:
                p = addr.rsplit(':', 1)[-1]
                if p.isdigit() and p not in seen:
                    seen.add(p); print(p)
except Exception:
    pass
PY
}

# Parse all remote ports from client.yaml paths[].addr via python3
get_client_ports() {
  python3 - <<'PY' 2>/dev/null
import yaml
try:
    with open('/etc/DaggerConnect/client.yaml') as f:
        data = yaml.safe_load(f) or {}
    for p in data.get('paths', []):
        addr = p.get('addr', '')
        if ':' in addr:
            port = addr.rsplit(':', 1)[-1]
            if port.isdigit():
                print(port)
except Exception:
    pass
PY
}

# Parse portmaps from server.yaml via python3
get_portmaps_json() {
  python3 - <<'PY' 2>/dev/null
import yaml, json
try:
    with open('/etc/DaggerConnect/server.yaml') as f:
        data = yaml.safe_load(f) or {}
    entries = []
    for listener in data.get('listeners', []):
        addr      = listener.get('addr', '')
        transport = listener.get('transport', '')
        for m in listener.get('maps', []):
            entries.append({
                'type':      m.get('type', ''),
                'bind':      m.get('bind', ''),
                'target':    m.get('target', ''),
                'transport': transport,
                'listener':  addr,
            })
    print(json.dumps(entries))
except Exception:
    print('[]')
PY
}

# ── SQLite metrics helpers ────────────────────────────────────

# Init metrics DB (30-day rolling with hourly aggregates)
init_metrics_db() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, os
db_path = '/etc/DaggerConnect/metrics.db'
os.makedirs(os.path.dirname(db_path), exist_ok=True)
conn = sqlite3.connect(db_path)
c = conn.cursor()
# Raw points: keep 24h of 5s samples
c.execute('''CREATE TABLE IF NOT EXISTS metrics_raw (
  ts INTEGER PRIMARY KEY,
  cpu INTEGER, ram INTEGER, ram_mb INTEGER,
  rx INTEGER, tx INTEGER, conns INTEGER,
  srv_cpu REAL, srv_mem INTEGER
)''')
# Hourly aggregates: keep 30 days
c.execute('''CREATE TABLE IF NOT EXISTS metrics_hourly (
  hour_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL,
  ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER,
  tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER,
  sample_count INTEGER
)''')
# Daily aggregates: keep 90 days
c.execute('''CREATE TABLE IF NOT EXISTS metrics_daily (
  day_ts INTEGER PRIMARY KEY,
  cpu_avg REAL, cpu_max REAL,
  ram_avg REAL, ram_max REAL,
  rx_min INTEGER, rx_max INTEGER,
  tx_min INTEGER, tx_max INTEGER,
  conns_avg REAL, conns_max INTEGER,
  sample_count INTEGER
)''')
conn.commit()
conn.close()
PY
}

# Write one metrics point to SQLite and trigger aggregation
write_metrics_db() {
  local ts="$1" cpu="$2" ram="$3" ram_mb="$4" rx="$5" tx="$6" conns="$7" srv_cpu="$8" srv_mem="$9"
  python3 - "$ts" "$cpu" "$ram" "$ram_mb" "$rx" "$tx" "$conns" "$srv_cpu" "$srv_mem" <<'PY' 2>/dev/null
import sqlite3, sys, time, os
ts, cpu, ram, ram_mb, rx, tx, conns, srv_cpu, srv_mem = sys.argv[1:]
db_path = '/etc/DaggerConnect/metrics.db'
# Auto-create DB and tables if missing (handles first run / missing init)
os.makedirs(os.path.dirname(db_path), exist_ok=True)
is_new = not os.path.exists(db_path)
conn = sqlite3.connect(db_path, timeout=5)
if is_new:
    c2 = conn.cursor()
    c2.execute('''CREATE TABLE IF NOT EXISTS metrics_raw (ts INTEGER PRIMARY KEY, cpu INTEGER, ram INTEGER, ram_mb INTEGER, rx INTEGER, tx INTEGER, conns INTEGER, srv_cpu REAL, srv_mem INTEGER)''')
    c2.execute('''CREATE TABLE IF NOT EXISTS metrics_hourly (hour_ts INTEGER PRIMARY KEY, cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL, rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER, conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
    c2.execute('''CREATE TABLE IF NOT EXISTS metrics_daily (day_ts INTEGER PRIMARY KEY, cpu_avg REAL, cpu_max REAL, ram_avg REAL, ram_max REAL, rx_min INTEGER, rx_max INTEGER, tx_min INTEGER, tx_max INTEGER, conns_avg REAL, conns_max INTEGER, sample_count INTEGER)''')
    conn.commit()
c = conn.cursor()
try:
    c.execute('''INSERT OR REPLACE INTO metrics_raw 
      (ts, cpu, ram, ram_mb, rx, tx, conns, srv_cpu, srv_mem)
      VALUES (?,?,?,?,?,?,?,?,?)''',
      (int(ts), int(cpu), int(ram), int(ram_mb), int(rx), int(tx), int(conns), float(srv_cpu), int(srv_mem)))
    
    # Prune raw > 25h to keep disk small
    cutoff_raw = int(ts) - 90000000  # 25h in ms
    c.execute('DELETE FROM metrics_raw WHERE ts < ?', (cutoff_raw,))
    
    # Aggregate to hourly (for current hour)
    hour_ts = (int(ts) // 3600000) * 3600000
    c.execute('''INSERT OR REPLACE INTO metrics_hourly
      (hour_ts, cpu_avg, cpu_max, ram_avg, ram_max,
       rx_min, rx_max, tx_min, tx_max, conns_avg, conns_max, sample_count)
      SELECT
        ? as hour_ts,
        AVG(cpu), MAX(cpu), AVG(ram), MAX(ram),
        MIN(rx), MAX(rx), MIN(tx), MAX(tx),
        AVG(conns), MAX(conns), COUNT(*)
      FROM metrics_raw WHERE ts >= ? AND ts < ? + 3600000''',
      (hour_ts, hour_ts, hour_ts))
    
    # Prune hourly > 31 days
    cutoff_hourly = int(ts) - 2678400000  # 31 days in ms
    c.execute('DELETE FROM metrics_hourly WHERE hour_ts < ?', (cutoff_hourly,))
    
    # Aggregate to daily (for today)
    day_ts = (int(ts) // 86400000) * 86400000
    c.execute('''INSERT OR REPLACE INTO metrics_daily
      (day_ts, cpu_avg, cpu_max, ram_avg, ram_max,
       rx_min, rx_max, tx_min, tx_max, conns_avg, conns_max, sample_count)
      SELECT
        ? as day_ts,
        AVG(cpu_avg), MAX(cpu_max), AVG(ram_avg), MAX(ram_max),
        MIN(rx_min), MAX(rx_max), MIN(tx_min), MAX(tx_max),
        AVG(conns_avg), MAX(conns_max), SUM(sample_count)
      FROM metrics_hourly WHERE hour_ts >= ? AND hour_ts < ? + 86400000''',
      (day_ts, day_ts, day_ts))
    
    # Prune daily > 92 days
    cutoff_daily = int(ts) - 7948800000  # 92 days in ms
    c.execute('DELETE FROM metrics_daily WHERE day_ts < ?', (cutoff_daily,))
    
    conn.commit()
except Exception as e:
    conn.rollback()
finally:
    conn.close()
PY
}

# Init audit log DB
init_audit_db() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, os
db = '/etc/DaggerConnect/audit.db'
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail TEXT,
  user TEXT DEFAULT 'panel'
)''')
conn.commit(); conn.close()
PY
}

record_audit() {
  local action="$1" target="${2:-}" detail="${3:-}"
  python3 - "$action" "$target" "$detail" <<'PY' 2>/dev/null
import sqlite3, sys, time, os
action, target, detail = sys.argv[1], sys.argv[2], sys.argv[3]
db = '/etc/DaggerConnect/audit.db'
if not os.path.exists(db): sys.exit(0)
ts = int(time.time() * 1000)
conn = sqlite3.connect(db, timeout=5)
c = conn.cursor()
try:
    c.execute('INSERT INTO audit_log (ts, action, target, detail) VALUES (?,?,?,?)', (ts, action, target, detail))
    c.execute('DELETE FROM audit_log WHERE ts < ?', (ts - 7776000000,))
    conn.commit()
except Exception: conn.rollback()
finally: conn.close()
PY
}

# Init quota DB
init_quota_db() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, os
db = '/etc/DaggerConnect/quota.db'
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS quota_config (
  key TEXT PRIMARY KEY,
  value TEXT
)''')
c.execute('''CREATE TABLE IF NOT EXISTS quota_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER,
  event TEXT,
  detail TEXT
)''')
conn.commit(); conn.close()
PY
}

# Init schedule DB — tracks pending scheduled restarts
init_schedule_db() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, os
db = '/etc/DaggerConnect/schedule.db'
os.makedirs(os.path.dirname(db), exist_ok=True)
conn = sqlite3.connect(db)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS scheduled_restarts (
  id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  fire_at INTEGER NOT NULL,
  delay_seconds INTEGER NOT NULL,
  reason TEXT,
  created_ts INTEGER,
  status TEXT DEFAULT 'pending'
)''')
conn.commit(); conn.close()
PY
}

# Resolve IP via GeoIP mmdb
resolve_geoip() {
  local ip="$1"
  python3 - "$ip" <<'PY' 2>/dev/null
import sys, json, os
ip = sys.argv[1]
city_db = '/etc/DaggerConnect/GeoLite2-City.mmdb'
asn_db  = '/etc/DaggerConnect/GeoLite2-ASN.mmdb'
result = {'ip': ip, 'country': 'Unknown', 'city': '', 'asn': '', 'org': ''}
try:
    import geoip2.database
    if os.path.exists(city_db):
        with geoip2.database.Reader(city_db) as r:
            resp = r.city(ip)
            result['country'] = resp.country.name or 'Unknown'
            result['country_iso'] = resp.country.iso_code or ''
            result['city'] = resp.city.name or ''
    if os.path.exists(asn_db):
        with geoip2.database.Reader(asn_db) as r:
            resp = r.asn(ip)
            result['asn'] = 'AS' + str(resp.autonomous_system_number or 0)
            result['org'] = resp.autonomous_system_organization or ''
except Exception as e:
    result['error'] = str(e)
print(json.dumps(result))
PY
}

# Human-readable uptime from seconds
format_uptime_human() {
  local secs="$1"
  python3 - "$secs" <<'PY' 2>/dev/null
import sys
s = int(sys.argv[1])
parts = []
if s >= 86400: parts.append(f"{s//86400}d")
if s % 86400 >= 3600: parts.append(f"{(s%86400)//3600}h")
if s % 3600 >= 60: parts.append(f"{(s%3600)//60}m")
if s < 60 or (s < 3600 and s % 60 > 0): parts.append(f"{s%60}s")
print(" ".join(parts) if parts else "0s")
PY
}

# Check quota and enforce via cgroup/systemd
check_and_enforce_quota() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, subprocess, json, os, time
db = '/etc/DaggerConnect/quota.db'
quota_db2 = '/etc/DaggerConnect/audit.db'
if not os.path.exists(db): sys.exit(0)
conn = sqlite3.connect(db, timeout=3)
c = conn.cursor()
try:
    rows = c.execute('SELECT key, value FROM quota_config').fetchall()
    cfg = {r[0]: r[1] for r in rows}
    max_cpu = float(cfg.get('max_cpu_pct', 0))
    max_mem = int(cfg.get('max_mem_mb', 0))
    if max_cpu <= 0 and max_mem <= 0:
        conn.close(); exit(0)
    import subprocess as sp
    for svc in ['DaggerConnect-server', 'DaggerConnect-client']:
        pid_out = sp.run(['systemctl','show','-p','MainPID','--value',svc], capture_output=True, text=True).stdout.strip()
        if not pid_out or pid_out == '0': continue
        pid = int(pid_out)
        try:
            cpu_out = sp.run(['ps','-p',str(pid),'-o','%cpu','--no-headers'], capture_output=True, text=True).stdout.strip()
            rss_out = sp.run(['ps','-p',str(pid),'-o','rss','--no-headers'], capture_output=True, text=True).stdout.strip()
            cur_cpu = float(cpu_out) if cpu_out else 0
            cur_mem = int(rss_out)//1024 if rss_out else 0
            breach = (max_cpu > 0 and cur_cpu > max_cpu) or (max_mem > 0 and cur_mem > max_mem)
            if breach:
                sp.run(['systemctl','restart',svc], capture_output=True)
                ts = int(time.time()*1000)
                c.execute('INSERT INTO quota_events (ts, event, detail) VALUES (?,?,?)',
                    (ts, 'quota_breach_restart', json.dumps({'svc':svc,'cpu':cur_cpu,'mem':cur_mem,'max_cpu':max_cpu,'max_mem':max_mem})))
                if os.path.exists(quota_db2):
                    conn2 = sqlite3.connect(quota_db2, timeout=3)
                    c2 = conn2.cursor()
                    c2.execute('INSERT INTO audit_log (ts, action, target, detail) VALUES (?,?,?,?)',
                        (ts, 'quota_restart', svc, f'cpu={cur_cpu}% mem={cur_mem}MB exceeded limits'))
                    conn2.commit(); conn2.close()
        except Exception: pass
    conn.commit()
except Exception: pass
finally: conn.close()
PY
}

# Init uptime/restart tracking DB
init_uptime_db() {
  python3 - <<'PY' 2>/dev/null
import sqlite3, os
db_path = '/etc/DaggerConnect/uptime.db'
os.makedirs(os.path.dirname(db_path), exist_ok=True)
conn = sqlite3.connect(db_path)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS svc_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  service TEXT NOT NULL,
  event TEXT NOT NULL,
  ts INTEGER NOT NULL,
  pid INTEGER
)''')
c.execute('''CREATE TABLE IF NOT EXISTS svc_stats (
  service TEXT PRIMARY KEY,
  restart_count INTEGER DEFAULT 0,
  last_start_ts INTEGER,
  last_stop_ts INTEGER,
  total_uptime_s INTEGER DEFAULT 0
)''')
conn.commit()
conn.close()
PY
}

# Record service event
record_svc_event() {
  local svc="$1" event="$2" pid="${3:-0}"
  python3 - "$svc" "$event" "$pid" <<'PY' 2>/dev/null
import sqlite3, sys, time, os
svc, event, pid = sys.argv[1], sys.argv[2], int(sys.argv[3])
db_path = '/etc/DaggerConnect/uptime.db'
if not os.path.exists(db_path):
    sys.exit(0)
ts = int(time.time() * 1000)
conn = sqlite3.connect(db_path, timeout=5)
c = conn.cursor()
try:
    c.execute('INSERT INTO svc_events (service, event, ts, pid) VALUES (?,?,?,?)', (svc, event, ts, pid))
    c.execute('INSERT OR IGNORE INTO svc_stats (service) VALUES (?)', (svc,))
    if event == 'start':
        c.execute('UPDATE svc_stats SET last_start_ts=?, restart_count=restart_count+1 WHERE service=?', (ts, svc))
    elif event == 'stop':
        row = c.execute('SELECT last_start_ts, total_uptime_s FROM svc_stats WHERE service=?', (svc,)).fetchone()
        if row and row[0]:
            elapsed = (ts - row[0]) // 1000
            c.execute('UPDATE svc_stats SET last_stop_ts=?, total_uptime_s=? WHERE service=?',
                      (ts, (row[1] or 0) + elapsed, svc))
    conn.commit()
except Exception:
    conn.rollback()
finally:
    conn.close()
PY
}

# Get service stats JSON
get_svc_stats() {
  local svc="$1"
  python3 - "$svc" <<'PY' 2>/dev/null
import sqlite3, sys, time, os, json
svc = sys.argv[1]
db_path = '/etc/DaggerConnect/uptime.db'
if not os.path.exists(db_path):
    print('{}')
    sys.exit(0)
conn = sqlite3.connect(db_path, timeout=3)
c = conn.cursor()
try:
    row = c.execute('''SELECT restart_count, last_start_ts, last_stop_ts, total_uptime_s
                       FROM svc_stats WHERE service=?''', (svc,)).fetchone()
    events = c.execute('''SELECT event, ts FROM svc_events WHERE service=?
                          ORDER BY ts DESC LIMIT 20''', (svc,)).fetchall()
    if row:
        now_ms = int(time.time() * 1000)
        last_start = row[1] or 0
        cur_uptime = max(0, (now_ms - last_start) // 1000) if last_start else 0
        result = {
            'restart_count': row[0] or 0,
            'last_start_ts': row[1],
            'last_stop_ts': row[2],
            'total_uptime_s': (row[3] or 0) + cur_uptime,
            'current_uptime_s': cur_uptime,
            'recent_events': [{'event': e[0], 'ts': e[1]} for e in events]
        }
    else:
        result = {'restart_count': 0, 'total_uptime_s': 0, 'current_uptime_s': 0, 'recent_events': []}
    print(json.dumps(result))
except Exception:
    print('{}')
finally:
    conn.close()
PY
}

# Initialize DBs on startup
init_audit_db 2>/dev/null
init_quota_db 2>/dev/null
init_schedule_db 2>/dev/null

# ── Read HTTP request from stdin ─────────────────────────────

read -r REQUEST_LINE
METHOD=$(printf '%s' "$REQUEST_LINE" | awk '{print $1}')
PATH_RAW=$(printf '%s' "$REQUEST_LINE" | awk '{print $2}')
ROUTE=$(printf '%s' "$PATH_RAW" | cut -d'?' -f1)
QUERY=$(printf '%s' "$PATH_RAW" | grep -o '?.*' | cut -c2-)

CONTENT_LENGTH=0
AUTH_TOKEN=""
STORED_WS_KEY=""
while IFS= read -r line; do
  line="${line%$'\r'}"
  [[ -z "$line" ]] && break
  if [[ "$line" =~ ^Content-Length:[[:space:]]*([0-9]+) ]]; then
    CONTENT_LENGTH="${BASH_REMATCH[1]}"
  fi
  if [[ "$line" =~ ^X-Auth-Token:[[:space:]]*(.*) ]]; then
    AUTH_TOKEN="${BASH_REMATCH[1]%$'\r'}"
    AUTH_TOKEN=$(printf '%s' "$AUTH_TOKEN" | tr -d '[:space:]')
  fi
  if [[ "$line" =~ ^Sec-WebSocket-Key:[[:space:]]*(.*) ]]; then
    STORED_WS_KEY="${BASH_REMATCH[1]%$'\r'}"
    STORED_WS_KEY=$(printf '%s' "$STORED_WS_KEY" | tr -d '[:space:]')
  fi
done

BODY=""
if [[ "$METHOD" == "POST" && "$CONTENT_LENGTH" -gt 0 ]]; then
  read -r -n "$CONTENT_LENGTH" BODY
fi

# ── CORS preflight ───────────────────────────────────────────
if [[ "$METHOD" == "OPTIONS" ]]; then
  printf "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, X-Auth-Token\r\n\r\n"
  exit 0
fi

# ── Auth check ───────────────────────────────────────────────
# WS: browser cannot send custom headers during handshake — accept token via ?token=
if [[ "$ROUTE" == "/api/ws" && -z "$AUTH_TOKEN" ]]; then
  WS_TOKEN=$(printf '%s' "$QUERY" | grep -o 'token=[^&]*' | cut -d= -f2)
  [[ -n "$WS_TOKEN" ]] && AUTH_TOKEN="$WS_TOKEN"
fi

if [[ -n "$EXPECTED_TOKEN" && "$ROUTE" != "/api/ping" && "$ROUTE" != "/api/auth" && "$ROUTE" != "/api/health" ]]; then
  if ! token_match "$AUTH_TOKEN" "$EXPECTED_TOKEN"; then
    err_auth
    exit 0
  fi
fi

# ── Routes ───────────────────────────────────────────────────

case "${METHOD} ${ROUTE}" in

"GET /api/ping")
  json_header
  printf '{"ok":true,"msg":"pong"}\n'
;;

# ── Health (unauthenticated composite) ───────────────────────
"GET /api/health")
  ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  [[ "$ROLE" != "server" && "$ROLE" != "client" ]] && ROLE="unknown"
  BIN=$(command -v DaggerConnect 2>/dev/null || echo "")
  VER="not installed"
  [[ -x "$BIN" ]] && VER=$("$BIN" -v 2>&1 | head -1)
  SRV=$(systemctl is-active DaggerConnect-server 2>/dev/null)
  CLI=$(systemctl is-active DaggerConnect-client 2>/dev/null)
  json_header
  printf '{"ok":true,"role":"%s","version":"%s","server_state":"%s","client_state":"%s"}\n' \
    "$ROLE" "$(json_escape "$VER")" "$SRV" "$CLI"
;;

"GET /api/role")
  ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  [[ "$ROLE" != "server" && "$ROLE" != "client" ]] && ROLE="unknown"
  json_header
  printf '{"ok":true,"role":"%s"}\n' "$ROLE"
;;

"POST /api/role")
  NEW_ROLE=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    r=json.load(sys.stdin).get('role','')
    print(r if r in ('server','client') else 'invalid')
except: print('invalid')
" 2>/dev/null)
  if [[ "$NEW_ROLE" == "invalid" || -z "$NEW_ROLE" ]]; then
    fail "Role must be 'server' or 'client'"
  else
    mkdir -p "$CONFIG_DIR"
    printf '%s' "$NEW_ROLE" > "$ROLE_FILE"
    chmod 644 "$ROLE_FILE"
    ok "Role set to $NEW_ROLE"
  fi
;;

"POST /api/auth")
  TOKEN=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('token',''))
except: print('')
" 2>/dev/null)
  if [[ -z "$EXPECTED_TOKEN" ]]; then
    json_header; printf '{"ok":true,"msg":"No auth configured"}\n'
  elif token_match "$TOKEN" "$EXPECTED_TOKEN"; then
    json_header; printf '{"ok":true,"msg":"Authenticated"}\n'
  else
    err_auth
  fi
;;

# ── Status ───────────────────────────────────────────────────
"GET /api/status")
  SRV_STATE=$(svc_state "$SERVER_SVC")
  CLI_STATE=$(svc_state "$CLIENT_SVC")

  SRV_PID=$(systemctl show -p MainPID --value "$SERVER_SVC" 2>/dev/null | tr -d '[:space:]')
  CLI_PID=$(systemctl show -p MainPID --value "$CLIENT_SVC" 2>/dev/null | tr -d '[:space:]')
  [[ -z "$SRV_PID" || "$SRV_PID" == "0" ]] && SRV_PID=0
  [[ -z "$CLI_PID" || "$CLI_PID" == "0" ]] && CLI_PID=0

  SRV_CPU=0; SRV_MEM=0; CLI_CPU=0; CLI_MEM=0; SRV_UPTIME=""; SRV_UPTIME_HUMAN=""; SRV_UPTIME_SECS=0
  CLI_UPTIME=""; CLI_UPTIME_HUMAN=""; CLI_UPTIME_SECS=0; CLI_STARTED_AT=0; SRV_STARTED_AT=0
  if [[ "$SRV_PID" -gt 1 ]]; then
    read -r SRV_CPU SRV_MEM < <(_proc_tree_stats "$SRV_PID")
    SRV_UPTIME=$(ps -p "$SRV_PID" -o etime= --no-headers 2>/dev/null | xargs)
    SRV_UPTIME_SECS=$(ps -p "$SRV_PID" -o etimes= --no-headers 2>/dev/null | xargs || echo 0)
    SRV_UPTIME_HUMAN=$(format_uptime_human "${SRV_UPTIME_SECS:-0}")
    SRV_STARTED_AT=$(( $(date +%s) - ${SRV_UPTIME_SECS:-0} ))
  fi
  if [[ "$CLI_PID" -gt 1 ]]; then
    read -r CLI_CPU CLI_MEM < <(_proc_tree_stats "$CLI_PID")
    CLI_UPTIME=$(ps -p "$CLI_PID" -o etime= --no-headers 2>/dev/null | xargs)
    CLI_UPTIME_SECS=$(ps -p "$CLI_PID" -o etimes= --no-headers 2>/dev/null | xargs || echo 0)
    CLI_UPTIME_HUMAN=$(format_uptime_human "${CLI_UPTIME_SECS:-0}")
    CLI_STARTED_AT=$(( $(date +%s) - ${CLI_UPTIME_SECS:-0} ))
  fi

  # CPU sample — reduced sleep, expose snap_ts so frontend calculates accurate net speed
  read -r _ u1 n1 s1 i1 _ _ _ _ _ < /proc/stat
  sleep 0.3
  read -r _ u2 n2 s2 i2 _ _ _ _ _ < /proc/stat
  DIFF_TOTAL=$(( (u2+n2+s2+i2) - (u1+n1+s1+i1) ))
  DIFF_IDLE=$(( i2 - i1 ))
  SYS_CPU=0
  [[ "$DIFF_TOTAL" -gt 0 ]] && SYS_CPU=$(( 100 * (DIFF_TOTAL - DIFF_IDLE) / DIFF_TOTAL ))

  read -r _ TOTAL USED _ < <(free -m | awk '/^Mem:/{print $1,$2,$3}')

  IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  RX=0; TX=0
  SNAP_TS=$(date +%s%3N)
  if [[ -n "$IFACE" && -f "/sys/class/net/$IFACE/statistics/rx_bytes" ]]; then
    RX=$(< "/sys/class/net/$IFACE/statistics/rx_bytes")
    TX=$(< "/sys/class/net/$IFACE/statistics/tx_bytes")
  fi

  # Active connections — role-aware, all ports
  NODE_ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  CONNS=0
  if [[ "$NODE_ROLE" == "client" ]]; then
    while IFS= read -r PORT; do
      [[ -z "$PORT" ]] && continue
      COUNT=$(ss -tn state established "dport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
      CONNS=$(( CONNS + COUNT ))
    done < <(get_client_ports)
  else
    while IFS= read -r PORT; do
      [[ -z "$PORT" ]] && continue
      COUNT=$(ss -tn state established "sport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
      CONNS=$(( CONNS + COUNT ))
    done < <(get_server_ports)
  fi

  json_header
  printf '{
  "server":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d,"uptime":"%s","uptime_human":"%s","uptime_s":%d,"started_at":%d,"connections":%d},
  "client":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d,"uptime":"%s","uptime_human":"%s","uptime_s":%d,"started_at":%d},
  "system":{"cpu_pct":%d,"ram_used_mb":%d,"ram_total_mb":%d,"rx_bytes":%d,"tx_bytes":%d,"iface":"%s","snap_ts":%d}
}\n' \
    "$SRV_STATE" "${SRV_PID:-0}" "${SRV_CPU:-0}" "${SRV_MEM:-0}" "$SRV_UPTIME" "${SRV_UPTIME_HUMAN:-}" "${SRV_UPTIME_SECS:-0}" "${SRV_STARTED_AT:-0}" "$CONNS" \
    "$CLI_STATE" "${CLI_PID:-0}" "${CLI_CPU:-0}" "${CLI_MEM:-0}" "$CLI_UPTIME" "${CLI_UPTIME_HUMAN:-}" "${CLI_UPTIME_SECS:-0}" "${CLI_STARTED_AT:-0}" \
    "$SYS_CPU" "${USED:-0}" "${TOTAL:-1}" "$RX" "$TX" "${IFACE:-eth0}" "$SNAP_TS"

  # ── Write metrics to SQLite (background collector handles this, but also write here for panel-open accuracy) ─────
  RAM_PCT=0
  [[ "${TOTAL:-0}" -gt 0 ]] && RAM_PCT=$(( 100 * ${USED:-0} / ${TOTAL} ))
  # Write to SQLite only — jsonl is no longer used
  write_metrics_db "$SNAP_TS" "$SYS_CPU" "$RAM_PCT" "${USED:-0}" "$RX" "$TX" "$CONNS" "${SRV_CPU:-0}" "${SRV_MEM:-0}"
;;

# ── Logs ─────────────────────────────────────────────────────
"GET /api/logs")
  SVC_PARAM=$(printf '%s' "$QUERY" | grep -o 'service=[^&]*' | cut -d= -f2)
  LINES_PARAM=$(printf '%s' "$QUERY" | grep -o 'lines=[^&]*' | cut -d= -f2)
  LINES="${LINES_PARAM:-$LOG_LINES}"
  [[ ! "$LINES" =~ ^[0-9]+$ ]] && LINES=$LOG_LINES
  [[ "$LINES" -gt 500 ]] && LINES=500
  [[ "$LINES" -lt 1 ]] && LINES=1

  case "$SVC_PARAM" in
    client) UNIT="$CLIENT_SVC" ;;
    *)      UNIT="$SERVER_SVC" ;;
  esac

  json_header
  printf '{"ok":true,"lines":['
  FIRST=1
  # timeout 10s prevents indefinite block if journald is slow
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    line="${line//\\/\\\\}"
    line="${line//\"/\\\"}"
    line="${line//$'\t'/\\t}"
    line="${line//$'\r'/}"
    [[ "$FIRST" -eq 1 ]] && FIRST=0 || printf ','
    printf '"%s"' "$line"
  done < <(timeout 10 journalctl -u "$UNIT" -n "$LINES" --no-pager --output=short-iso 2>/dev/null)
  printf ']}\n'
;;

# ── Service control ───────────────────────────────────────────
"POST /api/service/start" \
|"POST /api/service/stop" \
|"POST /api/service/restart" \
|"POST /api/service/enable" \
|"POST /api/service/disable")
  ACTION="${ROUTE##*/api/service/}"
  SVC=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('service',''))
except: print('')
" 2>/dev/null)
  # Hardcode unit names — never compose from user input
  case "$SVC" in
    server) UNIT="DaggerConnect-server" ;;
    client) UNIT="DaggerConnect-client" ;;
    *)      fail "Unknown service: $SVC"; exit 0 ;;
  esac
  if systemctl "$ACTION" "$UNIT" 2>/dev/null; then
    case "$ACTION" in
      start)   record_svc_event "$SVC" "start"; record_audit "service_$ACTION" "$SVC" "systemctl $ACTION $UNIT" ;;
      stop)    record_svc_event "$SVC" "stop"; record_audit "service_$ACTION" "$SVC" "systemctl $ACTION $UNIT" ;;
      restart) record_svc_event "$SVC" "stop"; sleep 0.5; record_svc_event "$SVC" "start"; record_audit "service_$ACTION" "$SVC" "systemctl $ACTION $UNIT" ;;
      *)       record_audit "service_$ACTION" "$SVC" "systemctl $ACTION $UNIT" ;;
    esac
    ok "${UNIT} ${ACTION}ed"
  else
    fail "systemctl $ACTION $UNIT failed — check journalctl"
  fi
;;

# ── GET config ───────────────────────────────────────────────
"GET /api/config")
  TARGET=$(printf '%s' "$QUERY" | grep -o 'target=[^&]*' | cut -d= -f2)
  case "$TARGET" in
    client) FILE="$CLIENT_YAML" ;;
    *)      FILE="$SERVER_YAML" ;;
  esac
  if [[ ! -f "$FILE" ]]; then
    fail "Config not found: $FILE"
  else
    CONTENT=$(escape_multiline < "$FILE")
    json_header
    printf '{"ok":true,"file":"%s","content":"%s"}\n' "$FILE" "$CONTENT"
  fi
;;

# ── POST config ──────────────────────────────────────────────
"POST /api/config")
  # Write to temp files to avoid subshell losing content with leading blank lines
  TMP_T=$(mktemp); TMP_C=$(mktemp)
  trap 'rm -f "$TMP_T" "$TMP_C"' EXIT

  TMP_PY=$(mktemp /tmp/api_parse.XXXXXX.py)
  cat > "$TMP_PY" << 'PY'
import sys, json
tf, cf = sys.argv[1], sys.argv[2]
try:
    d = json.loads(open(sys.argv[3]).read())
    t = d.get('target', 'server')
    if t not in ('server', 'client'):
        t = 'server'
    c = d.get('content', '')
    open(tf, 'w').write(t)
    open(cf, 'w').write(c)
except Exception as e:
    open(tf, 'w').write('error')
    open(cf, 'w').write(str(e))
PY
  TMP_BODY=$(mktemp)
  printf '%s' "$BODY" > "$TMP_BODY"
  python3 "$TMP_PY" "$TMP_T" "$TMP_C" "$TMP_BODY" 2>/dev/null
  rm -f "$TMP_PY" "$TMP_BODY"

  TARGET=$(cat "$TMP_T" 2>/dev/null)
  CONTENT=$(cat "$TMP_C" 2>/dev/null)

  if [[ "$TARGET" == "error" ]]; then
    fail "Invalid JSON body: $(json_escape "$CONTENT")"
    exit 0
  fi

  case "$TARGET" in
    client) FILE="$CLIENT_YAML" ;;
    *)      FILE="$SERVER_YAML" ;;
  esac

  [[ -z "$CONTENT" ]] && { fail "Empty content — not saved"; exit 0; }

  cp "$FILE" "${FILE}.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
  rotate_backups "$FILE"

  TMP_W=$(mktemp)
  printf '%s' "$CONTENT" > "$TMP_W" && mv "$TMP_W" "$FILE" \
    && { record_audit "config_save" "$TARGET" "Saved $FILE"; ok "Saved to $FILE (backup created)"; } \
    || fail "Failed to write $FILE"
;;

# ── POST config/validate ─────────────────────────────────────
"POST /api/config/validate")
  RESULT=$(printf '%s' "$BODY" | python3 -c "
import sys, json, yaml
try:
    d = json.load(sys.stdin)
    content = d.get('content', '')
    parsed = yaml.safe_load(content)
    if not isinstance(parsed, dict):
        print('error: top level must be a mapping')
        sys.exit()
    missing = [k for k in ['mode'] if k not in parsed]
    if missing:
        print('warn: missing required keys: ' + ', '.join(missing))
    else:
        print('ok')
except yaml.YAMLError as e:
    print('error: ' + str(e).replace(chr(10), ' '))
except Exception as e:
    print('error: ' + str(e))
" 2>/dev/null)
  STATUS="${RESULT%%:*}"
  MSG="${RESULT#*: }"
  json_header
  if [[ "$STATUS" == "ok" ]]; then
    printf '{"ok":true,"valid":true,"msg":"YAML is valid"}\n'
  elif [[ "$STATUS" == "warn" ]]; then
    printf '{"ok":true,"valid":true,"msg":"%s"}\n' "$(json_escape "$MSG")"
  else
    printf '{"ok":false,"valid":false,"msg":"%s"}\n' "$(json_escape "$RESULT")"
  fi
;;

# ── Port maps ────────────────────────────────────────────────
"GET /api/portmaps")
  if [[ ! -f "$SERVER_YAML" ]]; then
    json_header; printf '{"ok":true,"maps":[]}\n'; exit 0
  fi
  MAPS_JSON=$(get_portmaps_json)
  json_header
  printf '{"ok":true,"maps":%s}\n' "$MAPS_JSON"
;;

# ── Network speed (1-second sample with elapsed_ms) ──────────
"GET /api/network/speed")
  IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  if [[ -z "$IFACE" || ! -f "/sys/class/net/$IFACE/statistics/rx_bytes" ]]; then
    json_header; printf '{"ok":false,"msg":"No interface found"}\n'; exit 0
  fi
  RX1=$(< "/sys/class/net/$IFACE/statistics/rx_bytes")
  TX1=$(< "/sys/class/net/$IFACE/statistics/tx_bytes")
  T1=$(date +%s%3N)
  sleep 1
  RX2=$(< "/sys/class/net/$IFACE/statistics/rx_bytes")
  TX2=$(< "/sys/class/net/$IFACE/statistics/tx_bytes")
  T2=$(date +%s%3N)
  ELAPSED_MS=$(( T2 - T1 ))
  json_header
  printf '{"ok":true,"rx_bps":%d,"tx_bps":%d,"iface":"%s","elapsed_ms":%d}\n' \
    "$(( RX2 - RX1 ))" "$(( TX2 - TX1 ))" "$IFACE" "$ELAPSED_MS"
;;

# ── Cert generate ────────────────────────────────────────────
"POST /api/cert/generate")
  read -r CN DAYS < <(printf '%s' "$BODY" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    # Strip openssl subj field separator '/' and shell-dangerous chars
    cn = re.sub(r\"[/'\\\";|&\`<>]\", '', d.get('cn', 'www.google.com'))
    days = max(1, min(3650, int(d.get('days', 365))))
    print(cn, days)
except: print('www.google.com 365')
" 2>/dev/null)
  CN="${CN:-www.google.com}"; DAYS="${DAYS:-365}"
  CERT_DIR="$CONFIG_DIR/certs"
  mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
  if openssl req -x509 -newkey rsa:4096 -nodes \
      -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
      -days "$DAYS" -subj "/CN=$CN" 2>/dev/null; then
    chmod 600 "$CERT_DIR/key.pem"
    EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_DIR/cert.pem" 2>/dev/null | cut -d= -f2)
    json_header
    printf '{"ok":true,"cert":"%s","key":"%s","cn":"%s","expires":"%s"}\n' \
      "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem" "$CN" "$(json_escape "$EXPIRY")"
  else
    fail "openssl failed"
  fi
;;

# ── Cert info ────────────────────────────────────────────────
"GET /api/cert/info")
  CERT="$CONFIG_DIR/certs/cert.pem"
  if [[ ! -f "$CERT" ]]; then
    json_header; printf '{"ok":false,"msg":"No cert found"}\n'
  else
    CN=$(openssl x509 -subject -noout -in "$CERT" 2>/dev/null | sed 's/.*CN\s*=\s*//' | tr -d '\n')
    EXP=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2)
    NOW=$(date +%s)
    EXPTS=$(date -d "$EXP" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$EXP" +%s 2>/dev/null || echo 0)
    DAYS_LEFT=$(( (EXPTS - NOW) / 86400 ))
    json_header
    printf '{"ok":true,"cn":"%s","expires":"%s","days_left":%d}\n' \
      "$(json_escape "$CN")" "$(json_escape "$EXP")" "$DAYS_LEFT"
  fi
;;

# ── Active connections — role-aware, all ports, real states ──
"GET /api/connections")
  NODE_ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  ENTRIES=()
  PORTS_SEEN=()

  if [[ "$NODE_ROLE" == "client" ]]; then
    NOTE="outbound to server"
    while IFS= read -r PORT; do
      [[ -z "$PORT" ]] && continue
      PORTS_SEEN+=("$PORT")
      while read -r state _ _ local remote; do
        [[ -z "$local" ]] && continue
        ENTRIES+=("{\"local\":\"$local\",\"remote\":\"$remote\",\"state\":\"$state\",\"port\":$PORT}")
      done < <(ss -tn state established "dport = :$PORT" 2>/dev/null | tail -n +2)
    done < <(get_client_ports)
  else
    NOTE="inbound connections"
    while IFS= read -r PORT; do
      [[ -z "$PORT" ]] && continue
      PORTS_SEEN+=("$PORT")
      while read -r state _ _ local remote; do
        [[ -z "$local" ]] && continue
        ENTRIES+=("{\"local\":\"$local\",\"remote\":\"$remote\",\"state\":\"$state\",\"port\":$PORT}")
      done < <(ss -tn state established "sport = :$PORT" 2>/dev/null | tail -n +2)
    done < <(get_server_ports)
  fi

  # Build ports JSON array
  PORTS_JSON="[$(IFS=,; echo "${PORTS_SEEN[*]}")]"

  json_header
  printf '{"ok":true,"role":"%s","note":"%s","ports":%s,"count":%d,"connections":[' \
    "$NODE_ROLE" "$NOTE" "$PORTS_JSON" "${#ENTRIES[@]}"
  for i in "${!ENTRIES[@]}"; do
    [[ "$i" -gt 0 ]] && printf ','
    printf '%s' "${ENTRIES[$i]}"
  done
  printf '],"daggermux_note":"daggermux uses pcap — connections not visible to ss"}\n'
;;

# ── Version ──────────────────────────────────────────────────
"GET /api/version")
  BIN=$(command -v DaggerConnect 2>/dev/null || echo "/usr/local/bin/DaggerConnect")
  VER="not installed"
  [[ -x "$BIN" ]] && VER=$("$BIN" -v 2>&1 | head -1)
  ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  [[ "$ROLE" != "server" && "$ROLE" != "client" ]] && ROLE="unknown"
  json_header
  printf '{"ok":true,"version":"%s","binary":"%s","role":"%s"}\n' \
    "$(json_escape "$VER")" "$BIN" "$ROLE"
;;

# ── DaggerMux iptables setup ─────────────────────────────────
"POST /api/daggermux/iptables")
  PORT_ARG=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    p=int(json.load(sys.stdin).get('port',2020))
    print(p if 1<=p<=65535 else 2020)
except: print(2020)
" 2>/dev/null)
  PORT_ARG="${PORT_ARG:-2020}"

  ERRORS=""
  apply_ipt() { iptables "$@" 2>/dev/null || ERRORS="$ERRORS; iptables $* failed"; }
  apply_ipt -t raw    -A PREROUTING -p tcp --dport "$PORT_ARG" -j NOTRACK
  apply_ipt -t raw    -A OUTPUT     -p tcp --sport "$PORT_ARG" -j NOTRACK
  apply_ipt -t mangle -A OUTPUT     -p tcp --sport "$PORT_ARG" --tcp-flags RST RST -j DROP

  if [[ -z "$ERRORS" ]]; then
    PERSIST_NOTE=""
    if command -v iptables-save &>/dev/null; then
      mkdir -p /etc/iptables 2>/dev/null
      iptables-save > /etc/iptables/rules.v4 2>/dev/null \
        && PERSIST_NOTE=" Persisted to /etc/iptables/rules.v4." \
        || PERSIST_NOTE=" WARNING: could not persist rules — will be lost on reboot."
    else
      PERSIST_NOTE=" WARNING: iptables-save not found — rules not persisted across reboots."
    fi
    ok "Rules applied for port $PORT_ARG.${PERSIST_NOTE}"
  else
    fail "Some rules failed: $ERRORS"
  fi
;;

"GET /api/daggermux/iptables")
  PORT_ARG=$(printf '%s' "$QUERY" | grep -o 'port=[^&]*' | cut -d= -f2)
  PORT_ARG="${PORT_ARG:-2020}"
  RAW=$(iptables -t raw    -L PREROUTING -n 2>/dev/null | grep "$PORT_ARG")
  MNG=$(iptables -t mangle -L OUTPUT     -n 2>/dev/null | grep "$PORT_ARG")
  ACTIVE=false; [[ -n "$RAW" ]] && ACTIVE=true
  json_header
  printf '{"ok":true,"port":%s,"rules_active":%s,"raw_prerouting":"%s","mangle_output":"%s"}\n' \
    "$PORT_ARG" "$ACTIVE" "$(json_escape "$RAW")" "$(json_escape "$MNG")"
;;

# ── Config templates ─────────────────────────────────────────
"GET /api/config/template")
  TRANSPORT=$(printf '%s' "$QUERY" | grep -o 'transport=[^&]*' | cut -d= -f2)
  ROLE_T=$(printf '%s' "$QUERY" | grep -o 'role=[^&]*' | cut -d= -f2)
  [[ -z "$ROLE_T" ]] && ROLE_T=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  [[ "$ROLE_T" != "server" && "$ROLE_T" != "client" ]] && ROLE_T="server"
  T="${TRANSPORT:-httpsmux}"

  case "$T" in
    rawmux)
      [[ "$ROLE_T" == "server" ]] \
        && TMPL='mode: "server"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\nlisteners:\n  - addr: "0.0.0.0:5000"\n    transport: "rawmux"\n    maps:\n      - type: tcp\n        bind: "0.0.0.0:2222"\n        target: "127.0.0.1:22"\n\nrawmux:\n  handshake_timeout: 10\n  keepalive: 15\n  read_buffer: 4194304\n  write_buffer: 4194304\n  use_pcap: true\n\nobfuscation:\n  enabled: false\n' \
        || TMPL='mode: "client"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\npaths:\n  - transport: "rawmux"\n    addr: "IRAN_SERVER_IP:5000"\n    connection_pool: 4\n    retry_interval: 2\n    dial_timeout: 10\n\nrawmux:\n  handshake_timeout: 10\n  keepalive: 15\n  read_buffer: 4194304\n  write_buffer: 4194304\n  use_pcap: true\n\nobfuscation:\n  enabled: false\n'
      ;;
    daggermux)
      [[ "$ROLE_T" == "server" ]] \
        && TMPL='mode: "server"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "latency"\nverbose: false\nheartbeat: 2\n\nlisteners:\n  - addr: "0.0.0.0:2020"\n    transport: "daggermux"\n    maps:\n      - type: tcp\n        bind: "0.0.0.0:8080"\n        target: "127.0.0.1:8080"\n\ndaggermux:\n  mtu: 1350\n  snd_wnd: 1024\n  rcv_wnd: 1024\n  data_shard: 10\n  parity_shard: 1\n  sock_buf: 4194304\n  local_flags:\n    - "PA"\n    - "A"\n  remote_flags:\n    - "PA"\n    - "A"\n\nobfuscation:\n  enabled: false\n' \
        || TMPL='mode: "client"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "latency"\nverbose: false\nheartbeat: 2\n\npaths:\n  - transport: "daggermux"\n    addr: "IRAN_SERVER_IP:2020"\n    connection_pool: 2\n    aggressive_pool: true\n    retry_interval: 2\n    dial_timeout: 10\n\ndaggermux:\n  local_ip: ""\n  interface: ""\n  router_mac: ""\n  mtu: 1350\n  snd_wnd: 1024\n  rcv_wnd: 1024\n  data_shard: 10\n  parity_shard: 1\n  sock_buf: 4194304\n  local_flags:\n    - "PA"\n    - "A"\n  remote_flags:\n    - "PA"\n    - "A"\n\nobfuscation:\n  enabled: false\n'
      ;;
    kcpmux)
      [[ "$ROLE_T" == "server" ]] \
        && TMPL='mode: "server"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "gaming"\nverbose: false\n\nlisteners:\n  - addr: "0.0.0.0:4000"\n    transport: "kcpmux"\n    maps:\n      - type: tcp\n        bind: "0.0.0.0:2222"\n        target: "127.0.0.1:22"\n      - type: udp\n        bind: "0.0.0.0:2222"\n        target: "127.0.0.1:22"\n\nobfuscation:\n  enabled: false\n' \
        || TMPL='mode: "client"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "gaming"\nverbose: false\n\npaths:\n  - transport: "kcpmux"\n    addr: "IRAN_SERVER_IP:4000"\n    connection_pool: 2\n    retry_interval: 3\n    dial_timeout: 10\n\nobfuscation:\n  enabled: false\n'
      ;;
    httpmux|wsmux)
      [[ "$ROLE_T" == "server" ]] \
        && TMPL='mode: "server"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\nhttp_mimic:\n  fake_domain: "www.google.com"\n  fake_path: "/search"\n  session_cookie: true\n\nlisteners:\n  - addr: "0.0.0.0:80"\n    transport: "'$T'"\n    maps:\n      - type: tcp\n        bind: "0.0.0.0:2222"\n        target: "127.0.0.1:22"\n\nobfuscation:\n  enabled: true\n  min_padding: 16\n  max_padding: 256\n  min_delay_ms: 5\n  max_delay_ms: 50\n  burst_chance: 0.15\n' \
        || TMPL='mode: "client"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\nhttp_mimic:\n  fake_domain: "www.google.com"\n  fake_path: "/search"\n  session_cookie: true\n\npaths:\n  - transport: "'$T'"\n    addr: "IRAN_SERVER_IP:80"\n    connection_pool: 2\n    retry_interval: 3\n    dial_timeout: 10\n\nobfuscation:\n  enabled: true\n  min_padding: 16\n  max_padding: 256\n  min_delay_ms: 5\n  max_delay_ms: 50\n  burst_chance: 0.15\n'
      ;;
    httpsmux|wssmux|*)
      [[ "$T" != "httpsmux" && "$T" != "wssmux" ]] && T="httpsmux"
      [[ "$ROLE_T" == "server" ]] \
        && TMPL='mode: "server"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\ncert_file: "/etc/DaggerConnect/certs/cert.pem"\nkey_file: "/etc/DaggerConnect/certs/key.pem"\n\nhttp_mimic:\n  fake_domain: "www.google.com"\n  fake_path: "/search"\n  session_cookie: true\n\nlisteners:\n  - addr: "0.0.0.0:443"\n    transport: "'$T'"\n    cert_file: "/etc/DaggerConnect/certs/cert.pem"\n    key_file: "/etc/DaggerConnect/certs/key.pem"\n    maps:\n      - type: tcp\n        bind: "0.0.0.0:2222"\n        target: "127.0.0.1:22"\n\nobfuscation:\n  enabled: true\n  min_padding: 16\n  max_padding: 256\n  min_delay_ms: 5\n  max_delay_ms: 50\n  burst_chance: 0.15\n' \
        || TMPL='mode: "client"\npsk: "CHANGEME_USE_PSK_GENERATOR"\nprofile: "balanced"\nverbose: false\n\nhttp_mimic:\n  fake_domain: "www.google.com"\n  fake_path: "/search"\n  session_cookie: true\n\npaths:\n  - transport: "'$T'"\n    addr: "IRAN_SERVER_IP:443"\n    connection_pool: 2\n    retry_interval: 3\n    dial_timeout: 10\n\nobfuscation:\n  enabled: true\n  min_padding: 16\n  max_padding: 256\n  min_delay_ms: 5\n  max_delay_ms: 50\n  burst_chance: 0.15\n'
      ;;
  esac

  json_header
  TMPL_ESC="${TMPL//\\/\\\\}"; TMPL_ESC="${TMPL_ESC//\"/\\\"}"
  printf '{"ok":true,"transport":"%s","role":"%s","template":"%s"}\n' "$T" "$ROLE_T" "$TMPL_ESC"
;;

# ── Metrics history — SQLite with 30d support ────────────────
"GET /api/metrics/history")
  # ?range=raw|hourly|daily  ?points=N  ?days=D  ?from=TS  ?to=TS
  RANGE_PARAM=$(printf '%s' "$QUERY" | grep -o 'range=[^&]*' | cut -d= -f2)
  POINTS_PARAM=$(printf '%s' "$QUERY" | grep -o 'points=[^&]*' | cut -d= -f2)
  DAYS_PARAM=$(printf '%s' "$QUERY" | grep -o 'days=[^&]*' | cut -d= -f2)
  FROM_PARAM=$(printf '%s' "$QUERY" | grep -o 'from=[^&]*' | cut -d= -f2)
  TO_PARAM=$(printf '%s' "$QUERY" | grep -o 'to=[^&]*' | cut -d= -f2)

  RANGE="${RANGE_PARAM:-raw}"
  POINTS="${POINTS_PARAM:-720}"
  DAYS="${DAYS_PARAM:-1}"
  [[ ! "$POINTS" =~ ^[0-9]+$ ]] && POINTS=720
  [[ ! "$DAYS" =~ ^[0-9]+$ ]] && DAYS=1

  json_header
  python3 - "$RANGE" "$POINTS" "$DAYS" "${FROM_PARAM:-0}" "${TO_PARAM:-0}" <<'PY' 2>/dev/null
import sqlite3, json, sys, os, time
range_type, points, days, from_ts, to_ts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
db_path = '/etc/DaggerConnect/metrics.db'
now_ms = int(time.time() * 1000)

if from_ts == 0:
    from_ts = now_ms - days * 86400000
if to_ts == 0:
    to_ts = now_ms

result = []

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path, timeout=5)
    c = conn.cursor()
    try:
        if range_type == 'raw':
            rows = c.execute('''SELECT ts, cpu, ram, rx, tx, conns, srv_cpu, srv_mem
                                FROM metrics_raw WHERE ts >= ? AND ts <= ?
                                ORDER BY ts ASC LIMIT ?''',
                             (from_ts, to_ts, points)).fetchall()
            result = [{'ts': r[0], 'cpu': r[1], 'ram': r[2], 'rx': r[3], 'tx': r[4],
                       'conns': r[5], 'srv_cpu': r[6], 'srv_mem': r[7]} for r in rows]
        elif range_type == 'hourly':
            rows = c.execute('''SELECT hour_ts, cpu_avg, cpu_max, ram_avg, ram_max,
                                       rx_min, rx_max, tx_min, tx_max, conns_avg, conns_max, sample_count
                                FROM metrics_hourly WHERE hour_ts >= ? AND hour_ts <= ?
                                ORDER BY hour_ts ASC LIMIT ?''',
                             (from_ts, to_ts, min(points, 720))).fetchall()
            result = [{'ts': r[0], 'cpu_avg': r[1], 'cpu_max': r[2], 'ram_avg': r[3], 'ram_max': r[4],
                       'rx_min': r[5], 'rx_max': r[6], 'tx_min': r[7], 'tx_max': r[8],
                       'conns_avg': r[9], 'conns_max': r[10], 'samples': r[11], 'type': 'hourly'} for r in rows]
        elif range_type == 'daily':
            rows = c.execute('''SELECT day_ts, cpu_avg, cpu_max, ram_avg, ram_max,
                                       rx_min, rx_max, tx_min, tx_max, conns_avg, conns_max, sample_count
                                FROM metrics_daily WHERE day_ts >= ? AND day_ts <= ?
                                ORDER BY day_ts ASC LIMIT ?''',
                             (from_ts, to_ts, min(points, 92))).fetchall()
            result = [{'ts': r[0], 'cpu_avg': r[1], 'cpu_max': r[2], 'ram_avg': r[3], 'ram_max': r[4],
                       'rx_min': r[5], 'rx_max': r[6], 'tx_min': r[7], 'tx_max': r[8],
                       'conns_avg': r[9], 'conns_max': r[10], 'samples': r[11], 'type': 'daily'} for r in rows]
    except Exception:
        pass
    finally:
        conn.close()

print(json.dumps({'ok': True, 'range': range_type, 'count': len(result), 'points': result}))
PY
  # python3 always outputs a result — no fallback echo needed (would cause double JSON)
;;

# ── Metrics summary stats ─────────────────────────────────────
"GET /api/metrics/summary")
  json_header
  python3 - <<'PY' 2>/dev/null
import sqlite3, json, time, os
db_path = '/etc/DaggerConnect/metrics.db'
now_ms = int(time.time() * 1000)

result = {
    '1h': {}, '24h': {}, '7d': {}, '30d': {},
    'db_exists': os.path.exists(db_path)
}

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path, timeout=5)
    c = conn.cursor()
    try:
        for period, ms, table, ts_col in [
            ('1h',  3600000,    'metrics_raw',    'ts'),
            ('24h', 86400000,   'metrics_hourly', 'hour_ts'),
            ('7d',  604800000,  'metrics_hourly', 'hour_ts'),
            ('30d', 2592000000, 'metrics_daily',  'day_ts'),
        ]:
            from_ts = now_ms - ms
            if table == 'metrics_raw':
                row = c.execute('''SELECT AVG(cpu), MAX(cpu), AVG(ram), MAX(ram),
                                          MIN(rx), MAX(rx), MIN(tx), MAX(tx),
                                          AVG(conns), MAX(conns), COUNT(*)
                                   FROM metrics_raw WHERE ts >= ?''', (from_ts,)).fetchone()
                if row and row[10]:
                    result[period] = {
                        'cpu_avg': round(row[0] or 0, 1), 'cpu_max': row[1] or 0,
                        'ram_avg': round(row[2] or 0, 1), 'ram_max': row[3] or 0,
                        'rx_min': row[4], 'rx_max': row[5],
                        'tx_min': row[6], 'tx_max': row[7],
                        'conns_avg': round(row[8] or 0, 1), 'conns_max': row[9] or 0,
                        'samples': row[10]
                    }
            else:
                row = c.execute('''SELECT AVG(cpu_avg), MAX(cpu_max), AVG(ram_avg), MAX(ram_max),
                                          MIN(rx_min), MAX(rx_max), MIN(tx_min), MAX(tx_max),
                                          AVG(conns_avg), MAX(conns_max), SUM(sample_count)
                                   FROM {} WHERE {} >= ?'''.format(table, ts_col), (from_ts,)).fetchone()
                if row and row[10]:
                    result[period] = {
                        'cpu_avg': round(row[0] or 0, 1), 'cpu_max': row[1] or 0,
                        'ram_avg': round(row[2] or 0, 1), 'ram_max': row[3] or 0,
                        'rx_min': row[4], 'rx_max': row[5],
                        'tx_min': row[6], 'tx_max': row[7],
                        'conns_avg': round(row[8] or 0, 1), 'conns_max': row[9] or 0,
                        'samples': row[10]
                    }
    except Exception as e:
        result['error'] = str(e)
    finally:
        conn.close()

print(json.dumps({'ok': True, 'summary': result}))
PY
;;

# ── Service uptime/restart stats ─────────────────────────────
"GET /api/service/stats")
  SVC_PARAM=$(printf '%s' "$QUERY" | grep -o 'service=[^&]*' | cut -d= -f2)
  case "$SVC_PARAM" in
    client) SVC_KEY="client" ;;
    *)      SVC_KEY="server" ;;
  esac
  STATS=$(get_svc_stats "$SVC_KEY")
  [[ -z "$STATS" ]] && STATS="{}"
  json_header
  printf '{"ok":true,"service":"%s","stats":%s}\n' "$SVC_KEY" "$STATS"
;;

# ── Config diff — compare current with proposed ───────────────
"POST /api/config/diff")
  TMP_PY=$(mktemp /tmp/api_diff.XXXXXX.py)
  cat > "$TMP_PY" << 'PY'
import sys, json, difflib
try:
    d = json.loads(open(sys.argv[1]).read())
    target = d.get('target', 'server')
    proposed = d.get('content', '')
    
    config_dir = '/etc/DaggerConnect'
    if target == 'client':
        file_path = config_dir + '/client.yaml'
    else:
        file_path = config_dir + '/server.yaml'
    
    try:
        with open(file_path) as f:
            current = f.read()
    except FileNotFoundError:
        current = '# File not found\n'
    
    current_lines = current.splitlines(keepends=True)
    proposed_lines = proposed.splitlines(keepends=True)
    
    diff = list(difflib.unified_diff(
        current_lines, proposed_lines,
        fromfile='current (' + file_path + ')',
        tofile='proposed (unsaved)',
        lineterm=''
    ))
    
    # Also generate structured diff for UI
    sm = difflib.SequenceMatcher(None, current_lines, proposed_lines)
    changes = {'added': 0, 'removed': 0, 'changed': 0}
    hunks = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == 'insert':
            changes['added'] += j2 - j1
        elif op == 'delete':
            changes['removed'] += i2 - i1
        elif op == 'replace':
            changes['changed'] += max(i2-i1, j2-j1)
    
    result = {
        'ok': True,
        'target': target,
        'has_diff': len(diff) > 0,
        'diff_lines': diff,
        'changes': changes,
        'current_lines': len(current_lines),
        'proposed_lines': len(proposed_lines),
    }
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
PY
  TMP_BODY=$(mktemp)
  printf '%s' "$BODY" > "$TMP_BODY"
  RESULT=$(python3 "$TMP_PY" "$TMP_BODY" 2>/dev/null)
  rm -f "$TMP_PY" "$TMP_BODY"
  [[ -z "$RESULT" ]] && RESULT='{"ok":false,"msg":"diff failed"}'
  json_header
  printf '%s\n' "$RESULT"
;;



# ── WebSocket upgrade — real-time status push ─────────────────
"GET /api/ws")
  WS_KEY="$STORED_WS_KEY"
  if [[ -z "$WS_KEY" ]]; then
    printf "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nMissing Sec-WebSocket-Key\n"
    exit 0
  fi
  WS_ACCEPT=$(python3 -c "
import base64, hashlib, sys
digest = hashlib.sha1((sys.argv[1]+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
print(base64.b64encode(digest).decode())
" "$WS_KEY" 2>/dev/null)
  if [[ -z "$WS_ACCEPT" ]]; then
    printf "HTTP/1.1 500 Internal Server Error\r\n\r\n"; exit 0
  fi
  printf "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" "$WS_ACCEPT"

  _push_ws_text() {
    local payload="$1" len="${#1}"
    printf '\x81'
    if [[ $len -lt 126 ]]; then printf "\\x$(printf '%02x' $len)"
    else printf '\x7e'"\\x$(printf '%02x' $((len>>8)))\\x$(printf '%02x' $((len&0xff)))"; fi
    printf '%s' "$payload"
  }

  # WebSocket just reads latest metrics from DB — does NOT collect new samples
  # The background collector in start.sh handles all metrics collection
  while true; do
    # Service states
    SRV_ST=$(systemctl is-active DaggerConnect-server 2>/dev/null)
    CLI_ST=$(systemctl is-active DaggerConnect-client 2>/dev/null)
    SP=$(systemctl show -p MainPID --value DaggerConnect-server 2>/dev/null | tr -d '[:space:]')
    CP=$(systemctl show -p MainPID --value DaggerConnect-client 2>/dev/null | tr -d '[:space:]')
    [[ -z "$SP" || "$SP" == "0" ]] && SP=0
    [[ -z "$CP" || "$CP" == "0" ]] && CP=0
    
    # Process stats (server/client only)
    SC=0; SM=0; CC=0; CM=0
    [[ "$SP" -gt 1 ]] && read -r SC SM < <(_proc_tree_stats "$SP")
    [[ "$CP" -gt 1 ]] && read -r CC CM < <(_proc_tree_stats "$CP")
    
    # Read latest metrics from DB (collected by background process) - single python call
    LATEST=$(python3 - <<'PY' 2>/dev/null
import sqlite3, os, json
db = '/etc/DaggerConnect/metrics.db'
result = {'cpu': 0, 'ram_used_mb': 0, 'ram_total_mb': 1024, 'rx': 0, 'tx': 0, 'ts': 0}
if os.path.exists(db):
    try:
        conn = sqlite3.connect(db, timeout=2)
        c = conn.cursor()
        row = c.execute('SELECT ts, cpu, ram, ram_mb, rx, tx FROM metrics_raw ORDER BY ts DESC LIMIT 1').fetchone()
        conn.close()
        if row:
            total_mb = 1024
            try:
                with open('/proc/meminfo') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            total_mb = int(line.split()[1]) // 1024
                            break
            except Exception:
                pass
            result = {'ts': row[0], 'cpu': row[1], 'ram_used_mb': row[3], 'ram_total_mb': total_mb, 'rx': row[4], 'tx': row[5]}
    except Exception:
        pass
print(json.dumps(result))
PY
)

    # Parse metrics from single DB query result
    if [[ -n "$LATEST" ]]; then
      read -r SYS_CPU RU RT RX TX SNAP_TS < <(python3 -c "
import json,sys
d=json.loads(sys.argv[1])
print(d.get('cpu',0), d.get('ram_used_mb',0), d.get('ram_total_mb',1), d.get('rx',0), d.get('tx',0), d.get('ts',0))
" "$LATEST" 2>/dev/null)
    else
      SYS_CPU=0; RU=0; RT=1; RX=0; TX=0; SNAP_TS=$(date +%s%3N)
    fi

    # Count active connections live (role-aware) every WS tick
    WS_NODE_ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
    CONNS=0
    if [[ "$WS_NODE_ROLE" == "client" ]]; then
      while IFS= read -r PORT; do
        [[ -z "$PORT" ]] && continue
        COUNT=$(ss -tn state established "dport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
        CONNS=$(( CONNS + COUNT ))
      done < <(get_client_ports)
    else
      while IFS= read -r PORT; do
        [[ -z "$PORT" ]] && continue
        COUNT=$(ss -tn state established "sport = :$PORT" 2>/dev/null | tail -n +2 | wc -l)
        CONNS=$(( CONNS + COUNT ))
      done < <(get_server_ports)
    fi
    
    IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    
    # Service uptime
    SRV_UPTIME_SECS=0; SRV_STARTED_AT=0; CLI_UPTIME_SECS=0; CLI_STARTED_AT=0
    [[ "$SP" -gt 1 ]] && {
      SRV_UPTIME_SECS=$(ps -p "$SP" -o etimes= --no-headers 2>/dev/null | xargs || echo 0)
      SRV_STARTED_AT=$(( $(date +%s) - ${SRV_UPTIME_SECS:-0} ))
    }
    [[ "$CP" -gt 1 ]] && {
      CLI_UPTIME_SECS=$(ps -p "$CP" -o etimes= --no-headers 2>/dev/null | xargs || echo 0)
      CLI_STARTED_AT=$(( $(date +%s) - ${CLI_UPTIME_SECS:-0} ))
    }

    # Send comprehensive status update
    PAYLOAD=$(printf '{"type":"status","data":{"server":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d,"uptime_s":%d,"started_at":%d,"connections":%d},"client":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d,"uptime_s":%d,"started_at":%d},"system":{"cpu_pct":%d,"ram_used_mb":%d,"ram_total_mb":%d,"rx_bytes":%d,"tx_bytes":%d,"iface":"%s","snap_ts":%d}}}' \
      "$SRV_ST" "${SP:-0}" "${SC:-0}" "${SM:-0}" "${SRV_UPTIME_SECS:-0}" "${SRV_STARTED_AT:-0}" "$CONNS" \
      "$CLI_ST" "${CP:-0}" "${CC:-0}" "${CM:-0}" "${CLI_UPTIME_SECS:-0}" "${CLI_STARTED_AT:-0}" \
      "$SYS_CPU" "${RU:-0}" "${RT:-1}" "$RX" "$TX" "${IFACE:-eth0}" "$SNAP_TS")
    _push_ws_text "$PAYLOAD" || break
    
    # Also send a separate metrics-focused message for chart updates
    METRICS_PAYLOAD=$(printf '{"type":"metrics","data":{"system":{"cpu_pct":%d,"ram_used_mb":%d,"ram_total_mb":%d,"rx_bytes":%d,"tx_bytes":%d,"snap_ts":%d,"connections":%d}}}' \
      "$SYS_CPU" "${RU:-0}" "${RT:-1}" "$RX" "$TX" "$SNAP_TS" "$CONNS")
    _push_ws_text "$METRICS_PAYLOAD" || break
    
    check_and_enforce_quota
    
    sleep 5
  done
  exit 0
;;


# ── Config backups list ───────────────────────────────────────
"GET /api/config/backups")
  TARGET=$(printf '%s' "$QUERY" | grep -o 'target=[^&]*' | cut -d= -f2)
  case "$TARGET" in
    client) FILE="$CLIENT_YAML" ;;
    *)      FILE="$SERVER_YAML" ; TARGET="server" ;;
  esac
  json_header
  python3 - "$FILE" <<'PY' 2>/dev/null
import sys, os, json, glob
base = sys.argv[1]
backups = sorted(glob.glob(base + '.bak.*'), reverse=True)
result = []
for b in backups[:20]:
    try:
        stat = os.stat(b)
        result.append({'path': b, 'name': os.path.basename(b), 'size': stat.st_size, 'mtime': int(stat.st_mtime * 1000)})
    except Exception:
        pass
print(json.dumps({'ok': True, 'backups': result}))
PY
;;

# ── Config backup restore ─────────────────────────────────────
"POST /api/config/restore")
  TMP_PY=$(mktemp /tmp/api_restore.XXXXXX.py)
  cat > "$TMP_PY" << 'PY'
import sys, json, shutil, os
try:
    d = json.loads(open(sys.argv[1]).read())
    backup_path = d.get('backup_path', '')
    target = d.get('target', 'server')
    config_dir = '/etc/DaggerConnect'
    dest = config_dir + ('/' + target + '.yaml')
    if not backup_path or not os.path.exists(backup_path):
        print(json.dumps({'ok': False, 'msg': 'Backup file not found: ' + backup_path}))
        sys.exit()
    if not backup_path.startswith(config_dir):
        print(json.dumps({'ok': False, 'msg': 'Invalid backup path'}))
        sys.exit()
    import time
    new_bak = dest + '.bak.' + time.strftime('%Y%m%d_%H%M%S')
    if os.path.exists(dest):
        shutil.copy2(dest, new_bak)
    shutil.copy2(backup_path, dest)
    print(json.dumps({'ok': True, 'msg': 'Restored ' + backup_path + ' to ' + dest}))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
PY
  TMP_BODY=$(mktemp)
  printf '%s' "$BODY" > "$TMP_BODY"
  RESULT=$(python3 "$TMP_PY" "$TMP_BODY" 2>/dev/null)
  rm -f "$TMP_PY" "$TMP_BODY"
  [[ -z "$RESULT" ]] && RESULT='{"ok":false,"msg":"restore failed"}'
  record_audit "config_restore" "" "$(echo "$RESULT" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("msg",""))' 2>/dev/null)"
  json_header
  printf '%s\n' "$RESULT"
;;

# ── Config bundle export ──────────────────────────────────────
"GET /api/config/export")
  json_header
  python3 - <<'PY' 2>/dev/null
import json, os, base64, time
config_dir = '/etc/DaggerConnect'
bundle = {'exported_ts': int(time.time()*1000), 'files': {}}
for fname in ['server.yaml', 'client.yaml', 'panel.role', 'panel.token']:
    fpath = config_dir + '/' + fname
    if os.path.exists(fpath):
        try:
            with open(fpath, 'rb') as f:
                bundle['files'][fname] = base64.b64encode(f.read()).decode()
        except Exception:
            pass
cert_dir = config_dir + '/certs'
for cname in ['cert.pem', 'key.pem']:
    cpath = cert_dir + '/' + cname
    if os.path.exists(cpath):
        try:
            with open(cpath, 'rb') as f:
                bundle['files']['certs/' + cname] = base64.b64encode(f.read()).decode()
        except Exception:
            pass
print(json.dumps({'ok': True, 'bundle': bundle}))
PY
;;

# ── Config bundle import ──────────────────────────────────────
"POST /api/config/import")
  TMP_PY=$(mktemp /tmp/api_import.XXXXXX.py)
  cat > "$TMP_PY" << 'PY'
import sys, json, os, base64, time
try:
    d = json.loads(open(sys.argv[1]).read())
    bundle = d.get('bundle', {})
    files = bundle.get('files', {})
    config_dir = '/etc/DaggerConnect'
    restored = []
    for fname, b64data in files.items():
        if '/' in fname and not fname.startswith('certs/'):
            continue
        dest = config_dir + '/' + fname
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if os.path.exists(dest):
            bak = dest + '.bak.' + time.strftime('%Y%m%d_%H%M%S')
            import shutil; shutil.copy2(dest, bak)
        with open(dest, 'wb') as f:
            f.write(base64.b64decode(b64data))
        restored.append(fname)
    print(json.dumps({'ok': True, 'restored': restored, 'count': len(restored)}))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
PY
  TMP_BODY=$(mktemp)
  printf '%s' "$BODY" > "$TMP_BODY"
  RESULT=$(python3 "$TMP_PY" "$TMP_BODY" 2>/dev/null)
  rm -f "$TMP_PY" "$TMP_BODY"
  [[ -z "$RESULT" ]] && RESULT='{"ok":false,"msg":"import failed"}'
  record_audit "config_import" "" "bundle imported"
  json_header
  printf '%s\n' "$RESULT"
;;

# ── Bandwidth budget tracker ──────────────────────────────────
"GET /api/bandwidth/usage")
  json_header
  python3 - <<'PY' 2>/dev/null
import sqlite3, json, time, os
db = '/etc/DaggerConnect/metrics.db'
now_ms = int(time.time() * 1000)
result = {'ok': True, 'periods': {}}
if os.path.exists(db):
    conn = sqlite3.connect(db, timeout=5)
    c = conn.cursor()
    try:
        for period, ms, table, ts_col in [
            ('today', 86400000, 'metrics_hourly', 'hour_ts'),
            ('week',  604800000, 'metrics_hourly', 'hour_ts'),
            ('month', 2592000000, 'metrics_daily', 'day_ts'),
        ]:
            from_ts = now_ms - ms
            row = c.execute(f'SELECT MIN(rx_min), MAX(rx_max), MIN(tx_min), MAX(tx_max) FROM {table} WHERE {ts_col} >= ?', (from_ts,)).fetchone()
            if row and row[1] is not None:
                rx_bytes = max(0, (row[1] or 0) - (row[0] or 0))
                tx_bytes = max(0, (row[3] or 0) - (row[2] or 0))
                result['periods'][period] = {'rx_bytes': rx_bytes, 'tx_bytes': tx_bytes, 'total_bytes': rx_bytes + tx_bytes}
    except Exception as e:
        result['error'] = str(e)
    finally:
        conn.close()
print(json.dumps(result))
PY
;;

# ── Audit log ────────────────────────────────────────────────
"GET /api/audit/log")
  init_audit_db
  LIMIT_PARAM=$(printf '%s' "$QUERY" | grep -o 'limit=[^&]*' | cut -d= -f2)
  LIMIT="${LIMIT_PARAM:-100}"
  [[ ! "$LIMIT" =~ ^[0-9]+$ ]] && LIMIT=100
  [[ "$LIMIT" -gt 500 ]] && LIMIT=500
  json_header
  python3 - "$LIMIT" <<'PY' 2>/dev/null
import sqlite3, json, sys, os
db = '/etc/DaggerConnect/audit.db'
limit = int(sys.argv[1])
if not os.path.exists(db):
    print(json.dumps({'ok': True, 'entries': []})); exit()
conn = sqlite3.connect(db, timeout=3)
c = conn.cursor()
try:
    rows = c.execute('SELECT ts, action, target, detail, user FROM audit_log ORDER BY ts DESC LIMIT ?', (limit,)).fetchall()
    entries = [{'ts': r[0], 'action': r[1], 'target': r[2], 'detail': r[3], 'user': r[4]} for r in rows]
    print(json.dumps({'ok': True, 'entries': entries}))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
finally:
    conn.close()
PY
;;

# ── GeoIP lookup ─────────────────────────────────────────────
"GET /api/geoip")
  IP_PARAM=$(printf '%s' "$QUERY" | grep -o 'ip=[^&]*' | cut -d= -f2)
  if [[ -z "$IP_PARAM" ]]; then
    fail "ip parameter required"
  else
    RESULT=$(resolve_geoip "$IP_PARAM")
    [[ -z "$RESULT" ]] && RESULT="{\"ip\":\"$IP_PARAM\",\"country\":\"Unknown\"}"
    json_header
    printf '%s\n' "$RESULT"
  fi
;;

# ── GeoIP bulk for connections ────────────────────────────────
"POST /api/geoip/bulk")
  json_header
  python3 - <<'PY' 2>/dev/null
import sys, json, os, subprocess
try:
    import sys
    body = sys.stdin.read()
    ips = json.loads(body).get('ips', [])[:50]
    results = {}
    city_db = '/etc/DaggerConnect/GeoLite2-City.mmdb'
    asn_db  = '/etc/DaggerConnect/GeoLite2-ASN.mmdb'
    has_geoip2 = False
    try:
        import geoip2.database
        has_geoip2 = True
    except ImportError:
        pass
    for ip in ips:
        r = {'ip': ip, 'country': 'Unknown', 'city': '', 'asn': '', 'org': ''}
        if has_geoip2:
            try:
                if os.path.exists(city_db):
                    with geoip2.database.Reader(city_db) as reader:
                        resp = reader.city(ip)
                        r['country'] = resp.country.name or 'Unknown'
                        r['country_iso'] = resp.country.iso_code or ''
                        r['city'] = resp.city.name or ''
                if os.path.exists(asn_db):
                    with geoip2.database.Reader(asn_db) as reader:
                        resp = reader.asn(ip)
                        r['asn'] = 'AS' + str(resp.autonomous_system_number or 0)
                        r['org'] = resp.autonomous_system_organization or ''
            except Exception as e:
                r['error'] = str(e)
        results[ip] = r
    print(json.dumps({'ok': True, 'results': results}))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
PY
;;

# ── Live packet rate ──────────────────────────────────────────
"GET /api/network/packetrate")
  IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  if [[ -z "$IFACE" ]]; then
    json_header; printf '{"ok":false,"msg":"No interface found"}\n'; exit 0
  fi
  RX_PKT1=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
  TX_PKT1=$(cat /sys/class/net/$IFACE/statistics/tx_packets 2>/dev/null || echo 0)
  RX_ERR1=$(cat /sys/class/net/$IFACE/statistics/rx_errors 2>/dev/null || echo 0)
  TX_ERR1=$(cat /sys/class/net/$IFACE/statistics/tx_errors 2>/dev/null || echo 0)
  RX_DRP1=$(cat /sys/class/net/$IFACE/statistics/rx_dropped 2>/dev/null || echo 0)
  T1=$(date +%s%3N)
  sleep 1
  RX_PKT2=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
  TX_PKT2=$(cat /sys/class/net/$IFACE/statistics/tx_packets 2>/dev/null || echo 0)
  RX_ERR2=$(cat /sys/class/net/$IFACE/statistics/rx_errors 2>/dev/null || echo 0)
  TX_ERR2=$(cat /sys/class/net/$IFACE/statistics/tx_errors 2>/dev/null || echo 0)
  RX_DRP2=$(cat /sys/class/net/$IFACE/statistics/rx_dropped 2>/dev/null || echo 0)
  T2=$(date +%s%3N)
  ELAPSED=$(( T2 - T1 ))
  json_header
  printf '{"ok":true,"iface":"%s","rx_pps":%d,"tx_pps":%d,"rx_errors_ps":%d,"tx_errors_ps":%d,"rx_dropped_ps":%d,"elapsed_ms":%d}\n' \
    "$IFACE" "$(( RX_PKT2 - RX_PKT1 ))" "$(( TX_PKT2 - TX_PKT1 ))" \
    "$(( RX_ERR2 - RX_ERR1 ))" "$(( TX_ERR2 - TX_ERR1 ))" \
    "$(( RX_DRP2 - RX_DRP1 ))" "$ELAPSED"
;;

# ── MTU probe ────────────────────────────────────────────────
"POST /api/network/mtu_probe")
  TARGET_IP=$(printf '%s' "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('target','8.8.8.8'))" 2>/dev/null)
  CUSTOM_SIZE=$(printf '%s' "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); v=d.get('custom_size',0); print(int(v) if v else 0)" 2>/dev/null)
  TARGET_IP="${TARGET_IP:-8.8.8.8}"
  TARGET_IP=$(printf '%s' "$TARGET_IP" | tr -cd 'a-zA-Z0-9._-')
  CUSTOM_SIZE="${CUSTOM_SIZE:-0}"
  json_header
  python3 - "$TARGET_IP" "$CUSTOM_SIZE" <<'PY' 2>/dev/null
import sys, subprocess, json
target = sys.argv[1]
custom_size = int(sys.argv[2]) if sys.argv[2] != '0' else 0
results = {}
if custom_size and 576 <= custom_size <= 9000:
    sizes = [custom_size]
else:
    sizes = [1500, 1492, 1480, 1450, 1400, 1350, 1280]
for size in sizes:
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '2', '-M', 'do', '-s', str(size - 28), target],
            capture_output=True, text=True, timeout=5
        )
        results[size] = r.returncode == 0
    except Exception:
        results[size] = False
max_mtu = max((s for s, ok in results.items() if ok), default=None)
print(json.dumps({'ok': True, 'target': target, 'probe_results': results, 'max_mtu': max_mtu, 'custom_size': custom_size or None}))
PY
;;

# ── Scheduled restart ────────────────────────────────────────
"POST /api/service/schedule_restart")
  SR_DATA=$(printf '%s' "$BODY" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('service','server'), d.get('delay_seconds','60'), d.get('reason','scheduled'))
except: print('server 60 scheduled')
" 2>/dev/null)
  SR_SVC=$(echo "$SR_DATA" | awk '{print $1}')
  SR_DELAY=$(echo "$SR_DATA" | awk '{print $2}')
  SR_REASON=$(echo "$SR_DATA" | awk '{$1=$2=""; print substr($0,3)}')
  [[ ! "$SR_DELAY" =~ ^[0-9]+$ ]] && SR_DELAY=60
  [[ "$SR_DELAY" -gt 86400 ]] && SR_DELAY=86400
  [[ "$SR_DELAY" -lt 1 ]] && SR_DELAY=1
  [[ -z "$SR_REASON" ]] && SR_REASON="scheduled"
  case "$SR_SVC" in
    server) SR_UNIT="DaggerConnect-server" ;;
    client) SR_UNIT="DaggerConnect-client" ;;
    *)      fail "Unknown service"; exit 0 ;;
  esac
  # Generate job ID and store in schedule DB
  JOB_ID=$(openssl rand -hex 8 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 16)
  JOB_ID="${JOB_ID:-$(date +%s%N | sha256sum | head -c 16)}"
  FIRE_AT=$(( $(date +%s) + SR_DELAY ))
  init_schedule_db 2>/dev/null
  python3 - "$JOB_ID" "$SR_SVC" "$FIRE_AT" "$SR_DELAY" "$SR_REASON" <<'PY' 2>/dev/null
import sqlite3, sys, time
job_id, svc, fire_at, delay, reason = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
db = '/etc/DaggerConnect/schedule.db'
conn = sqlite3.connect(db, timeout=5)
conn.execute('INSERT OR REPLACE INTO scheduled_restarts (id,service,fire_at,delay_seconds,reason,created_ts,status) VALUES (?,?,?,?,?,?,?)',
    (job_id, svc, fire_at*1000, delay, reason, int(time.time()*1000), 'pending'))
conn.commit(); conn.close()
PY
  # Background recurring loop: sleep, check status, restart, reschedule
  ( while true; do
      sleep "$SR_DELAY"
      STATUS=$(python3 -c "
import sqlite3
db='/etc/DaggerConnect/schedule.db'
try:
    conn=sqlite3.connect(db,timeout=3)
    row=conn.execute('SELECT status FROM scheduled_restarts WHERE id=?',('$JOB_ID',)).fetchone()
    conn.close()
    print(row[0] if row else 'missing')
except: print('error')
" 2>/dev/null)
      if [[ "$STATUS" == "pending" ]]; then
        systemctl restart "$SR_UNIT" 2>/dev/null
        record_audit "scheduled_restart" "$SR_SVC" "delay=${SR_DELAY}s reason=$SR_REASON"
        NEXT_FIRE=$(( $(date +%s) + SR_DELAY ))
        python3 - "$JOB_ID" "$NEXT_FIRE" <<'PY' 2>/dev/null
import sqlite3, sys
db='/etc/DaggerConnect/schedule.db'
job_id = sys.argv[1]
next_fire_at = int(sys.argv[2]) * 1000
conn=sqlite3.connect(db,timeout=3)
conn.execute("UPDATE scheduled_restarts SET fire_at=? WHERE id=?",(next_fire_at, job_id))
conn.commit(); conn.close()
PY
      else
        break
      fi
    done
  ) &
  record_audit "schedule_restart" "$SR_SVC" "job=$JOB_ID scheduled in ${SR_DELAY}s: $SR_REASON"
  json_header
  printf '{"ok":true,"msg":"Restart of %s scheduled in %d seconds","service":"%s","delay":%d,"job_id":"%s","fire_at":%d}\n' \
    "$SR_UNIT" "$SR_DELAY" "$SR_SVC" "$SR_DELAY" "$JOB_ID" "$FIRE_AT"
;;

# ── List pending scheduled restarts ──────────────────────────
"GET /api/service/scheduled_restarts")
  SVC_PARAM=$(printf '%s' "$QUERY" | grep -o 'service=[^&]*' | cut -d= -f2)
  init_schedule_db 2>/dev/null
  json_header
  python3 - "$SVC_PARAM" <<'PY' 2>/dev/null
import sqlite3, json, time, sys
svc = sys.argv[1]
db = '/etc/DaggerConnect/schedule.db'
now_ms = int(time.time() * 1000)
conn = sqlite3.connect(db, timeout=3)
c = conn.cursor()
# Auto-expire done/old jobs
c.execute("DELETE FROM scheduled_restarts WHERE status='done' AND created_ts < ?", (now_ms - 86400000,))
conn.commit()
if svc:
    rows = c.execute("SELECT id, service, fire_at, delay_seconds, reason, created_ts, status FROM scheduled_restarts WHERE service=? AND status='pending' ORDER BY fire_at ASC", (svc,)).fetchall()
else:
    rows = c.execute("SELECT id, service, fire_at, delay_seconds, reason, created_ts, status FROM scheduled_restarts WHERE status='pending' ORDER BY fire_at ASC").fetchall()
conn.close()
schedules = [{'id':r[0],'service':r[1],'fire_at':r[2]//1000,'delay_seconds':r[3],'reason':r[4],'created_ts':r[5],'status':r[6]} for r in rows]
print(json.dumps({'ok': True, 'schedules': schedules}))
PY
;;

# ── Cancel a scheduled restart ────────────────────────────────
"POST /api/service/cancel_restart")
  JOB_ID_CANCEL=$(printf '%s' "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null)
  if [[ -z "$JOB_ID_CANCEL" ]]; then
    fail "job_id required"
    exit 0
  fi
  JOB_ID_CANCEL=$(printf '%s' "$JOB_ID_CANCEL" | tr -cd 'a-fA-F0-9-')
  init_schedule_db 2>/dev/null
  CANCEL_RESULT=$(python3 - "$JOB_ID_CANCEL" <<'PY' 2>/dev/null
import sqlite3, sys, json
job_id = sys.argv[1]
db = '/etc/DaggerConnect/schedule.db'
conn = sqlite3.connect(db, timeout=5)
row = conn.execute("SELECT service, reason FROM scheduled_restarts WHERE id=? AND status='pending'", (job_id,)).fetchone()
if row:
    conn.execute("UPDATE scheduled_restarts SET status='cancelled' WHERE id=?", (job_id,))
    conn.commit(); conn.close()
    print(json.dumps({'ok': True, 'msg': 'Cancelled scheduled restart for ' + row[0], 'service': row[0]}))
else:
    conn.close()
    print(json.dumps({'ok': False, 'msg': 'Job not found or already completed'}))
PY
)
  [[ -z "$CANCEL_RESULT" ]] && CANCEL_RESULT='{"ok":false,"msg":"cancel failed"}'
  SVC_CANCELLED=$(printf '%s' "$CANCEL_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('service',''))" 2>/dev/null)
  [[ -n "$SVC_CANCELLED" ]] && record_audit "cancel_restart" "$SVC_CANCELLED" "job=$JOB_ID_CANCEL"
  json_header
  printf '%s\n' "$CANCEL_RESULT"
;;

# ── Panel health self-check ───────────────────────────────────
"GET /api/health/panel")
  HEALTH_ROLE=$(tr -d '[:space:]' < "$ROLE_FILE" 2>/dev/null)
  [[ "$HEALTH_ROLE" != "server" && "$HEALTH_ROLE" != "client" ]] && HEALTH_ROLE="unknown"
  json_header
  python3 - "$HEALTH_ROLE" <<'PY' 2>/dev/null
import json, os, time, sqlite3, subprocess, sys
role = sys.argv[1]  # "server", "client", or "unknown"
checks = {}
config_dir = '/etc/DaggerConnect'
now_ms = int(time.time() * 1000)

# ── Services (only check the relevant one for this node's role) ──
active_svc  = 'DaggerConnect-' + role if role in ('server','client') else None
active_key  = role if role in ('server','client') else 'server'
if active_svc:
    try:
        r = subprocess.run(['systemctl','is-active', active_svc], capture_output=True, text=True, timeout=3)
        checks[active_key + '_running'] = r.stdout.strip() == 'active'
    except Exception:
        checks[active_key + '_running'] = False
    try:
        r2 = subprocess.run(['systemctl','is-enabled', active_svc], capture_output=True, text=True, timeout=3)
        checks[active_key + '_enabled'] = r2.stdout.strip() == 'enabled'
    except Exception:
        checks[active_key + '_enabled'] = False

# ── Config (only check relevant config file) ──────────────────
import yaml
target = role if role in ('server','client') else 'server'
fpath = config_dir + '/' + target + '.yaml'
checks[target + '_config_exists'] = os.path.isfile(fpath)
if checks[target + '_config_exists']:
    try:
        with open(fpath) as f:
            parsed = yaml.safe_load(f.read())
        checks[target + '_config_ok'] = isinstance(parsed, dict) and 'mode' in parsed
    except Exception:
        checks[target + '_config_ok'] = False
else:
    checks[target + '_config_ok'] = False

checks['config_dir_ok'] = os.path.isdir(config_dir)
checks['metrics_db'] = os.path.isfile(config_dir + '/metrics.db')

# ── Metrics freshness ─────────────────────────────────────────
if os.path.isfile(config_dir + '/metrics.db'):
    try:
        conn = sqlite3.connect(config_dir + '/metrics.db', timeout=2)
        c = conn.cursor()
        row = c.execute('SELECT ts FROM metrics_raw ORDER BY ts DESC LIMIT 1').fetchone()
        conn.close()
        age_ms = (now_ms - row[0]) if row else -1
        checks['metrics_fresh'] = row is not None and age_ms < 30000
        checks['last_metric_age_ms'] = age_ms
    except Exception:
        checks['metrics_fresh'] = False
else:
    checks['metrics_fresh'] = False

# ── System ────────────────────────────────────────────────────
try:
    disk = os.statvfs(config_dir)
    free_gb = round((disk.f_bavail * disk.f_frsize) / (1024**3), 2)
    checks['disk_free_gb'] = free_gb
    checks['disk_ok'] = free_gb > 0.05
except Exception:
    checks['disk_free_gb'] = 0; checks['disk_ok'] = False

try:
    with open('/proc/meminfo') as f:
        mem = {}
        for line in f:
            k, v = line.split(':')
            mem[k.strip()] = int(v.split()[0])
    free_mb = (mem.get('MemAvailable', mem.get('MemFree', 0))) // 1024
    checks['mem_free_mb'] = free_mb
    checks['mem_ok'] = free_mb > 64
except Exception:
    checks['mem_free_mb'] = 0; checks['mem_ok'] = False

try:
    with open('/proc/stat') as f:
        fields = f.readline().split()
    idle = int(fields[4]); total_j = sum(int(x) for x in fields[1:])
    time.sleep(0.2)
    with open('/proc/stat') as f:
        fields2 = f.readline().split()
    idle2 = int(fields2[4]); total2 = sum(int(x) for x in fields2[1:])
    dt = total2 - total_j; di = idle2 - idle
    cpu_pct = round(100 * (dt - di) / dt, 1) if dt > 0 else 0
    checks['cpu_pct'] = cpu_pct
    checks['cpu_ok'] = cpu_pct < 95
except Exception:
    checks['cpu_pct'] = 0; checks['cpu_ok'] = True

try:
    with open('/proc/uptime') as f:
        checks['uptime_s'] = int(float(f.read().split()[0]))
except Exception:
    checks['uptime_s'] = 0

all_ok = all(v for k, v in checks.items() if isinstance(v, bool))
print(json.dumps({'ok': True, 'healthy': all_ok, 'checks': checks, 'ts': now_ms}))
PY
;;

# ── Quota alarm dismiss is above. Canary DB and bandwidth budget removed (features removed from panel) ──

# ── Quota config ─────────────────────────────────────────────
"GET /api/quota/config")
  init_quota_db
  json_header
  python3 - <<'PY' 2>/dev/null
import sqlite3, json, os, time
db = '/etc/DaggerConnect/quota.db'
conn = sqlite3.connect(db, timeout=3)
c = conn.cursor()
rows = c.execute('SELECT key, value FROM quota_config').fetchall()
cfg = {r[0]: r[1] for r in rows}
events = c.execute('SELECT ts, event, detail FROM quota_events ORDER BY ts DESC LIMIT 20').fetchall()
# Expose latest unacknowledged breach as alarm
# An alarm is active if the most recent quota_breach_restart has no subsequent alarm_dismissed
alarm_row = c.execute(
    "SELECT ts, event, detail FROM quota_events WHERE event IN ('quota_breach_restart','alarm_dismissed') ORDER BY ts DESC LIMIT 1"
).fetchone()
conn.close()
evlist = [{'ts':r[0],'event':r[1],'detail':r[2]} for r in events]
alarm = None
if alarm_row and alarm_row[1] == 'quota_breach_restart':
    try:
        d = json.loads(alarm_row[2])
        svc_short = d.get('svc','').replace('DaggerConnect-','')
        breach_type = 'cpu' if float(d.get('cpu',0)) > float(d.get('max_cpu',100)) else 'mem'
        value = d.get('cpu',0) if breach_type == 'cpu' else d.get('mem',0)
        alarm = {'ts': alarm_row[0], 'service': svc_short, 'type': breach_type, 'value': value}
    except Exception:
        pass
print(json.dumps({'ok': True, 'config': cfg, 'events': evlist, 'alarm': alarm}))
PY
;;

"POST /api/quota/config")
  init_quota_db
  TMP_QC=$(mktemp)
  printf '%s' "$BODY" > "$TMP_QC"
  QUOTA_RESULT=$(python3 - "$TMP_QC" 2>/dev/null <<'PY'
import sqlite3, json, sys
try:
    d = json.loads(open(sys.argv[1]).read())
    db = '/etc/DaggerConnect/quota.db'
    conn = sqlite3.connect(db, timeout=5)
    c = conn.cursor()
    for key in ['max_cpu_pct', 'max_mem_mb', 'enabled']:
        if key in d:
            c.execute('INSERT OR REPLACE INTO quota_config (key, value) VALUES (?,?)', (key, str(d[key])))
    conn.commit(); conn.close()
    print(json.dumps({'ok': True, 'msg': 'Quota config saved'}))
except Exception as e:
    print(json.dumps({'ok': False, 'msg': str(e)}))
PY
)
  rm -f "$TMP_QC"
  [[ -z "$QUOTA_RESULT" ]] && QUOTA_RESULT='{"ok":false,"msg":"save failed"}'
  json_header
  printf '%s\n' "$QUOTA_RESULT"
;;

# (heatmap endpoint removed — feature removed from panel)

# ── Side-by-side config view removed — use /api/config/backup_content instead ──

# ── PSK generator ────────────────────────────────────────────
"GET /api/psk/generate")
  PSK_LEN=$(printf '%s' "$QUERY" | grep -o 'len=[^&]*' | cut -d= -f2)
  [[ ! "$PSK_LEN" =~ ^[0-9]+$ ]] && PSK_LEN=32
  [[ "$PSK_LEN" -gt 64 ]] && PSK_LEN=64
  [[ "$PSK_LEN" -lt 8 ]] && PSK_LEN=8
  PSK=$(openssl rand -hex "$PSK_LEN" 2>/dev/null | tr -d '\n')
  [[ -z "$PSK" ]] && PSK=$(head -c "$PSK_LEN" /dev/urandom | xxd -p | tr -d '\n' | head -c $(( PSK_LEN * 2 )))
  json_header
  printf '{"ok":true,"psk":"%s","length":%d}\n' "$PSK" "${#PSK}"
;;

# ── Config backup content preview ────────────────────────────
"GET /api/config/backup_content")
  BACKUP_PATH_RAW=$(printf '%s' "$QUERY" | grep -o 'path=[^&]*' | cut -d= -f2-)
  BACKUP_PATH=$(python3 -c "import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))" "$BACKUP_PATH_RAW" 2>/dev/null)
  # Security: must be inside /etc/DaggerConnect and be a .bak. file
  case "$BACKUP_PATH" in
    /etc/DaggerConnect/*.bak.*) : ;;  # ok
    *) fail "Invalid or missing backup path"; exit 0 ;;
  esac
  if [[ ! -f "$BACKUP_PATH" ]]; then
    fail "Backup file not found"
    exit 0
  fi
  CONTENT=$(escape_multiline < "$BACKUP_PATH")
  json_header
  printf '{"ok":true,"path":"%s","content":"%s"}\n' "$(json_escape "$BACKUP_PATH")" "$CONTENT"
;;

# ── Config read (alias for GET /api/config, used by MTU apply) ─
"GET /api/config/read")
  TARGET=$(printf '%s' "$QUERY" | grep -o 'target=[^&]*' | cut -d= -f2)
  case "$TARGET" in
    client) FILE="$CLIENT_YAML" ;;
    *)      FILE="$SERVER_YAML" ;;
  esac
  if [[ ! -f "$FILE" ]]; then
    fail "Config not found: $FILE"
  else
    CONTENT=$(escape_multiline < "$FILE")
    json_header
    printf '{"ok":true,"file":"%s","content":"%s"}\n' "$FILE" "$CONTENT"
  fi
;;

# ── Quota alarm dismiss ───────────────────────────────────────
"POST /api/quota/clear_alarm")
  init_quota_db
  python3 - <<'PY' 2>/dev/null
import sqlite3, time, json
db = '/etc/DaggerConnect/quota.db'
conn = sqlite3.connect(db, timeout=5)
ts = int(time.time() * 1000)
conn.execute('INSERT INTO quota_events (ts, event, detail) VALUES (?,?,?)', (ts, 'alarm_dismissed', 'dismissed via panel'))
conn.commit(); conn.close()
PY
  ok "Alarm dismissed"
;;

# ── Token / auth management ───────────────────────────────────
"POST /api/auth/set_token")
  NEW_TOKEN_VAL=$(printf '%s' "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
  if [[ -z "$NEW_TOKEN_VAL" ]]; then
    fail "Token is required"
  else
    printf '%s' "$NEW_TOKEN_VAL" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    record_audit "token_changed" "panel.token" "Token updated via API"
    ok "Token updated. Re-login required."
  fi
;;

"POST /api/auth/clear_token")
  rm -f "$TOKEN_FILE"
  record_audit "token_cleared" "panel.token" "Auth token removed"
  ok "Token cleared. Panel is now unauthenticated."
;;

"GET /api/auth/status")
  json_header
  if [[ -n "$EXPECTED_TOKEN" ]]; then
    printf '{"ok":true,"auth_enabled":true,"token_set":true}\n'
  else
    printf '{"ok":true,"auth_enabled":false,"token_set":false}\n'
  fi
;;

*)
  err_404 "$ROUTE"
;;

esac