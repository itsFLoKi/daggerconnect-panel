#!/bin/bash
# ============================================================
# DaggerConnect Panel — API Handler (socat backend)
# Fixed: connections (role-aware, multi-port, real states),
#        network speed accuracy, YAML parsing via python3,
#        timing-safe auth, config backup rotation, journalctl
#        timeout, openssl CN injection, iptables persist warn,
#        PSK hex encoding, validate endpoint added.
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
METRICS_FILE="/etc/DaggerConnect/metrics.jsonl"
METRICS_MAX_LINES=2880  # 4 hours at 5s poll = 2880 points

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

# Parse all listener ports from server.yaml via python3
get_server_ports() {
  python3 - <<'PY' 2>/dev/null
import yaml
try:
    with open('/etc/DaggerConnect/server.yaml') as f:
        data = yaml.safe_load(f) or {}
    for l in data.get('listeners', []):
        addr = l.get('addr', '')
        if ':' in addr:
            p = addr.rsplit(':', 1)[-1]
            if p.isdigit():
                print(p)
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

# ── Read HTTP request from stdin ─────────────────────────────

read -r REQUEST_LINE
METHOD=$(printf '%s' "$REQUEST_LINE" | awk '{print $1}')
PATH_RAW=$(printf '%s' "$REQUEST_LINE" | awk '{print $2}')
ROUTE=$(printf '%s' "$PATH_RAW" | cut -d'?' -f1)
QUERY=$(printf '%s' "$PATH_RAW" | grep -o '?.*' | cut -c2-)

CONTENT_LENGTH=0
AUTH_TOKEN=""
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

  SRV_CPU=0; SRV_MEM=0; CLI_CPU=0; CLI_MEM=0; SRV_UPTIME=""
  if [[ "$SRV_PID" -gt 1 ]]; then
    read -r SRV_CPU SRV_MEM < <(ps -p "$SRV_PID" -o %cpu,rss --no-headers 2>/dev/null \
      | awk '{printf "%.1f %d", $1, int($2/1024)}')
    SRV_UPTIME=$(ps -p "$SRV_PID" -o etime= --no-headers 2>/dev/null | xargs)
  fi
  if [[ "$CLI_PID" -gt 1 ]]; then
    read -r CLI_CPU CLI_MEM < <(ps -p "$CLI_PID" -o %cpu,rss --no-headers 2>/dev/null \
      | awk '{printf "%.1f %d", $1, int($2/1024)}')
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
  "server":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d,"uptime":"%s","connections":%d},
  "client":{"state":"%s","pid":%d,"cpu":"%s","mem_mb":%d},
  "system":{"cpu_pct":%d,"ram_used_mb":%d,"ram_total_mb":%d,"rx_bytes":%d,"tx_bytes":%d,"iface":"%s","snap_ts":%d}
}\n' \
    "$SRV_STATE" "${SRV_PID:-0}" "${SRV_CPU:-0}" "${SRV_MEM:-0}" "$SRV_UPTIME" "$CONNS" \
    "$CLI_STATE" "${CLI_PID:-0}" "${CLI_CPU:-0}" "${CLI_MEM:-0}" \
    "$SYS_CPU" "${USED:-0}" "${TOTAL:-1}" "$RX" "$TX" "${IFACE:-eth0}" "$SNAP_TS"

  # ── Append to rolling metrics log ──────────────────────────
  RAM_PCT=0
  [[ "${TOTAL:-0}" -gt 0 ]] && RAM_PCT=$(( 100 * ${USED:-0} / ${TOTAL} ))
  METRIC_LINE="{\"ts\":${SNAP_TS},\"cpu\":${SYS_CPU},\"ram\":${RAM_PCT},\"ram_mb\":${USED:-0},\"rx\":${RX},\"tx\":${TX},\"conns\":${CONNS},\"srv_cpu\":\"${SRV_CPU:-0}\",\"srv_mem\":${SRV_MEM:-0}}"
  mkdir -p "$(dirname "$METRICS_FILE")" 2>/dev/null
  printf '%s\n' "$METRIC_LINE" >> "$METRICS_FILE" 2>/dev/null
  # Trim to last METRICS_MAX_LINES lines (avoid unbounded growth)
  if [[ -f "$METRICS_FILE" ]]; then
    LINE_COUNT=$(wc -l < "$METRICS_FILE" 2>/dev/null || echo 0)
    if [[ "$LINE_COUNT" -gt "$METRICS_MAX_LINES" ]]; then
      TRIM=$(mktemp)
      tail -n "$METRICS_MAX_LINES" "$METRICS_FILE" > "$TRIM" && mv "$TRIM" "$METRICS_FILE" 2>/dev/null
    fi
  fi
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
    && ok "Saved to $FILE (backup created)" \
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

# ── PSK generate — hex avoids base64 URL-unsafe chars ────────
"POST /api/psk/generate")
  PSK=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p | tr -d '\n')
  json_header
  printf '{"ok":true,"psk":"%s"}\n' "$PSK"
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
      while read -r state _ local remote _; do
        [[ -z "$local" ]] && continue
        ENTRIES+=("{\"local\":\"$local\",\"remote\":\"$remote\",\"state\":\"$state\",\"port\":$PORT}")
      done < <(ss -tn "dport = :$PORT" 2>/dev/null | tail -n +2)
    done < <(get_client_ports)
  else
    NOTE="inbound on listeners"
    while IFS= read -r PORT; do
      [[ -z "$PORT" ]] && continue
      PORTS_SEEN+=("$PORT")
      while read -r state _ local remote _; do
        [[ -z "$local" ]] && continue
        ENTRIES+=("{\"local\":\"$local\",\"remote\":\"$remote\",\"state\":\"$state\",\"port\":$PORT}")
      done < <(ss -tn "sport = :$PORT" 2>/dev/null | tail -n +2)
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

# ── Metrics history ──────────────────────────────────────────
"GET /api/metrics/history")
  # ?points=N  — how many most-recent points to return (default 720 = 1hr at 5s)
  POINTS_PARAM=$(printf '%s' "$QUERY" | grep -o 'points=[^&]*' | cut -d= -f2)
  POINTS="${POINTS_PARAM:-720}"
  [[ ! "$POINTS" =~ ^[0-9]+$ ]] && POINTS=720
  [[ "$POINTS" -gt "$METRICS_MAX_LINES" ]] && POINTS="$METRICS_MAX_LINES"
  [[ "$POINTS" -lt 1 ]] && POINTS=1

  json_header
  printf '{"ok":true,"points":['
  FIRST=1
  if [[ -f "$METRICS_FILE" ]]; then
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$FIRST" -eq 1 ]] && FIRST=0 || printf ','
      printf '%s' "$line"
    done < <(tail -n "$POINTS" "$METRICS_FILE" 2>/dev/null)
  fi
  printf ']}\n'
;;

*)
  err_404 "$ROUTE"
;;

esac