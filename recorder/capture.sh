#!/bin/bash
# Start/stop mitmproxy traffic capture from any directory.
#
#   capture.sh start          start mitmdump + recorder addon, enable macOS system proxy
#   capture.sh start --no-proxy   start capture only (for curl -x / per-app proxy use)
#   capture.sh start --phone  proxy a phone: listen on LAN, skip system proxy
#   capture.sh start --wireguard  full-device phone capture via WireGuard tunnel
#   capture.sh stop           disable system proxy, stop mitmdump
#   capture.sh status         show capture + proxy state
#
# Database: /Users/sion/projects/mitmproxy/recorder/traffic.db
# Query via Claude Code: the "traffic-recorder" MCP server (user scope) reads it.

set -euo pipefail

PROJECT=/Users/sion/projects/mitmproxy
PORT=8080
PIDFILE=/tmp/traffic_recorder_mitmdump.pid
LOG=/tmp/traffic_recorder_mitmdump.log
NETWORK_SERVICE="Wi-Fi"

is_running() {
  [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

start() {
  local mode="${1:-}"
  case "$mode" in
    --wireguard) start_wireguard; return ;;
  esac

  local listen_host=127.0.0.1
  local set_system_proxy=1
  case "$mode" in
    --no-proxy) set_system_proxy=0 ;;
    --phone) listen_host=0.0.0.0; set_system_proxy=0 ;;
  esac

  if is_running; then
    echo "already running (pid $(cat "$PIDFILE"))"
  else
    nohup uv run --project "$PROJECT" mitmdump \
      -p "$PORT" --listen-host "$listen_host" \
      -s "$PROJECT/recorder/traffic_recorder.py" \
      >"$LOG" 2>&1 &
    echo $! >"$PIDFILE"
    sleep 5
    if is_running; then
      echo "mitmdump started (pid $(cat "$PIDFILE"), listening on $listen_host:$PORT, log: $LOG)"
    else
      echo "failed to start, see $LOG" >&2
      exit 1
    fi
  fi
  if [[ "$set_system_proxy" == "1" ]]; then
    networksetup -setwebproxy "$NETWORK_SERVICE" 127.0.0.1 "$PORT" >/dev/null
    networksetup -setsecurewebproxy "$NETWORK_SERVICE" 127.0.0.1 "$PORT" >/dev/null
    echo "system proxy enabled ($NETWORK_SERVICE -> 127.0.0.1:$PORT)"
  else
    echo "system proxy untouched"
  fi
  if [[ "$listen_host" == "0.0.0.0" ]]; then
    local ip
    ip=$(ipconfig getifaddr en0 2>/dev/null || echo "<Mac 的局域网 IP>")
    echo ""
    echo "==> 手机设置：Wi-Fi 代理 -> 手动 -> 服务器 $ip 端口 $PORT"
    echo "==> 手机首次使用：代理生效后用浏览器访问 http://mitm.it 安装 CA 证书"
  fi
}

start_wireguard() {
  if is_running; then
    echo "already running (pid $(cat "$PIDFILE"))"
    return
  fi
  # Do NOT pass -p here: it becomes the default port for every mode,
  # so WireGuard would grab 8080 and the regular proxy would never start.
  PYTHONUNBUFFERED=1 nohup uv run --project "$PROJECT" mitmweb \
    --mode regular --mode wireguard \
    -s "$PROJECT/recorder/traffic_recorder.py" \
    >"$LOG" 2>&1 &
  echo $! >"$PIDFILE"
  sleep 8
  if ! is_running; then
    echo "failed to start, see $LOG" >&2
    exit 1
  fi
  local ip
  ip=$(ipconfig getifaddr en0 2>/dev/null || echo "<Mac 的局域网 IP>")
  echo "mitmweb started (pid $(cat "$PIDFILE"), regular :$PORT, wireguard :51820, log: $LOG)"
  echo "web ui: $(grep -o 'http://127.0.0.1:8081/?token=[a-f0-9]*' "$LOG" | head -1)"
  echo ""
  echo "==> 手机设置：关闭 Wi-Fi 手动代理（与 WireGuard 模式互斥）"
  echo "==> 手机 WireGuard App 扫描 Web UI 里的二维码导入隧道"
  echo "==> 导入后手动把 Endpoint 改成 $ip:51820（开了 VPN 时扫码自带的是错的隧道 IP）"
}

stop() {
  networksetup -setwebproxystate "$NETWORK_SERVICE" off >/dev/null
  networksetup -setsecurewebproxystate "$NETWORK_SERVICE" off >/dev/null
  echo "system proxy disabled ($NETWORK_SERVICE)"
  if is_running; then
    kill "$(cat "$PIDFILE")"
    rm -f "$PIDFILE"
    echo "mitmdump stopped"
  else
    rm -f "$PIDFILE"
    echo "mitmdump was not running"
  fi
}

status() {
  if is_running; then
    echo "capture: running (pid $(cat "$PIDFILE"), port $PORT)"
  else
    echo "capture: stopped"
  fi
  echo "system proxy: $(networksetup -getwebproxy "$NETWORK_SERVICE" | head -1)"
  if [[ -f "$PROJECT/recorder/traffic.db" ]]; then
    echo "database: $PROJECT/recorder/traffic.db ($(du -h "$PROJECT/recorder/traffic.db" | cut -f1), $(sqlite3 "$PROJECT/recorder/traffic.db" 'SELECT count(*) FROM flows' 2>/dev/null || echo '?') flows)"
  else
    echo "database: not created yet"
  fi
}

case "${1:-}" in
  start) start "${2:-}" ;;
  stop) stop ;;
  status) status ;;
  *) echo "usage: $0 {start [--no-proxy|--phone|--wireguard]|stop|status}" >&2; exit 1 ;;
esac
