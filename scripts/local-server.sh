#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
label="fund.mithril.flame-sword.local"

case "${1:-start}" in
  start)
    if launchctl list "$label" >/dev/null 2>&1; then
      echo "Flame Sword is already registered. Use restart to reload .env."
      exit 0
    fi
    mkdir -p "$root/.local"
    launchctl submit -l "$label" -o "$root/.local/server.log" \
      -e "$root/.local/server-error.log" -- "$root/.venv/bin/python" "$root/app.py"
    echo "Flame Sword started. Default URL: http://127.0.0.1:5055"
    ;;
  stop)
    launchctl remove "$label"
    echo "Flame Sword stopped."
    ;;
  restart)
    if launchctl list "$label" >/dev/null 2>&1; then
      launchctl remove "$label"
    fi
    exec "$0" start
    ;;
  status)
    launchctl list "$label"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}" >&2
    exit 2
    ;;
esac
