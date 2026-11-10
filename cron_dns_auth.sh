#!/usr/bin/env bash
# Compatible con cron Linux/DirectAdmin. Ajusta PYTHON_BIN si usas un virtualenv de panel.
set -euo pipefail
APP="${APP_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
PYTHON="${PYTHON_BIN:-${APP}/.venv/bin/python}"
cd "$APP"
exec 9>"$APP/cron_dns_auth.lock"
flock -n 9 || exit 0
exec "$PYTHON" "$APP/robot_dns_auth.py"
