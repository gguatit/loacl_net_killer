#!/usr/bin/env bash
set -euo pipefail

# One-click launcher for Linux/NetHunter:
# 1) Create venv if missing
# 2) Install/upgrade dependencies
# 3) Optionally start external control API
# 4) Start Flask web server

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$PROJECT_DIR/.venv}"
REQ_FILE="${REQ_FILE:-$PROJECT_DIR/requirements.txt}"
APP_FILE="${APP_FILE:-$PROJECT_DIR/app.py}"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-5000}"

echo "========================================"
echo " Network Device Controller (Linux)"
echo " One-click setup + run"
echo "========================================"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] $PYTHON_BIN not found. Install python3 first."
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "[1/5] Creating virtual environment: $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
else
  echo "[1/5] Virtual environment exists: $VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"

echo "[2/5] Upgrading pip"
python -m pip install --upgrade pip

if [ -f "$REQ_FILE" ]; then
  echo "[3/5] Installing dependencies from requirements.txt"
  pip install -r "$REQ_FILE"
else
  echo "[3/5] requirements.txt missing, installing minimum packages"
  pip install Flask zeroconf
fi

if [ -n "${CONTROL_API_COMMAND:-}" ]; then
  echo "[4/5] Starting external control API"
  nohup bash -lc "$CONTROL_API_COMMAND" >/tmp/control_api.log 2>&1 &
  echo "      Control API log: /tmp/control_api.log"
else
  echo "[4/5] CONTROL_API_COMMAND not set, skipping external control API"
  echo "      (GUI runs, but real network control may be unavailable)"
fi

echo "[5/5] Starting web server"
export FLASK_ENV="${FLASK_ENV:-development}"
export FLASK_RUN_HOST="$HOST"
export FLASK_RUN_PORT="$PORT"

# Launch browser if available and not disabled
if [ "${NO_BROWSER:-0}" != "1" ]; then
  if command -v xdg-open >/dev/null 2>&1; then
    (sleep 1; xdg-open "http://localhost:$PORT" >/dev/null 2>&1 || true) &
  fi
fi

exec python "$APP_FILE"
