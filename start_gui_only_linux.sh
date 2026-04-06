#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

NO_BROWSER="${NO_BROWSER:-0}" \
CONTROL_API_COMMAND="" \
bash "$SCRIPT_DIR/start_all_linux.sh"
