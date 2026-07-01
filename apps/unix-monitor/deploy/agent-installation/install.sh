#!/bin/bash
# Rollout agent install — same flow as full edition, agent role locked (no standalone/master).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export UNIX_MONITOR_ROLLOUT_AGENT=1
export SCRIPT_NAME="${SCRIPT_NAME:-unix-monitor-agent.py}"
export DEFAULT_INSTALL_DIR="${DEFAULT_INSTALL_DIR:-/opt/unix-rollout-agent}"
export SCRIPT_REMOTE_PATH="${SCRIPT_REMOTE_PATH:-apps/unix-monitor/deploy/agent-installation/${SCRIPT_NAME}}"
exec bash "${ROOT}/../full-version/install.sh" "$@"
