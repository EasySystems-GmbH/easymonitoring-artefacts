#!/usr/bin/env bash
# Compatibility shim — canonical: ../synology-monitor/deploy/agent-installation/build-spk.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec bash "${ROOT}/synology-monitor/deploy/agent-installation/build-spk.sh" "$@"
