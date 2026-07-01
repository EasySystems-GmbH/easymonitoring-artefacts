#!/usr/bin/env bash
# Compatibility shim — canonical: ../unix-monitor/deploy/agent-installation/install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec bash "${ROOT}/unix-monitor/deploy/agent-installation/install.sh" "$@"
