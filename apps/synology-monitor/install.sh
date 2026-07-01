#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
exec bash "${ROOT}/deploy/full-version/install.sh" "$@"
