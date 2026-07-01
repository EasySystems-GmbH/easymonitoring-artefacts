#!/usr/bin/env bash
# Compatibility entry — canonical: deploy/full-version/community-package/build-spk.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec bash "${ROOT}/deploy/full-version/community-package/build-spk.sh" "$@"
