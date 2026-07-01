#!/usr/bin/env bash
# Build rollout-agent distribution artifacts (unix script, synology SPK, docker image, windows publish).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
# easymonitoring apps/ sibling (unix-monitor, synology-monitor, windows-monitor)
APPS_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
VERSION="${ROLLOUT_VERSION:-1.12.0-rollout.1}"

echo "==> Patching rollout-agent sources (${VERSION})"
python3 "${ROOT_DIR}/scripts/patch-source.py" --version "${VERSION}" --root "${ROOT_DIR}"

echo "==> Building Docker image (unix rollout agent)"
"${ROOT_DIR}/docker/build-image.sh" "${VERSION}"

if [[ "${SKIP_SYNOLOGY:-0}" != "1" ]]; then
  echo "==> Building Synology rollout SPK"
  "${ROOT_DIR}/synology/build-spk-rollout.sh" "${VERSION}"
fi

if [[ "$(uname -s)" == "Darwin" ]] || [[ "$(uname -s)" == "Linux" ]]; then
  if command -v dotnet >/dev/null 2>&1 && [[ "${SKIP_WINDOWS:-0}" != "1" ]]; then
    echo "==> Publishing Windows rollout agent (dotnet)"
    if [[ "$(uname -s)" == "Darwin" ]]; then
      echo "WARN: Windows rollout publish on macOS produces binaries for current RID only; use Windows CI for installer."
    fi
    dotnet publish "${APPS_DIR}/windows-monitor/src/WindowsMonitor.Service/WindowsMonitor.Service.csproj" \
      -c Release \
      -p:RolloutAgent=true \
      -o "${ROOT_DIR}/dist/windows-rollout-agent"
  fi
fi

echo ""
echo "Rollout agent build complete."
echo "  dist/unix-monitor-agent.py + dist/src/ + dist/web/"
echo "  dist/synology-monitor-agent.py (synology SPK uses per-app dist/ with src/ + web/)"
echo "  docker image: ghcr.io/easystems-gmbh/unix-rollout-agent:${VERSION}"
if [[ -d "${ROOT_DIR}/dist/synology-package" ]]; then
  echo "  dist/synology-monitor-agent.spk (if synology build ran)"
fi
if [[ -d "${ROOT_DIR}/dist/windows-rollout-agent" ]]; then
  echo "  dist/windows-rollout-agent/"
fi
