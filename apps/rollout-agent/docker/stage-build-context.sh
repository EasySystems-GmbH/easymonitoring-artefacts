#!/usr/bin/env bash
# Stage patched dist/ (entry + src/ + web/) into docker/ for image build context.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${ROOT_DIR}/dist"
DOCKER_CTX="${ROOT_DIR}/docker"

for item in unix-monitor-agent.py src web; do
  if [[ ! -e "${DIST}/${item}" ]]; then
    echo "missing ${DIST}/${item}; run scripts/patch-source.py first" >&2
    exit 1
  fi
done

cp "${DIST}/unix-monitor-agent.py" "${DOCKER_CTX}/unix-monitor-agent.py"
rm -rf "${DOCKER_CTX}/src" "${DOCKER_CTX}/web"
cp -a "${DIST}/src" "${DOCKER_CTX}/src"
cp -a "${DIST}/web" "${DOCKER_CTX}/web"
