#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-1.12.0-rollout.1}"
IMAGE="${ROLLOUT_IMAGE:-ghcr.io/easystems-gmbh/unix-rollout-agent:${VERSION}}"

"${ROOT_DIR}/docker/stage-build-context.sh"
docker build -t "${IMAGE}" -f "${ROOT_DIR}/docker/Dockerfile" "${ROOT_DIR}/docker"
echo "Built ${IMAGE}"
