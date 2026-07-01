#!/usr/bin/env bash
# Build and optionally push the unix rollout-agent image to GHCR.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# easymonitoring apps/ sibling — monitor sources live under apps/unix-monitor, etc.
APPS_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
REGISTRY="${ROLLOUT_REGISTRY:-ghcr.io}"
IMAGE_NAME="${ROLLOUT_IMAGE_NAME:-easystems-gmbh/unix-rollout-agent}"
PUSH="${ROLLOUT_DOCKER_PUSH:-0}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Build (and optionally push) the unix rollout-agent Docker image.

Environment:
  ROLLOUT_REGISTRY       Registry host (default: ghcr.io)
  ROLLOUT_IMAGE_NAME     Image path without registry (default: easystems-gmbh/unix-rollout-agent)
  ROLLOUT_VERSION        Rollout version tag (default: derived from unix-monitor VERSION)
  ROLLOUT_DOCKER_PUSH    Set to 1 to push after build (default: 0)

Examples:
  $(basename "$0")
  ROLLOUT_DOCKER_PUSH=1 $(basename "$0")
  ROLLOUT_VERSION=1.12.0-rollout.0001 ROLLOUT_DOCKER_PUSH=1 $(basename "$0")

Before pushing to GHCR:
  echo "\$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

monitor_version="$(grep -E '^VERSION = ' "${APPS_DIR}/unix-monitor/unix-monitor.py" | head -1 | sed -E 's/^VERSION = "([^"]+)".*/\1/')"
major="${monitor_version%-*}"
build="${monitor_version#*-}"
ROLLOUT_VERSION="${ROLLOUT_VERSION:-${major}-rollout.${build}}"
TAG="${ROLLOUT_VERSION}"
FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${TAG}"

export ROLLOUT_VERSION
python3 "${ROOT_DIR}/scripts/patch-source.py" --version "${ROLLOUT_VERSION}" --root "${ROOT_DIR}"
"${ROOT_DIR}/docker/stage-build-context.sh"

echo "Building ${FULL_IMAGE} ..."
docker build \
  -t "${FULL_IMAGE}" \
  -f "${ROOT_DIR}/docker/Dockerfile" \
  "${ROOT_DIR}/docker"

if [[ "${PUSH}" == "1" ]]; then
  echo "Pushing ${FULL_IMAGE} ..."
  docker push "${FULL_IMAGE}"
  echo "Pushed ${FULL_IMAGE}"
else
  echo "Built ${FULL_IMAGE} (set ROLLOUT_DOCKER_PUSH=1 to push)"
fi
