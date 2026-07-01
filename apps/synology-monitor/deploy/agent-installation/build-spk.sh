#!/usr/bin/env bash
# Build synology-monitor-agent.spk (agent-only edition).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="$(cd "${ROOT_DIR}/../.." && pwd)"
VERSION="${1:-1.12.0-rollout.1}"
FULL_PKG="${APP_DIR}/deploy/full-version/community-package/package"
DIST_DIR="${ROOT_DIR}/dist"
AGENT_PY="${DIST_DIR}/synology-monitor-agent.py"
INFO_SRC="${DIST_DIR}/synology-package/INFO"

if [[ ! -f "${AGENT_PY}" ]]; then
  echo "ERROR: missing ${AGENT_PY} — run patch-source (playbook build-rollout) first." >&2
  exit 1
fi
if [[ ! -f "${INFO_SRC}" ]]; then
  echo "ERROR: missing ${INFO_SRC}" >&2
  exit 1
fi

WORK_DIR="${ROOT_DIR}/.build-spk"
rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/package-root" "${WORK_DIR}/package" "${DIST_DIR}"

cp "${AGENT_PY}" "${WORK_DIR}/package-root/synology-monitor.py"
chmod 700 "${WORK_DIR}/package-root/synology-monitor.py"
if [[ -d "${DIST_DIR}/src" && -d "${DIST_DIR}/web" ]]; then
  cp -R "${DIST_DIR}/src" "${WORK_DIR}/package-root/"
  cp -R "${DIST_DIR}/web" "${WORK_DIR}/package-root/"
elif [[ -d "${APP_DIR}/src" && -d "${APP_DIR}/web" ]]; then
  cp -R "${APP_DIR}/src" "${WORK_DIR}/package-root/"
  cp -R "${APP_DIR}/web" "${WORK_DIR}/package-root/"
else
  echo "ERROR: missing src/ and web/ beside agent entry script (run patch-source first)." >&2
  exit 1
fi
cp "${APP_DIR}"/task-*.png "${WORK_DIR}/package-root/" 2>/dev/null || true
cp "${INFO_SRC}" "${WORK_DIR}/package/INFO"

# Reuse full SPK DSM hooks (start/stop, privileges) — same install UX, agent-only binary.
if [[ -d "${FULL_PKG}/scripts" ]]; then
  cp -R "${FULL_PKG}/scripts" "${WORK_DIR}/package/"
fi
if [[ -d "${FULL_PKG}/conf" ]]; then
  cp -R "${FULL_PKG}/conf" "${WORK_DIR}/package/"
fi
EXTRAS_CONF="${ROOT_DIR}/package-extras/conf"
if [[ -d "${EXTRAS_CONF}" ]]; then
  mkdir -p "${WORK_DIR}/package/conf"
  cp -R "${EXTRAS_CONF}/." "${WORK_DIR}/package/conf/"
fi
for icon in PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG; do
  if [[ -f "${FULL_PKG}/${icon}" ]]; then
    cp "${FULL_PKG}/${icon}" "${WORK_DIR}/package/"
  fi
done

ROOT_DIR="${WORK_DIR}" \
  SPK_OUT="${DIST_DIR}/synology-monitor-agent.spk" \
  SPK_NAME="synology-monitor-agent.spk" \
  python3 - <<'PY'
import hashlib
import os
import tarfile
from pathlib import Path

work = Path(os.environ["ROOT_DIR"])
pkg_root = work / "package-root"
pkg_tgz = work / "package.tgz"
spk = Path(os.environ["SPK_OUT"])
package_dir = work / "package"

def add_path(tf: tarfile.TarFile, src: Path, arcname: str, mode: int | None = None) -> None:
    if src.is_dir():
        for child in sorted(src.rglob("*")):
            if child.is_file():
                rel = child.relative_to(src)
                add_path(tf, child, f"{arcname}/{rel}".replace("\\", "/"), mode)
        return
    ti = tf.gettarinfo(str(src), arcname)
    if mode is not None:
        ti.mode = mode
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    ti.mtime = 1700000000
    with src.open("rb") as f:
        tf.addfile(ti, f)

with tarfile.open(pkg_tgz, "w:gz", format=tarfile.GNU_FORMAT) as tf:
    add_path(tf, pkg_root / "synology-monitor.py", "synology-monitor.py", mode=0o700)
    for support in ("src", "web"):
        support_dir = pkg_root / support
        if support_dir.is_dir():
            add_path(tf, support_dir, support, mode=0o644)
    for img in sorted(pkg_root.glob("task-*.png")):
        add_path(tf, img, img.name, mode=0o644)

with tarfile.open(spk, "w", format=tarfile.GNU_FORMAT) as tf:
    for item in sorted(package_dir.iterdir()):
        if item.name == "package.tgz":
            continue
        mode = 0o755 if item.is_dir() or item.suffix == ".sh" else 0o644
        add_path(tf, item, item.name, mode=mode)
    add_path(tf, pkg_tgz, "package.tgz", mode=0o644)

print(f"Wrote {spk}")
PY

echo "Synology rollout SPK: ${DIST_DIR}/synology-monitor-agent.spk"
