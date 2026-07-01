#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PACKAGE_DIR="${ROOT_DIR}/package"
DIST_DIR="${ROOT_DIR}/dist"
REPO_DIR="${ROOT_DIR}/repo"
WORK_DIR="${ROOT_DIR}/.build"
TARGET_DIR="${WORK_DIR}/package-root"
PACKAGE_TGZ="${WORK_DIR}/package.tgz"
SPK_PATH="${DIST_DIR}/synology-monitor-basic.spk"
GITHUB_REPO="${GITHUB_REPO:-${PUBLIC_REPO:-EasySystems-GmbH/EasySystems-GmbH/easymonitoring-artefacts}}"
RELEASE_TAG="${RELEASE_TAG:-}"

rm -rf "${WORK_DIR}" "${DIST_DIR}"
mkdir -p "${TARGET_DIR}" "${DIST_DIR}" "${REPO_DIR}"

APP_DIR="$(cd "${ROOT_DIR}/../../.." && pwd)"

# Copy runtime payload (entry script + §9 src/web support tree)
cp "${APP_DIR}/synology-monitor.py" "${TARGET_DIR}/synology-monitor.py"
chmod 700 "${TARGET_DIR}/synology-monitor.py"
cp -R "${APP_DIR}/src" "${TARGET_DIR}/"
cp -R "${APP_DIR}/web" "${TARGET_DIR}/"
cp "${APP_DIR}"/task-*.png "${TARGET_DIR}/" 2>/dev/null || true
chmod 644 "${TARGET_DIR}"/task-*.png 2>/dev/null || true

# Build package.tgz and .spk using Python tarfile to avoid macOS AppleDouble files (._*).
ROOT_DIR="${ROOT_DIR}" GITHUB_REPO="${GITHUB_REPO}" RELEASE_TAG="${RELEASE_TAG}" python3 - <<'PY'
import tarfile
import os
import json
import hashlib
from pathlib import Path

root = Path(os.environ["ROOT_DIR"])
github_repo = os.environ["GITHUB_REPO"]
release_tag = os.environ.get("RELEASE_TAG", "").strip()
work = root / ".build"
pkg_root = work / "package-root"
pkg_tgz = work / "package.tgz"
spk = root / "dist" / "synology-monitor-basic.spk"
package_dir = root / "package"
repo_dir = root / "repo"

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
    add_path(tf, package_dir / "INFO", "INFO", mode=0o644)
    add_path(tf, pkg_tgz, "package.tgz", mode=0o644)
    add_path(tf, package_dir / "PACKAGE_ICON.PNG", "PACKAGE_ICON.PNG", mode=0o644)
    add_path(tf, package_dir / "PACKAGE_ICON_256.PNG", "PACKAGE_ICON_256.PNG", mode=0o644)

    for rel in sorted((package_dir / "scripts").iterdir()):
        if rel.name.startswith("."):
            continue
        add_path(tf, rel, f"scripts/{rel.name}", mode=0o755)
    for rel in sorted((package_dir / "conf").iterdir()):
        if rel.name.startswith("."):
            continue
        add_path(tf, rel, f"conf/{rel.name}", mode=0o644)

# Build Package Center source index for GitHub-hosted repo usage.
info: dict[str, str] = {}
for line in (package_dir / "INFO").read_text(encoding="utf-8").splitlines():
    if "=" not in line:
        continue
    k, v = line.split("=", 1)
    info[k.strip()] = v.strip().strip('"')

spk_bytes = spk.read_bytes()
sha256 = hashlib.sha256(spk_bytes).hexdigest()
if release_tag:
    link = f"https://github.com/{github_repo}/releases/download/{release_tag}/{spk.name}"
else:
    link = f"https://github.com/{github_repo}/releases/latest/download/{spk.name}"
packages_json = {
    "packages": [
        {
            "package": info.get("package", "synology-monitor"),
            "name": info.get("package", "synology-monitor"),
            "dname": info.get("displayname", "Synology Monitor"),
            "displayname": info.get("displayname", "Synology Monitor"),
            "version": info.get("version", "0.0.0"),
            "arch": info.get("arch", "noarch"),
            "description": info.get("description", ""),
            "desc": info.get("description", ""),
            "maintainer": info.get("maintainer", ""),
            "maintainer_url": info.get("maintainer_url", ""),
            "distributor": info.get("distributor", ""),
            "distributor_url": info.get("distributor_url", ""),
            "support_center": info.get("support_center", ""),
            "helpurl": info.get("helpurl", ""),
            "startable": info.get("startable", "yes"),
            "thirdparty": info.get("thirdparty", "yes"),
            "beta": info.get("beta", "yes"),
            "os_min_ver": info.get("os_min_ver", ""),
            "link": link,
            "checksum_sha256": sha256,
            "size": len(spk_bytes),
        }
    ]
}
(repo_dir / "packages.json").write_text(json.dumps(packages_json, indent=2) + "\n", encoding="utf-8")
(root / "dist" / "packages.json").write_text(json.dumps(packages_json, indent=2) + "\n", encoding="utf-8")
PY

echo "Built: ${SPK_PATH}"
echo "Package source index: ${REPO_DIR}/packages.json"
