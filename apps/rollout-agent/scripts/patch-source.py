#!/usr/bin/env python3
"""Bake rollout-agent edition flags into per-app deploy/agent-installation/dist/.

Each patched agent dist ships the entry ``*.py`` plus colocated ``src/`` and ``web/``
trees (§9 layout). Single-file ``*.py`` alone is no longer sufficient — TOTP and
web assets resolve from those directories at runtime.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

SUPPORT_DIRS = ("src", "web")
_COPY_IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store")


def patch_monitor_source(src: Path, dst: Path, version: str) -> None:
    text = src.read_text(encoding="utf-8")
    if "ROLLOUT_AGENT_BUILD" not in text:
        raise SystemExit(f"ROLLOUT_AGENT_BUILD not found in {src}")

    text = re.sub(
        r'^ROLLOUT_AGENT_BUILD\s*=\s*False\s*$',
        "ROLLOUT_AGENT_BUILD = True",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    text = re.sub(
        r'^VERSION\s*=\s*"[^"]*"\s*$',
        f'VERSION = "{version}"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")


def copy_support_dirs(app_dir: Path, dst_dir: Path) -> None:
    """Copy ``src/`` and ``web/`` from an app root into a dist output directory."""
    for name in SUPPORT_DIRS:
        src = app_dir / name
        dst = dst_dir / name
        if not src.is_dir():
            raise SystemExit(f"Support directory not found: {src}")
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, ignore=_COPY_IGNORE)


def patch_synology_info(src: Path, dst: Path, version: str) -> None:
    text = src.read_text(encoding="utf-8")
    text = re.sub(r'^package="[^"]*"\s*$', 'package="synology-monitor-agent"', text, count=1, flags=re.MULTILINE)
    text = re.sub(r'^version="[^"]*"\s*$', f'version="{version}"', text, count=1, flags=re.MULTILINE)
    text = re.sub(
        r'^displayname="[^"]*"\s*$',
        'displayname="EasySystems GmbH - Kuma Rollout Agent"',
        text,
        count=1,
        flags=re.MULTILINE,
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch monitor sources for rollout-agent builds")
    parser.add_argument("--version", default="1.12.0-rollout.1")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate source paths and print targets without writing files",
    )
    args = parser.parse_args()

    # easymonitoring layout: args.root = apps/rollout-agent, apps = apps/
    apps = args.root.parent
    version = args.version.strip()
    rollout_dist = args.root / "dist"

    unix_app = apps / "unix-monitor"
    syno_app = apps / "synology-monitor"
    unix_src = unix_app / "unix-monitor.py"
    syno_src = syno_app / "synology-monitor.py"
    unix_agent_dist = unix_app / "deploy" / "agent-installation" / "dist"
    syno_agent_dist = syno_app / "deploy" / "agent-installation" / "dist"
    syno_info_src = (
        apps / "synology-monitor" / "deploy" / "full-version" / "community-package" / "package" / "INFO"
    )

    unix_agent_py = unix_agent_dist / "unix-monitor-agent.py"
    syno_agent_py = syno_agent_dist / "synology-monitor-agent.py"
    syno_info_dst = syno_agent_dist / "synology-package" / "INFO"

    file_targets = [
        (unix_src, unix_agent_py),
        (syno_src, syno_agent_py),
        (syno_info_src, syno_info_dst),
        (unix_src, rollout_dist / "unix-monitor-agent.py"),
        (syno_src, rollout_dist / "synology-monitor-agent.py"),
        (syno_info_src, rollout_dist / "synology-package" / "INFO"),
    ]
    dir_targets = [
        (unix_app, unix_agent_dist),
        (syno_app, syno_agent_dist),
        (unix_app, rollout_dist),
    ]
    for src, dst in file_targets:
        if not src.is_file():
            raise SystemExit(f"Source not found: {src}")
    for app_dir, dst_dir in dir_targets:
        for name in SUPPORT_DIRS:
            if not (app_dir / name).is_dir():
                raise SystemExit(f"Support directory not found: {app_dir / name}")

    if args.dry_run:
        print(f"DRY-RUN: would patch rollout artifacts (version {version})")
        for src, dst in file_targets:
            print(f"  {src} -> {dst}")
        for app_dir, dst_dir in dir_targets:
            for name in SUPPORT_DIRS:
                print(f"  {app_dir / name}/ -> {dst_dir / name}/")
        return 0

    patch_monitor_source(unix_src, unix_agent_py, version)
    patch_monitor_source(syno_src, syno_agent_py, version)
    patch_synology_info(syno_info_src, syno_info_dst, version)
    copy_support_dirs(unix_app, unix_agent_dist)
    copy_support_dirs(syno_app, syno_agent_dist)

    # Mirror for rollout-agent Docker CI workflow (unix src/web only).
    patch_monitor_source(unix_src, rollout_dist / "unix-monitor-agent.py", version)
    patch_monitor_source(syno_src, rollout_dist / "synology-monitor-agent.py", version)
    patch_synology_info(syno_info_src, rollout_dist / "synology-package" / "INFO", version)
    copy_support_dirs(unix_app, rollout_dist)

    print(
        f"Patched agent artifacts -> {unix_agent_dist} and {syno_agent_dist} "
        f"(version {version}; includes src/ + web/)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
