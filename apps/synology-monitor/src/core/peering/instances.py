"""Pure peer instance-id / monitor-field helpers.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith during Phase 4 Slice C. These helpers operate only on plain data
structures (peer dicts, instance-id strings, the ``cfg`` dict passed in) and
the standard library; they hold no module-global runtime state and perform no
config persistence, so they move cleanly into ``src/core/peering/``.

Call-site signatures are unchanged versus the monolith.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def _is_valid_peer_instance_id(instance_id: str) -> bool:
    iid = str(instance_id or "").strip()
    if len(iid) < 8:
        return False
    if iid.lower() in {"none", "null", "unknown", "-", "?"}:
        return False
    return bool(re.match(r"^[A-Za-z0-9_-]+$", iid))


def _display_peer_instance_id(instance_id: str) -> str:
    """Format Windows-style 32-hex IDs to UUID shape for UI display."""
    iid = str(instance_id or "").strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", iid):
        lower = iid.lower()
        return f"{lower[0:8]}-{lower[8:12]}-{lower[12:16]}-{lower[16:20]}-{lower[20:32]}"
    return iid


def _normalize_peer_instance_id_key(instance_id: str) -> str:
    """Canonical key for matching UUID-like peer IDs across dashed/non-dashed forms."""
    iid = str(instance_id or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", iid):
        return iid.replace("-", "")
    if re.fullmatch(r"[0-9a-f]{32}", iid):
        return iid
    return iid


def _dedupe_peers_by_instance_id(peers: Any) -> List[Dict[str, Any]]:
    """Collapse duplicate peer rows sharing the same instance_id (keeps most recently seen)."""
    if not isinstance(peers, list):
        return []
    valid: List[Dict[str, Any]] = []
    for p in peers:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("instance_id", "") or "").strip()
        if _is_valid_peer_instance_id(pid):
            valid.append(p)
    valid.sort(key=lambda x: int(x.get("last_seen", 0) or 0), reverse=True)
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for p in valid:
        pid = str(p.get("instance_id", "") or "").strip()
        if pid in seen:
            continue
        seen.add(pid)
        out.append(p)
    return out


def _registered_peer_instance_ids(cfg: Dict[str, Any]) -> set[str]:
    """Instance IDs listed under cfg['peers'] (master's registered agents)."""
    peers = cfg.get("peers", [])
    if not isinstance(peers, list):
        return set()
    out: set[str] = set()
    for p in peers:
        if not isinstance(p, dict):
            continue
        pid = str(p.get("instance_id", "") or "").strip()
        if _is_valid_peer_instance_id(pid):
            out.add(pid)
    return out


def _is_legacy_peer(peer: Optional[Dict[str, Any]]) -> bool:
    """True when peer enrolled via legacy token register (default for older peers)."""
    if not isinstance(peer, dict):
        return True
    enrollment = str(peer.get("enrollment", "") or "").strip().lower()
    if enrollment in ("legacy-peer", "legacy"):
        return True
    if enrollment in ("modern-pairing", "modern", "paired"):
        return False
    return True


def _peer_monitor_name(pm: Dict[str, Any], fallback: str = "?") -> str:
    if not isinstance(pm, dict):
        return fallback
    for key in ("name", "Name", "monitor", "Monitor", "monitor_name", "monitorName", "id", "Id", "monitor_id", "monitorId"):
        value = str(pm.get(key, "") or "").strip()
        if value:
            return value
    return fallback


def _peer_monitor_mode(pm: Dict[str, Any]) -> str:
    if not isinstance(pm, dict):
        return "smart"
    raw = pm.get(
        "check_mode",
        pm.get("checkMode", pm.get("mode", pm.get("Mode", pm.get("monitor_mode", pm.get("monitorMode", "smart"))))),
    )
    if isinstance(raw, (int, float)):
        return {
            0: "smart",
            1: "storage",
            2: "ping",
            3: "service",
            4: "backup",
            5: "port",
            6: "dns",
        }.get(int(raw), "smart")
    mode = str(raw or "smart").strip().lower()
    if mode in ("smart", "storage", "ping", "port", "dns", "backup", "service"):
        return mode
    return "smart"
