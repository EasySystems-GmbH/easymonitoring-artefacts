"""Pure peer URL / port parsing & formatting helpers.

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. These helpers operate only on plain data
structures (URL/host strings, the ``cfg`` dict passed in) and the standard
library; they hold no module-global runtime state beyond the protocol default
port and perform no network I/O or config persistence, so they move cleanly
into ``src/core/peering/``.

The network-touching resolvers (``_resolve_peer_url`` /
``_resolve_peer_url_from_stored`` / ``_peer_master_base_url``) depend on the
mTLS-aware ``_peer_http_request`` and live in :mod:`.resolvers`; they consume
these pure helpers from here.

``PEER_DEFAULT_PORT`` (the standard peering protocol port) is owned here and
re-imported by the entry script. Call-site signatures are unchanged versus the
monolith.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple
from urllib.parse import urlparse

PEER_DEFAULT_PORT = 8787


def _normalize_peer_port(value: Any, default: int = PEER_DEFAULT_PORT) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 1 <= port <= 65535 else default


def _peer_master_port(cfg: Dict[str, Any]) -> int:
    legacy = _normalize_peer_port(cfg.get("peer_port", PEER_DEFAULT_PORT))
    return _normalize_peer_port(cfg.get("peer_master_port", legacy), legacy)


def _peer_agent_port(cfg: Dict[str, Any]) -> int:
    legacy = _normalize_peer_port(cfg.get("peer_port", PEER_DEFAULT_PORT))
    return _normalize_peer_port(cfg.get("peer_agent_port", legacy), legacy)


def _parse_peer_host_port(url_or_host: str, default_port: int = PEER_DEFAULT_PORT) -> Tuple[str, int]:
    """Extract host and port from URL (https://host:port) or plain host or host:port. Returns (host, port)."""
    s = str(url_or_host or "").strip().rstrip("/")
    if not s:
        return ("", default_port)
    parsed = urlparse(s if "://" in s else f"http://{s}")
    host = (parsed.hostname or parsed.path or s).strip()
    if not host:
        return ("", default_port)
    port = parsed.port if parsed.port is not None else default_port
    return (host, port)


def _peer_url_for_input_display(url: str, default_port: int = PEER_DEFAULT_PORT) -> str:
    """Return URL for display in agent URL input - omit :8787 when that's the port so user enters host only."""
    if not url or not str(url).strip():
        return ""
    host, port = _parse_peer_host_port(url, default_port)
    if not host:
        return ""
    if port == default_port:
        return host
    return f"{host}:{port}"


def _peer_url_for_open(url: str, default_port: int = PEER_DEFAULT_PORT) -> str:
    """Build full URL for opening agent UI in a new tab. Uses http when no scheme to avoid SSL errors."""
    if not url or not str(url).strip():
        return ""
    if "://" in url:
        return url.rstrip("/")
    host, port = _parse_peer_host_port(url, default_port)
    if not host:
        return ""
    return f"http://{host}:{port}"


def _peer_scheme_probe_order(port: int) -> Tuple[str, ...]:
    if port in (443, 8443):
        return ("https", "http")
    return ("http", "https")


def _cached_peer_base_url(cfg: Dict[str, Any], host: str, port: int) -> str:
    cached = str(cfg.get("peer_master_base_url", "") or "").strip().rstrip("/")
    if not cached:
        return ""
    cached_host, cached_port = _parse_peer_host_port(cached, port)
    if cached_host.lower() != host.lower() or cached_port != port:
        return ""
    return cached


def _peer_direct_base_url(url_or_host: str, default_port: int = PEER_DEFAULT_PORT) -> str:
    host, port = _parse_peer_host_port(url_or_host, default_port)
    if not host:
        return ""
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def _peer_lan_reachability_hint(master_host: str, master_port: int) -> str:
    return (
        f"If this host cannot reach {master_host}:{master_port}, set HOSTED_BIND_IP=0.0.0.0 on the master "
        "(deploy/.env) and redeploy, or use NPM HTTPS on port 443 with the proxy hostname."
    )
