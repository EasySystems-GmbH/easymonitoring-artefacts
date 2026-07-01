"""Pure peer mTLS certificate *path* / listing helpers (no TLS handshake).

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. These helpers only resolve the certificate
directory, build/inspect certificate file *paths*, and list signed-agent cert
files on disk. They perform no subprocess/OpenSSL calls, no UI logging, no
payload encryption, and no network/TLS I/O.

The monolith owns the runtime data directory these helpers resolve against
(``get_runtime_data_dir``). Rather than change every call site, the entry
script injects it once via :func:`configure` at startup; the public function
signatures are identical to the monolith versions so all existing call sites
keep working unchanged.

The mTLS-aware transport (``_peer_http_request`` — TLS context, cert-chain
load, ``_encrypt_payload``/``_decrypt_payload`` token crypto) and the OpenSSL
CA/cert *generation/signing* helpers (``_generate_ca``,
``_generate_instance_cert``, ``_sign_agent_csr``, ``_get_ca_fingerprint``,
``_revoke_agent_cert``, ``_get_mtls_security_status``) intentionally stay in
the monolith for now: they shell out via ``_run_cmd`` and/or call
``append_ui_log``, so they are not pure-leaf extractable yet. They consume
``get_certs_dir`` / ``_get_mtls_cert_paths`` from here (single source).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Injected by the entry script so the certs directory resolves to the same
# runtime data directory the monolith uses.
_runtime_data_dir_provider: Optional[Callable[[], Path]] = None


def configure(*, runtime_data_dir: Callable[[], Path]) -> None:
    """Inject the monolith-owned runtime data dir. Call once at startup."""
    global _runtime_data_dir_provider
    _runtime_data_dir_provider = runtime_data_dir


def get_certs_dir() -> Path:
    if _runtime_data_dir_provider is None:
        raise RuntimeError("peering.certs.configure() must be called before use")
    d = _runtime_data_dir_provider() / "certs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_mtls_cert_paths(cfg: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (cert_path, key_path, ca_cert_path) if all exist, else (None, None, None)."""
    d = get_certs_dir()
    ca_crt = d / "ca.crt"
    if not ca_crt.exists():
        return None, None, None
    instance_id = str(cfg.get("instance_id", "") or "").strip()
    if not instance_id:
        return None, None, None
    safe_id = re.sub(r'[^a-zA-Z0-9_-]', '_', instance_id)[:40]
    cert_path = d / f"{safe_id}.crt"
    key_path = d / f"{safe_id}.key"
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path), str(ca_crt)
    return None, None, None


def _list_signed_agents() -> List[str]:
    d = get_certs_dir()
    agents = []
    for p in sorted(d.glob("agent-*.crt")):
        agents.append(p.stem.replace("agent-", "", 1))
    return agents
