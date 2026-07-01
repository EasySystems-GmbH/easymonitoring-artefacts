"""Peer payload encryption (AES-256-GCM) for the HTTP safety net.

Extracted verbatim (behavior-preserving) from the legacy ``unix-monitor.py``
monolith during Phase 4 Slice C. This is the AES-GCM payload-crypto family used
to encrypt/decrypt peer request/response bodies when a peering token is shared:

* :func:`_derive_aes_key` — pure stdlib (PBKDF2-HMAC-SHA256); 32-byte key.
* :func:`_encrypt_payload` — AES-256-GCM via ``cryptography`` when available,
  with an ``openssl`` CLI fallback and finally a keyed-XOR last resort.
* :func:`_decrypt_payload` — inverse of the above; ``None`` on any failure.

``_encrypt_payload``'s ``openssl`` CLI fallback shells out, so this module is
not a pure-leaf move: the monolith owns ``_run_cmd``. Rather than change every
call site, the entry script injects it once via :func:`configure` at startup;
the public function signatures are identical to the monolith versions so all
existing call sites keep working unchanged. ``_derive_aes_key`` and
``_decrypt_payload`` are pure and never need the injected runner.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from pathlib import Path
from typing import Callable, Optional, Tuple

# Injected by the entry script so the openssl-CLI encryption fallback shells out
# through the same runner the monolith uses.
_run_cmd_provider: Optional[Callable[..., Tuple[int, str]]] = None


def configure(*, run_cmd: Callable[..., Tuple[int, str]]) -> None:
    """Inject the monolith-owned command runner. Call once at startup."""
    global _run_cmd_provider
    _run_cmd_provider = run_cmd


def _derive_aes_key(token: str, salt: bytes = b"synmon-peer-v1") -> bytes:
    """Derive a 32-byte AES key from the peering token using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, 100000)


def _encrypt_payload(plaintext: str, token: str) -> str:
    """Encrypt a JSON string with AES-256-GCM using the peering token. Returns base64(iv + tag + ciphertext)."""
    key = _derive_aes_key(token)
    iv = secrets.token_bytes(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
        return base64.b64encode(iv + ct).decode("ascii")
    except ImportError:
        pass
    # Pure-Python AES-GCM fallback using openssl CLI
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pt") as ptf:
        ptf.write(plaintext.encode("utf-8"))
        ptf_name = ptf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ct") as ctf:
        ctf_name = ctf.name
    try:
        if _run_cmd_provider is None:
            raise RuntimeError("peering.crypto.configure() must be called before use")
        rc, out = _run_cmd_provider([
            "openssl", "enc", "-aes-256-gcm", "-e",
            "-K", key.hex(), "-iv", iv.hex(),
            "-in", ptf_name, "-out", ctf_name,
        ], timeout_sec=10)
        if rc == 0 and Path(ctf_name).exists():
            ct_data = Path(ctf_name).read_bytes()
            return base64.b64encode(iv + ct_data).decode("ascii")
    finally:
        Path(ptf_name).unlink(missing_ok=True)
        Path(ctf_name).unlink(missing_ok=True)
    # Last resort: XOR-based cipher (not as strong but still encrypts)
    ct_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(plaintext.encode("utf-8")):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        ct_bytes.append(b ^ key_stream[i % 64])
    tag = hmac.new(key, iv + bytes(ct_bytes), hashlib.sha256).digest()[:16]
    return base64.b64encode(iv + tag + bytes(ct_bytes)).decode("ascii")


def _decrypt_payload(encoded: str, token: str) -> Optional[str]:
    """Decrypt an encrypted payload. Returns plaintext or None on failure."""
    key = _derive_aes_key(token)
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None
    if len(raw) < 13:
        return None
    iv = raw[:12]
    rest = raw[12:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        plaintext = aes.decrypt(iv, rest, None)
        return plaintext.decode("utf-8")
    except ImportError:
        pass
    except Exception:
        pass
    # Try XOR fallback: iv(12) + tag(16) + ciphertext
    if len(rest) < 16:
        return None
    tag = rest[:16]
    ct_bytes = rest[16:]
    expected_tag = hmac.new(key, iv + ct_bytes, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        return None
    plaintext_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(ct_bytes):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        plaintext_bytes.append(b ^ key_stream[i % 64])
    return bytes(plaintext_bytes).decode("utf-8", errors="ignore")
