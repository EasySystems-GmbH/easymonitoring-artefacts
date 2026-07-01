"""Config-backup encryption (AES-256-GCM) for user-exported backups.

Extracted verbatim (behavior-preserving) from the legacy ``synology-monitor.py``
monolith. This is the backup-crypto family used to encrypt/decrypt exported
config backups with a user-supplied backup key. It is distinct from the peer
payload-crypto family in ``src/core/peering/crypto.py``: the key derivation
uses a **different, backup-specific salt** (:data:`BACKUP_SALT`,
``b"synology-monitor-backup-v1"``) so backup blobs and peer blobs are never
cross-decryptable.

* :func:`_derive_backup_key` — pure stdlib (PBKDF2-HMAC-SHA256); 32-byte key.
* :func:`_encrypt_backup` — AES-256-GCM via ``cryptography`` when available,
  with an ``openssl`` CLI fallback and finally a keyed-XOR last resort.
* :func:`_decrypt_backup` — inverse of the above; ``None`` on any failure.

``_encrypt_backup``'s ``openssl`` CLI fallback shells out, so this module is
not a pure-leaf move: the monolith owns ``_run_cmd``. Rather than change every
call site, the entry script injects it once via :func:`configure` at startup;
the public function signatures are identical to the monolith versions so all
existing call sites keep working unchanged. ``_derive_backup_key`` and
``_decrypt_backup`` are pure and never need the injected runner.
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

# Backup-specific salt: intentionally different from the peer-crypto salt
# (b"synmon-peer-v1") so backup and peer blobs never cross-decrypt.
BACKUP_SALT = b"synology-monitor-backup-v1"


def configure(*, run_cmd: Callable[..., Tuple[int, str]]) -> None:
    """Inject the monolith-owned command runner. Call once at startup."""
    global _run_cmd_provider
    _run_cmd_provider = run_cmd


def _derive_backup_key(user_key: str) -> bytes:
    """Derive a 32-byte AES key from user-provided backup key."""
    return hashlib.pbkdf2_hmac("sha256", user_key.encode("utf-8"), BACKUP_SALT, 100000)


def _encrypt_backup(plaintext: str, user_key: str) -> str:
    """Encrypt backup payload with user key. Returns base64(iv + tag + ciphertext)."""
    key = _derive_backup_key(user_key)
    iv = secrets.token_bytes(12)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import-not-found]
        aes = AESGCM(key)
        ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
        return base64.b64encode(iv + ct).decode("ascii")
    except ImportError:
        pass
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pt") as ptf:
        ptf.write(plaintext.encode("utf-8"))
        ptf_name = ptf.name
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ct") as ctf:
        ctf_name = ctf.name
    try:
        if _run_cmd_provider is None:
            raise RuntimeError("security.backup_crypto.configure() must be called before use")
        rc, _ = _run_cmd_provider([
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
    ct_bytes = bytearray()
    key_stream = hashlib.sha512(key + iv).digest()
    for i, b in enumerate(plaintext.encode("utf-8")):
        if i % 64 == 0 and i > 0:
            key_stream = hashlib.sha512(key + iv + i.to_bytes(4, "big")).digest()
        ct_bytes.append(b ^ key_stream[i % 64])
    tag = hmac.new(key, iv + bytes(ct_bytes), hashlib.sha256).digest()[:16]
    return base64.b64encode(iv + tag + bytes(ct_bytes)).decode("ascii")


def _decrypt_backup(encoded: str, user_key: str) -> Optional[str]:
    """Decrypt backup payload. Returns plaintext or None on failure."""
    key = _derive_backup_key(user_key)
    try:
        raw = base64.b64decode(encoded)
    except Exception:
        return None
    if len(raw) < 12:
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
        return None
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
