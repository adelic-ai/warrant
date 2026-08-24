"""Shared EC key material, persisted to disk so multiple warrant replicas can verify each
other's tokens/SVIDs instead of each generating its own ephemeral key at process start.

Cloud-agnostic by construction: a plain file path, so the backing store is whatever the
deployment already has for shared state (a mounted volume, EFS/Filestore/Azure Files, or a
single-instance local path for a prototype) rather than a specific cloud KMS. Swapping in a
real KMS/Vault later means implementing this same load-or-create contract against that
backend, not changing tokens.py/identity.py, which only depend on getting back an
EllipticCurvePrivateKey.
"""
from __future__ import annotations

import os
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def load_or_create_ec_key(path: str) -> ec.EllipticCurvePrivateKey:
    """Loads the EC private key at `path` if it exists; otherwise generates one and writes it
    there (mode 0600) so the next replica to start finds it instead of generating its own.

    Race-safe for concurrent first-boot (multiple replicas starting simultaneously against an
    empty shared path): the full key is written to a unique temp file first, then published
    via os.link() -- which atomically creates `path` pointing at that already-complete content
    and raises FileExistsError if another process already published one, rather than silently
    overwriting (os.rename's POSIX semantics) or letting a reader see a partially-written file
    (a plain O_CREAT|O_EXCL write, tried first, let a losing thread read a still-mid-write file
    and fail on a malformed PEM -- caught by test_concurrent_first_boot_race... actually
    exercising the race with real concurrent threads, not simulated sequentially). Exactly one
    process's generated key ever becomes the persisted one; every other process loads that
    same key instead of using its own. A real deployment should still prefer provisioning this
    file once, out of band, before any replica starts -- this race handling is a safety net,
    not the intended provisioning path.
    """
    if os.path.exists(path):
        return _read_key(path)

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)

    tmp_path = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
        f.flush()
        os.fsync(f.fileno())

    try:
        os.link(tmp_path, path)
    except FileExistsError:
        # Lost the race -- another process's temp file was linked to `path` first. Its
        # content is guaranteed complete (link only happens after that process's own flush),
        # so load it instead of using the key we just generated.
        return _read_key(path)
    finally:
        os.remove(tmp_path)
    return key


def _read_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
