"""SPIFFE-shaped workload identity for agents.

Not real SPIRE — deliberately, and disclosed as such in the README (see docs/build-prompt.md
Phase 4). This issues short-lived X.509 certs whose SAN carries a `spiffe://<trust-domain>/...`
URI, the same identity convention real SPIRE uses, signed by a local CA generated fresh at process
start. What's missing relative to real SPIRE: node/workload attestation (minting is now gated on
a pre-shared bootstrap token per agent_id — see `check_bootstrap_token` — rather than real SPIRE's
platform-specific attestation plugins, e.g. verifying a k8s service account projection or an AWS
instance identity document; a real deployment would attest what's actually running, not just check
a shared secret), a long-lived trust bundle (this CA is ephemeral, regenerated every run), and the
Workload API delivery mechanism (SPIRE's actual bootstrapping story). What's preserved: the
identity primitive itself — URI-SAN-as-identity, short TTL, X.509 chain validation — is the real
shape, not a placeholder string.
"""
from __future__ import annotations

import datetime
import json
import os
import secrets
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

TRUST_DOMAIN = "warrant.local"


def _bootstrap_tokens() -> dict[str, str]:
    """Operator-provisioned {agent_id: shared secret} map, read fresh from
    WARRANT_BOOTSTRAP_TOKENS (a JSON object) on every call rather than cached at import — so
    rotating it takes effect without a process restart, same freshness rule warden's own
    reloadable-allowlist proxy follows for the identical reason (a cached value can silently
    outlive a real change). This is the same join-token fallback real SPIRE itself offers when no
    platform attestation plugin is configured for an environment: not attestation of what's
    actually running, but it closes "anyone can mint an identity for any agent_id" down to "you
    need the secret provisioned out-of-band for this specific agent_id."
    """
    raw = os.environ.get("WARRANT_BOOTSTRAP_TOKENS", "")
    return json.loads(raw) if raw else {}


def check_bootstrap_token(agent_id: str, token: str | None) -> bool:
    """True iff `token` matches the provisioned secret for `agent_id`. Constant-time compare
    (`secrets.compare_digest`) so a timing side-channel can't be used to guess a valid token
    character-by-character. No token configured for this agent_id, or none presented -> False,
    never an implicit allow."""
    if token is None:
        return False
    expected = _bootstrap_tokens().get(agent_id)
    if expected is None:
        return False
    return secrets.compare_digest(expected, token)


def spiffe_id_for(agent_id: str) -> str:
    return f"spiffe://{TRUST_DOMAIN}/agent/{agent_id}"


@dataclass
class Svid:
    spiffe_id: str
    cert_pem: bytes
    key_pem: bytes
    not_after: datetime.datetime


class LocalCA:
    """Stands in for SPIRE's server CA. One instance per process — the trust bundle a real
    deployment would persist and distribute is, here, just this object's public cert."""

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"warrant-local-ca.{TRUST_DOMAIN}")]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        self._cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self._key, hashes.SHA256())
        )

    @property
    def trust_bundle_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    def issue(self, agent_id: str, *, ttl_minutes: int = 60) -> Svid:
        spiffe_id = spiffe_id_for(agent_id)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        not_after = now + datetime.timedelta(minutes=ttl_minutes)
        # min(...) so a negative ttl_minutes (used in tests to construct an already-expired
        # cert) still produces a valid not_before < not_after ordering instead of raising.
        not_before = min(now - datetime.timedelta(minutes=1), not_after - datetime.timedelta(seconds=30))
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
            .issuer_name(self._cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
                critical=False,
            )
            .sign(self._key, hashes.SHA256())
        )
        return Svid(
            spiffe_id=spiffe_id,
            cert_pem=cert.public_bytes(serialization.Encoding.PEM),
            key_pem=leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            not_after=not_after,
        )

    def verify(self, cert_pem: bytes) -> str | None:
        """Returns the SPIFFE ID (SAN URI) iff cert_pem is signed by this CA, unexpired, and
        carries exactly one URI SAN. Returns None on any failure — never raises to the caller,
        so a malformed/forged assertion is just an unauthenticated request, not a crash."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            self._cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
            now = datetime.datetime.now(datetime.timezone.utc)
            if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
                return None
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
            if len(uris) != 1 or not uris[0].startswith(f"spiffe://{TRUST_DOMAIN}/"):
                return None
            return uris[0]
        except Exception:
            return None


# One CA per process — see class docstring. Imported and used as a singleton throughout.
CA = LocalCA()
