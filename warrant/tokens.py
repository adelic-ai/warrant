"""RFC 8693 OAuth 2.0 Token Exchange — delegation, not impersonation.

`exchange()` takes a subject_token (the human's session) and an actor assertion (the agent's
SPIFFE SVID, from warrant.identity) and mints a new token carrying BOTH identities via a nested `act`
claim: `sub` stays the human, `act.sub` names the agent. Downstream sees "user U, acted upon by
agent A" — never a token that looks like it came from the human alone. Scope is narrowed to the
intersection of what the delegation actually grants, not copied wholesale from the subject token.

Simplification, disclosed: `issue_subject_token` stands in for a real IdP (Entra/Okta) issuing an
OIDC ID token to the human. A production deployment would validate a real IdP-issued token here
instead of minting its own. The signing key is an ephemeral in-process EC key, same as
`warrant.identity`'s CA — regenerated every process start, not persisted. Fine for a prototype; a real
deployment would use a proper key-management story (KMS-backed, rotated).
"""
from __future__ import annotations

import datetime
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from sqlmodel import Session

from warrant.identity import CA
from warrant.pdp import find_active_delegation

ALG = "ES256"
_SIGNING_KEY = ec.generate_private_key(ec.SECP256R1())

SUBJECT_TOKEN_TTL_MINUTES = 60
EXCHANGED_TOKEN_TTL_MINUTES = 5
AUDIENCE = "warrant-resources"


class ExchangeError(Exception):
    """Raised for any exchange failure — invalid subject token, unverifiable actor assertion, or
    a scope-widen attempt. The caller (the /token/exchange endpoint) turns this into a 4xx with
    the message as the reason; nothing about this is a silent partial success."""


def issue_subject_token(principal_id: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": principal_id,
        "iss": "warrant",
        "token_use": "subject",
        "iat": now,
        "exp": now + datetime.timedelta(minutes=SUBJECT_TOKEN_TTL_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, _SIGNING_KEY, algorithm=ALG)


def _decode(token: str) -> dict:
    return jwt.decode(
        token, _SIGNING_KEY.public_key(), algorithms=[ALG], audience=None,
        options={"verify_aud": False},
    )


def agent_id_from_spiffe(spiffe_id: str) -> str:
    # "spiffe://warrant.local/agent/A17" -> "agent:A17" — the identity id convention used
    # throughout the rest of the models (Identity.id, Delegation.delegate_id).
    return "agent:" + spiffe_id.rsplit("/", 1)[-1]


def exchange(
    session: Session,
    *,
    subject_token: str,
    actor_cert_pem: bytes,
    case: str,
    requested_actions: list[str],
) -> str:
    """Exchange a subject_token + actor SVID for a delegated, scope-narrowed access token.

    Looks up the active Delegation for (principal from subject_token, agent from the SVID, case)
    itself, and rejects a `requested_actions` list that asks for anything beyond what that
    delegation actually grants (permitted ∪ requires-approval — never anything explicitly
    forbidden) — the scope-non-increase check, enforced at mint time.
    """
    try:
        subject_claims = _decode(subject_token)
    except jwt.PyJWTError as exc:
        raise ExchangeError(f"invalid subject_token: {exc}") from exc
    if subject_claims.get("token_use") != "subject":
        raise ExchangeError("subject_token is not a subject-use token")
    principal_id = subject_claims["sub"]

    spiffe_id = CA.verify(actor_cert_pem)
    if spiffe_id is None:
        raise ExchangeError("actor assertion (SVID) failed verification")
    agent_id = agent_id_from_spiffe(spiffe_id)

    delegation = find_active_delegation(
        session, principal_id=principal_id, delegate_id=agent_id, scope=case
    )
    if delegation is None:
        raise ExchangeError(f"no active delegation from {principal_id} to {agent_id} for {case}")

    grantable = set(delegation.permitted) | set(delegation.requires_approval)
    if not requested_actions:
        raise ExchangeError("requested_actions must be non-empty")
    widened = set(requested_actions) - grantable
    if widened:
        raise ExchangeError(
            f"requested_actions exceeds what the delegation grants: {sorted(widened)}"
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": principal_id,
        "act": {"sub": spiffe_id},
        "scope": requested_actions,
        "aud": AUDIENCE,
        "iss": "warrant",
        "delegation_id": delegation.id,
        "iat": now,
        "exp": now + datetime.timedelta(minutes=EXCHANGED_TOKEN_TTL_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, _SIGNING_KEY, algorithm=ALG)


def exchange_chained(
    session: Session,
    *,
    parent_token: str,
    sub_actor_cert_pem: bytes,
    requested_actions: list[str],
) -> str:
    """Second (or later) hop of a delegation chain: agent A holds a token from the first
    exchange and wants to delegate a (narrower) subset of it to sub-agent B. `act` nests —
    the new token's `act.sub` is B, with A's whole `act` object preserved underneath — so the
    full chain is inspectable from the token alone: "sub, acted upon by B, acted upon by A."

    The scope-non-increase invariant is the entire enforcement here: `requested_actions` must be
    a subset of the *parent token's own* `scope` claim. No Delegation DB row is consulted for
    this hop — the parent token's scope already is the ceiling, by construction of the first
    hop's own exchange. `session` is accepted for interface symmetry with `exchange()` even
    though this function doesn't touch the DB; kept in case a future hop needs the delegation_id
    to look up per-hop policy.
    """
    del session  # not needed yet — see docstring
    try:
        parent_claims = verify_exchanged_token(parent_token)
    except ExchangeError as exc:
        raise ExchangeError(f"invalid parent_token: {exc}") from exc

    sub_spiffe_id = CA.verify(sub_actor_cert_pem)
    if sub_spiffe_id is None:
        raise ExchangeError("sub-agent actor assertion (SVID) failed verification")

    parent_scope = set(parent_claims.get("scope", []))
    if not requested_actions:
        raise ExchangeError("requested_actions must be non-empty")
    widened = set(requested_actions) - parent_scope
    if widened:
        raise ExchangeError(
            f"requested_actions exceeds the parent token's own scope {sorted(parent_scope)}: "
            f"{sorted(widened)}"
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    claims = {
        "sub": parent_claims["sub"],
        "act": {"sub": sub_spiffe_id, "act": parent_claims["act"]},
        "scope": requested_actions,
        "aud": AUDIENCE,
        "iss": "warrant",
        "delegation_id": parent_claims.get("delegation_id"),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=EXCHANGED_TOKEN_TTL_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, _SIGNING_KEY, algorithm=ALG)


def root_spiffe_from_claims(claims: dict) -> str:
    """Walks a (possibly nested) `act` chain down to the original first-hop agent — the one that
    actually holds a Delegation row from the human principal. A sub-agent further down the chain
    (e.g. B1, delegated to by A17) never gets its own Delegation row; its authority is a narrowed
    view of A17's, not a separate grant, so policy decisions are checked against the root."""
    act = claims["act"]
    while "act" in act:
        act = act["act"]
    return act["sub"]


def verify_exchanged_token(token: str) -> dict:
    try:
        claims = _decode(token)
    except jwt.PyJWTError as exc:
        raise ExchangeError(f"invalid token: {exc}") from exc
    if "act" not in claims:
        raise ExchangeError("token carries no act claim — not a delegated token")
    if claims.get("aud") != AUDIENCE:
        raise ExchangeError("token not valid for this audience")
    return claims
