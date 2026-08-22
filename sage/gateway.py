"""The PEP — an MCP-shaped gateway in front of the toy protected resource.

Every call passes through here: validate the delegated token (not the raw identity strings —
this is the one place in the service that actually gates on what `/token/exchange` minted),
re-check the action is within the *token's own* narrowed scope (not just what the underlying
Delegation would allow — a token scoped to `read` must not be usable for `export` even if the
Delegation separately permits both; this is the same discipline MCP's 2025-06-18 spec forces with
audience-bound, non-passthrough tokens), call the PDP, and — only on PERMIT — perform credential
injection: fetch the downstream secret server-side and use it, never handing it to the caller.
This is Roblox's Ring 4 pattern, in miniature.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlmodel import Session

from sage.downstream import INTERNAL_KEY, DownstreamAuthError, fetch_document
from sage.models import Decision
from sage.pdp import decide
from sage.tokens import ExchangeError, agent_id_from_spiffe, verify_exchanged_token


@dataclass
class GatewayResult:
    decision: Decision
    policy: str
    facts: list[str]
    reason: str
    obligation_id: Optional[str] = None
    content: Optional[str] = None


class GatewayError(Exception):
    """Token invalid, or the action isn't within the token's own scope — rejected before the PDP
    is even consulted, since an out-of-scope request isn't a policy question, it's a malformed
    one."""


def handle(session: Session, *, access_token: str, action: str, resource_id: str) -> GatewayResult:
    try:
        claims = verify_exchanged_token(access_token)
    except ExchangeError as exc:
        raise GatewayError(f"token rejected: {exc}") from exc

    if action not in claims.get("scope", []):
        raise GatewayError(
            f"action '{action}' is outside this token's own scope {claims.get('scope')} "
            "— re-exchange is required to widen it, and re-exchange enforces non-increase"
        )

    principal_id = claims["sub"]
    agent_id = agent_id_from_spiffe(claims["act"]["sub"])

    result = decide(
        session, subject_id=agent_id, principal_id=principal_id, action=action, resource_id=resource_id
    )

    content = None
    if result.decision == Decision.PERMIT and action == "read":
        try:
            content = fetch_document(resource_id, internal_key=INTERNAL_KEY)
        except (DownstreamAuthError, KeyError) as exc:
            raise GatewayError(f"downstream fetch failed: {exc}") from exc

    return GatewayResult(
        decision=result.decision,
        policy=result.policy,
        facts=result.facts,
        reason=result.reason,
        obligation_id=result.obligation_id,
        content=content,
    )
