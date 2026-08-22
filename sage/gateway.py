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

from sage.audit import record_completion
from sage.downstream import INTERNAL_KEY, DownstreamAuthError, fetch_document
from sage.models import Decision, Obligation
from sage.pdp import decide
from sage.tokens import ExchangeError, agent_id_from_spiffe, root_spiffe_from_claims, verify_exchanged_token


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
    immediate_agent_id = agent_id_from_spiffe(claims["act"]["sub"])
    root_agent_id = agent_id_from_spiffe(root_spiffe_from_claims(claims))

    # The PDP checks the ROOT of the delegation chain — that's where the actual human-granted
    # Delegation row lives. A sub-agent's authority is a narrowed view of that same grant (already
    # enforced at exchange time by exchange_chained's scope-non-increase check), not a separate one.
    result = decide(
        session, subject_id=root_agent_id, principal_id=principal_id, action=action, resource_id=resource_id
    )

    content = None
    facts = list(result.facts)
    if immediate_agent_id != root_agent_id:
        facts.append(f"acting via delegation chain: {immediate_agent_id} <- {root_agent_id}")
    decision = result.decision

    if decision == Decision.PERMIT and action == "read":
        try:
            content = fetch_document(resource_id, internal_key=INTERNAL_KEY)
        except (DownstreamAuthError, KeyError) as exc:
            raise GatewayError(f"downstream fetch failed: {exc}") from exc

    if decision == Decision.REQUIRE_APPROVAL and result.obligation_id is not None:
        # Ground-truth check, not a trusted self-report: read the Obligation row a *distinct*
        # /approve call wrote, not any flag the caller of this gateway request could set itself.
        obligation = session.get(Obligation, result.obligation_id)
        if obligation is not None and obligation.discharged and obligation.discharged_at is not None:
            facts.append(
                f"obligation {obligation.id} discharged by {obligation.discharged_by} "
                f"at {obligation.discharged_at.isoformat()} — completing now"
            )
            try:
                content = fetch_document(resource_id, internal_key=INTERNAL_KEY)
            except (DownstreamAuthError, KeyError) as exc:
                raise GatewayError(f"downstream fetch failed: {exc}") from exc
            decision = Decision.PERMIT
            # A distinct audit event for the completion itself — the underlying decide() call
            # above still logged REQUIRE_APPROVAL (it has no notion of discharge state), so
            # without this the trail would never show that the action actually completed.
            record_completion(
                session,
                subject_id=root_agent_id,
                principal_id=principal_id,
                action=action,
                resource_id=resource_id,
                obligation_id=obligation.id,
                facts=facts,
            )

    return GatewayResult(
        decision=decision,
        policy=result.policy,
        facts=facts,
        reason=result.reason,
        obligation_id=result.obligation_id,
        content=content,
    )
