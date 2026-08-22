"""Policy Decision Point.

`decide()` is the one seam the rest of the service depends on. The pre-checks (unknown resource,
expiry, explicit forbid, requires-approval) are plain Python and always run first — those are the
deontic-seam wrapper the architecture research calls out as the actual contribution. The final
affirmative-grant question ("is this action permitted") is delegated to Cedar when the `cedarpy`
wheel is installed, and to an equivalent plain-Python `in` check when it isn't. Which backend is
active is exposed via `PDP_BACKEND` below and surfaced at `/health` — never silently substituted.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from sqlmodel import Session, select

from warrant.cedar_backend import CEDAR_AVAILABLE, cedar_permits
from warrant.models import AuditRecord, Decision, Delegation, Obligation, Resource, utcnow

PDP_BACKEND = "cedar" if CEDAR_AVAILABLE else "python-fallback"


def _is_permitted(subject_id: str, action: str, resource_id: str, delegation: Delegation) -> bool:
    if CEDAR_AVAILABLE:
        return cedar_permits(subject_id, action, resource_id, delegation.permitted)
    return action in delegation.permitted

POLICY_PERMIT = "AGENT-DELEGATION-01"
POLICY_FORBID_NO_DELEGATION = "AGENT-DELEGATION-02"
POLICY_FORBID_EXPLICIT = "AGENT-DELEGATION-03"
POLICY_REQUIRE_APPROVAL = "CASE-DOCUMENT-EXPORT-01"
POLICY_UNKNOWN_RESOURCE = "AGENT-DELEGATION-04"
POLICY_EXPIRED = "AGENT-DELEGATION-05"


@dataclass
class AuthorizationResult:
    decision: Decision
    subject_id: str
    principal_id: str
    action: str
    resource_id: str
    policy: str
    facts: list[str] = field(default_factory=list)
    reason: str = ""
    obligation_id: Optional[str] = None


def find_active_delegation(
    session: Session, *, principal_id: str, delegate_id: str, scope: str
) -> Optional[Delegation]:
    stmt = select(Delegation).where(
        Delegation.principal_id == principal_id,
        Delegation.delegate_id == delegate_id,
        Delegation.scope == scope,
    )
    candidates = session.exec(stmt).all()
    for d in candidates:
        if not d.is_expired():
            return d
    return None


def decide(
    session: Session,
    *,
    subject_id: str,
    principal_id: str,
    action: str,
    resource_id: str,
) -> AuthorizationResult:
    resource = session.get(Resource, resource_id)
    if resource is None:
        result = AuthorizationResult(
            decision=Decision.FORBID,
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            policy=POLICY_UNKNOWN_RESOURCE,
            facts=[f"{resource_id} is not a known resource"],
            reason="Resource does not exist.",
        )
        _record(session, result)
        return result

    delegation = find_active_delegation(
        session, principal_id=principal_id, delegate_id=subject_id, scope=resource.belongs_to
    )
    facts = [f"{resource_id} belongsTo {resource.belongs_to}"]

    if delegation is None:
        # Distinguish "expired" from "never existed" for a better `reason`, if any candidate exists.
        stmt = select(Delegation).where(
            Delegation.principal_id == principal_id,
            Delegation.delegate_id == subject_id,
            Delegation.scope == resource.belongs_to,
        )
        any_candidate = session.exec(stmt).first()
        if any_candidate is not None:
            facts.append(f"{subject_id} had a delegation for {resource.belongs_to}, now expired")
            policy, reason = POLICY_EXPIRED, "Delegation for this scope has expired."
        else:
            facts.append(f"{subject_id} actsOnBehalfOf {principal_id}")
            facts.append(f"no delegation covers scope {resource.belongs_to}")
            policy, reason = (
                POLICY_FORBID_NO_DELEGATION,
                "Requested action exceeds delegated authority — no delegation covers this scope.",
            )
        result = AuthorizationResult(
            decision=Decision.FORBID,
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            policy=policy,
            facts=facts,
            reason=reason,
        )
        _record(session, result)
        return result

    facts.append(f"{subject_id} actsOnBehalfOf {principal_id}")
    facts.append(f"delegation {delegation.id} scoped to {delegation.scope}")
    # Defeater provenance — the delegation is the only thing here that can override a
    # default-deny, so every decision that reaches this point answers "why wasn't this
    # forbidden" with who granted it, why, and when it was last reviewed — not just "it wasn't."
    reviewed = delegation.reviewed_at.isoformat() if delegation.reviewed_at else "never reviewed"
    facts.append(
        f"delegation {delegation.id} owner={delegation.principal_id} "
        f'reason="{delegation.granted_reason}" reviewed={reviewed}'
    )

    if action in delegation.forbidden:
        facts.append(f"delegation explicitly forbids {action}")
        result = AuthorizationResult(
            decision=Decision.FORBID,
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            policy=POLICY_FORBID_EXPLICIT,
            facts=facts,
            reason=f"Delegation explicitly forbids '{action}'.",
        )
        _record(session, result)
        return result

    if action in delegation.requires_approval:
        facts.append(f"'{action}' requires human approval under this delegation")
        result = AuthorizationResult(
            decision=Decision.REQUIRE_APPROVAL,
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            policy=POLICY_REQUIRE_APPROVAL,
            facts=facts,
            reason=f"Agent has delegated access to {delegation.scope}, but '{action}' requires human approval.",
        )
        # Reuse an existing undischarged obligation for the exact same request instead of
        # spawning a duplicate on every repeated call — the obligation identifies "this
        # requirement," not "this particular attempt."
        stmt = select(Obligation).where(
            Obligation.subject_id == subject_id,
            Obligation.principal_id == principal_id,
            Obligation.action == action,
            Obligation.resource_id == resource_id,
            Obligation.delegation_id == delegation.id,
        )
        obligation = session.exec(stmt).first()
        if obligation is None:
            obligation = Obligation(
                subject_id=subject_id,
                principal_id=principal_id,
                action=action,
                resource_id=resource_id,
                delegation_id=delegation.id,
            )
            session.add(obligation)
            session.commit()
            session.refresh(obligation)
        if obligation.discharged:
            facts.append(
                f"obligation {obligation.id} already discharged by {obligation.discharged_by} "
                f"at {obligation.discharged_at.isoformat()}"
            )
        result.obligation_id = obligation.id
        _record(session, result)
        return result

    if _is_permitted(subject_id, action, resource_id, delegation):
        facts.append(f"delegation permits '{action}' ({PDP_BACKEND} evaluator)")
        result = AuthorizationResult(
            decision=Decision.PERMIT,
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            policy=POLICY_PERMIT,
            facts=facts,
            reason=f"Delegation grants '{action}' within scope {delegation.scope}.",
        )
        _record(session, result)
        return result

    # Default deny — an action not mentioned anywhere in the delegation is not implicitly granted.
    facts.append(f"'{action}' is not mentioned in the delegation (default-deny)")
    result = AuthorizationResult(
        decision=Decision.FORBID,
        subject_id=subject_id,
        principal_id=principal_id,
        action=action,
        resource_id=resource_id,
        policy=POLICY_FORBID_NO_DELEGATION,
        facts=facts,
        reason=f"'{action}' is not granted by this delegation.",
    )
    _record(session, result)
    return result


def _record(session: Session, result: AuthorizationResult) -> None:
    session.add(
        AuditRecord(
            subject_id=result.subject_id,
            principal_id=result.principal_id,
            action=result.action,
            resource_id=result.resource_id,
            decision=result.decision,
            policy=result.policy,
            facts=json.dumps(result.facts),
            reason=result.reason,
            obligation_id=result.obligation_id,
        )
    )
    session.commit()
