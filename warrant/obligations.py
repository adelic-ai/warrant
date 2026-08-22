"""Obligation discharge — the first deontic seam.

An obligation is discharged only through this module, only by the delegation's own principal
(never by the agent that triggered it — enforced by identity comparison, not a role flag), and
the discharge timestamp is what the gateway checks before letting the underlying action complete.
That check (`obligation.discharged and obligation.discharged_at is not None`) is the ground-truth
read: the gateway does not trust a self-reported "approved" flag from the caller, it reads the
Obligation row this module wrote.
"""
from __future__ import annotations

from sqlmodel import Session

from warrant.models import Identity, IdentityKind, Obligation, utcnow


class ApprovalError(Exception):
    pass


def discharge(session: Session, *, obligation_id: str, approver_id: str) -> Obligation:
    obligation = session.get(Obligation, obligation_id)
    if obligation is None:
        raise ApprovalError(f"no such obligation: {obligation_id}")
    if obligation.discharged:
        raise ApprovalError(f"obligation {obligation_id} was already discharged")

    if approver_id == obligation.subject_id:
        raise ApprovalError("the agent that triggered the obligation may not discharge it itself")

    approver = session.get(Identity, approver_id)
    if approver is None:
        raise ApprovalError(f"no such identity: {approver_id}")
    if approver.kind != IdentityKind.HUMAN:
        raise ApprovalError("only a human identity may discharge an obligation")
    if approver_id != obligation.principal_id:
        raise ApprovalError(
            f"only the delegating principal ({obligation.principal_id}) may approve this — "
            f"{approver_id} is not it"
        )

    obligation.discharged = True
    obligation.discharged_by = approver_id
    obligation.discharged_at = utcnow()
    session.add(obligation)
    session.commit()
    session.refresh(obligation)
    return obligation
