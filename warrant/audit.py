"""Audit reconciliation — the concrete, working version of "don't trust self-report."

`record_completion` is what the gateway calls when it completes an action after an obligation's
discharge — a distinct audit event from the PDP's own REQUIRE_APPROVAL log, so the trail actually
shows what happened. `reconcile` then checks every such completion against the Obligation row it
claims discharge from: flagging anything that ran before its own discharge timestamp is the
miniature version of warden/agentwatch's self-report-vs-ground-truth reconciliation, applied here
to obligation-discharge instead of OS-level syscalls. The "ground truth" in this case is the
Obligation row a *separate* identity (the approver, via /approve) wrote — never the completion
record's own claim about itself.
"""
from __future__ import annotations

import json

from sqlmodel import Session, select

from warrant.models import AuditRecord, Decision, Obligation

COMPLETION_POLICY = "OBLIGATION-DISCHARGED-COMPLETION"


def record_completion(
    session: Session,
    *,
    subject_id: str,
    principal_id: str,
    action: str,
    resource_id: str,
    obligation_id: str,
    facts: list[str],
) -> None:
    session.add(
        AuditRecord(
            subject_id=subject_id,
            principal_id=principal_id,
            action=action,
            resource_id=resource_id,
            decision=Decision.PERMIT,
            policy=COMPLETION_POLICY,
            facts=json.dumps(facts),
            reason=f"Completed after obligation {obligation_id} was discharged.",
            obligation_id=obligation_id,
        )
    )
    session.commit()


def full_log(session: Session) -> list[dict]:
    """The complete audit trail, oldest first — every /authorize and gateway decision, each a
    full justified verdict. Read-only; nothing here is ever mutated after the fact."""
    records = session.exec(select(AuditRecord).order_by(AuditRecord.timestamp)).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "subject": r.subject_id,
            "principal": r.principal_id,
            "action": r.action,
            "resource": r.resource_id,
            "decision": r.decision,
            "policy": r.policy,
            "facts": json.loads(r.facts),
            "reason": r.reason,
            "obligation_id": r.obligation_id,
        }
        for r in records
    ]


def reconcile(session: Session) -> list[dict]:
    violations: list[dict] = []
    records = session.exec(select(AuditRecord).where(AuditRecord.policy == COMPLETION_POLICY)).all()
    for record in records:
        if record.obligation_id is None:
            continue
        obligation = session.get(Obligation, record.obligation_id)
        if obligation is None or not obligation.discharged or obligation.discharged_at is None:
            violations.append(
                {
                    "audit_record_id": record.id,
                    "obligation_id": record.obligation_id,
                    "violation": "completed with no valid discharge on record",
                }
            )
            continue
        record_ts = record.timestamp
        discharged_ts = obligation.discharged_at
        if record_ts < discharged_ts:
            violations.append(
                {
                    "audit_record_id": record.id,
                    "obligation_id": obligation.id,
                    "violation": "completed before its obligation was discharged",
                    "completed_at": record_ts.isoformat(),
                    "discharged_at": discharged_ts.isoformat(),
                }
            )
    return violations
