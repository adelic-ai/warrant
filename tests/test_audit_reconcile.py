import datetime
import json

from sage.audit import COMPLETION_POLICY, reconcile
from sage.gateway import handle
from sage.identity import CA
from sage.models import AuditRecord, Decision, Obligation
from sage.obligations import discharge
from sage.tokens import exchange, issue_subject_token


def _export_token(session):
    subject_token = issue_subject_token("user:rick")
    return exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["export"],
    )


def test_reconcile_is_clean_after_a_legitimate_discharge_and_completion(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    discharge(session, obligation_id=first.obligation_id, approver_id="user:rick")
    second = handle(session, access_token=token, action="export", resource_id="doc:123")
    assert second.decision == Decision.PERMIT

    report = reconcile(session)
    assert report == []


def test_reconcile_flags_a_completion_that_predates_its_own_discharge(session):
    # Manufacture the exact scenario the sibling `warden` project's reconciliation philosophy is
    # built to catch: a completion whose own timestamp is BEFORE the discharge it claims to rest
    # on — i.e. it ran before it was actually approved. This bypasses the gateway entirely (which
    # would never construct this state honestly) to prove the checker itself catches it.
    obligation = Obligation(
        subject_id="agent:A17",
        principal_id="user:rick",
        action="export",
        resource_id="doc:123",
        delegation_id="del_demo42",
        discharged=True,
        discharged_by="user:rick",
        discharged_at=datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc),
    )
    session.add(obligation)
    session.commit()
    session.refresh(obligation)

    backdated_completion = AuditRecord(
        subject_id="agent:A17",
        principal_id="user:rick",
        action="export",
        resource_id="doc:123",
        decision=Decision.PERMIT,
        policy=COMPLETION_POLICY,
        facts=json.dumps(["fabricated"]),
        reason="claims completion after discharge",
        obligation_id=obligation.id,
        timestamp=datetime.datetime(2026, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc),  # 1h BEFORE discharge
    )
    session.add(backdated_completion)
    session.commit()

    report = reconcile(session)
    assert len(report) == 1
    assert report[0]["violation"] == "completed before its obligation was discharged"
    assert report[0]["obligation_id"] == obligation.id


def test_reconcile_endpoint_over_http(client):
    resp = client.get("/audit/reconcile")
    assert resp.status_code == 200
    assert resp.json() == {"violations": [], "clean": True}
