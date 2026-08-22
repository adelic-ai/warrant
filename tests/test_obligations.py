from sage.gateway import handle
from sage.identity import CA
from sage.models import Decision
from sage.obligations import ApprovalError, discharge
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


def test_export_requires_approval_before_completing(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    assert first.decision == Decision.REQUIRE_APPROVAL
    assert first.content is None
    assert first.obligation_id is not None


def test_agent_cannot_discharge_its_own_obligation(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    try:
        discharge(session, obligation_id=first.obligation_id, approver_id="agent:A17")
        assert False, "expected ApprovalError"
    except ApprovalError as exc:
        assert "may not discharge it itself" in str(exc)


def test_only_the_delegating_principal_may_approve(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    try:
        discharge(session, obligation_id=first.obligation_id, approver_id="user:approver")
        assert False, "expected ApprovalError"
    except ApprovalError as exc:
        assert "only the delegating principal" in str(exc)


def test_full_discharge_then_completion_flow(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    assert first.decision == Decision.REQUIRE_APPROVAL

    discharge(session, obligation_id=first.obligation_id, approver_id="user:rick")

    second = handle(session, access_token=token, action="export", resource_id="doc:123")
    assert second.decision == Decision.PERMIT
    assert second.content is not None
    assert "discharged" in " ".join(second.facts)


def test_cannot_discharge_the_same_obligation_twice(session):
    token = _export_token(session)
    first = handle(session, access_token=token, action="export", resource_id="doc:123")
    discharge(session, obligation_id=first.obligation_id, approver_id="user:rick")
    try:
        discharge(session, obligation_id=first.obligation_id, approver_id="user:rick")
        assert False, "expected ApprovalError"
    except ApprovalError as exc:
        assert "already discharged" in str(exc)


def test_approve_endpoint_over_http(client):
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    cert_pem = client.post("/identity/issue", json={"agent_id": "A17"}).json()["cert_pem"]
    access_token = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": cert_pem,
            "case": "case:42",
            "requested_actions": ["export"],
        },
    ).json()["access_token"]

    first = client.post(
        "/gateway/documents/doc:123/export", headers={"Authorization": f"Bearer {access_token}"}
    ).json()
    assert first["decision"] == "REQUIRE_APPROVAL"

    approve_resp = client.post(
        "/approve", json={"obligation_id": first["obligation_id"], "approver": "user:rick"}
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["discharged"] is True

    second = client.post(
        "/gateway/documents/doc:123/export", headers={"Authorization": f"Bearer {access_token}"}
    ).json()
    assert second["decision"] == "PERMIT"
    assert second["content"] is not None
