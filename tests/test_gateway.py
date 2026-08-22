import json

from sage.gateway import GatewayError, handle
from sage.identity import CA
from sage.models import Decision
from sage.tokens import exchange, issue_subject_token


def _token(session, actions, case="case:42", agent="A17"):
    subject_token = issue_subject_token("user:rick")
    return exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue(agent).cert_pem,
        case=case,
        requested_actions=actions,
    )


def test_permit_read_injects_credential_never_exposes_it(session):
    token = _token(session, ["read"])
    result = handle(session, access_token=token, action="read", resource_id="doc:123")
    assert result.decision == Decision.PERMIT
    assert "deposition" in result.content
    # The internal credential must never appear anywhere in the result we hand back to the caller.
    from sage.downstream import INTERNAL_KEY

    serialized = json.dumps(result.__dict__)
    assert INTERNAL_KEY not in serialized


def test_action_outside_tokens_own_scope_is_rejected_before_pdp(session):
    # Delegation permits both read and export(-with-approval), but this token was only minted
    # for "read" — the gateway must enforce the token's own narrower scope, not the delegation's.
    token = _token(session, ["read"])
    try:
        handle(session, access_token=token, action="export", resource_id="doc:123")
        assert False, "expected GatewayError"
    except GatewayError as exc:
        assert "outside this token's own scope" in str(exc)


def test_require_approval_returns_obligation_no_content(session):
    token = _token(session, ["export"])
    result = handle(session, access_token=token, action="export", resource_id="doc:123")
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.obligation_id is not None
    assert result.content is None


def test_forbid_out_of_scope_resource_no_content(session):
    # doc:999 belongs to case:99 — no delegation covers it, so exchanging for case:42 and then
    # asking the gateway to read doc:999 must FORBID at the PDP, not at the gateway/token layer.
    token = _token(session, ["read"])
    result = handle(session, access_token=token, action="read", resource_id="doc:999")
    assert result.decision == Decision.FORBID
    assert result.content is None


def test_gateway_over_http(client):
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    cert_pem = client.post("/identity/issue", json={"agent_id": "A17"}).json()["cert_pem"]
    access_token = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": cert_pem,
            "case": "case:42",
            "requested_actions": ["read"],
        },
    ).json()["access_token"]

    resp = client.get("/gateway/documents/doc:123", headers={"Authorization": f"Bearer {access_token}"})
    body = resp.json()
    assert resp.status_code == 200
    assert body["decision"] == "PERMIT"
    assert "deposition" in body["content"]

    # No token at all -> 401/422 depending on how FastAPI reports a missing required header.
    resp_no_auth = client.get("/gateway/documents/doc:123")
    assert resp_no_auth.status_code in (401, 422)
