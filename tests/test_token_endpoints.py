from tests.conftest import bootstrap_headers


def test_identity_issue_endpoint(client):
    resp = client.post("/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("A17"))
    body = resp.json()
    assert resp.status_code == 200
    assert body["spiffe_id"] == "spiffe://warrant.local/agent/A17"
    assert "BEGIN CERTIFICATE" in body["cert_pem"]


def test_identity_issue_rejects_missing_bootstrap_token(client):
    resp = client.post("/identity/issue", json={"agent_id": "A17"})
    assert resp.status_code == 401


def test_identity_issue_rejects_wrong_bootstrap_token(client):
    resp = client.post(
        "/identity/issue", json={"agent_id": "A17"}, headers={"X-Bootstrap-Token": "not-the-secret"}
    )
    assert resp.status_code == 401


def test_identity_issue_rejects_token_provisioned_for_a_different_agent(client):
    # Holding a valid secret for B1 must not be usable to mint an identity claiming to be A17.
    resp = client.post("/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("B1"))
    assert resp.status_code == 401


def test_full_delegation_flow_over_http(client):
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    cert_pem = client.post(
        "/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("A17")
    ).json()["cert_pem"]

    resp = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": cert_pem,
            "case": "case:42",
            "requested_actions": ["read"],
        },
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_exchange_endpoint_rejects_widen_with_400(client):
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    cert_pem = client.post(
        "/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("A17")
    ).json()["cert_pem"]

    resp = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": cert_pem,
            "case": "case:42",
            "requested_actions": ["modify"],
        },
    )
    assert resp.status_code == 400
    assert "exceeds" in resp.json()["detail"]
