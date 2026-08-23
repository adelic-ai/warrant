from tests.conftest import bootstrap_headers
from warrant.identity import CA
from warrant.tokens import ExchangeError, exchange, exchange_chained, issue_subject_token, verify_exchanged_token


def test_chained_exchange_over_http(client):
    subject_token = client.post("/token/subject", json={"principal": "user:rick"}).json()["subject_token"]
    a17_cert = client.post(
        "/identity/issue", json={"agent_id": "A17"}, headers=bootstrap_headers("A17")
    ).json()["cert_pem"]
    hop1 = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": a17_cert,
            "case": "case:42",
            "requested_actions": ["read", "export"],
        },
    ).json()["access_token"]

    b1_cert = client.post(
        "/identity/issue", json={"agent_id": "B1"}, headers=bootstrap_headers("B1")
    ).json()["cert_pem"]
    resp = client.post(
        "/token/exchange/chain",
        json={"parent_token": hop1, "sub_actor_cert_pem": b1_cert, "requested_actions": ["read"]},
    )
    assert resp.status_code == 200
    from warrant.tokens import verify_exchanged_token as verify

    claims = verify(resp.json()["access_token"])
    assert claims["act"]["sub"] == "spiffe://warrant.local/agent/B1"
    assert claims["act"]["act"]["sub"] == "spiffe://warrant.local/agent/A17"
    assert claims["scope"] == ["read"]

    # And a widen attempt over HTTP is rejected too — hop1 itself has both actions, so construct
    # a genuinely-narrower parent token to make the rejection meaningful.
    narrow_hop1 = client.post(
        "/token/exchange",
        json={
            "subject_token": subject_token,
            "actor_cert_pem": a17_cert,
            "case": "case:42",
            "requested_actions": ["read"],
        },
    ).json()["access_token"]
    widen_resp = client.post(
        "/token/exchange/chain",
        json={"parent_token": narrow_hop1, "sub_actor_cert_pem": b1_cert, "requested_actions": ["read", "export"]},
    )
    assert widen_resp.status_code == 400
    assert "exceeds the parent token's own scope" in widen_resp.json()["detail"]


def test_three_hop_chain_scope_narrows_and_both_identities_are_nested(session):
    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],
    )
    hop2 = exchange_chained(
        session,
        parent_token=hop1,
        sub_actor_cert_pem=CA.issue("B1").cert_pem,
        requested_actions=["read"],
    )
    claims = verify_exchanged_token(hop2)
    assert claims["sub"] == "user:rick"  # the human principal is unchanged, three hops in
    assert claims["act"]["sub"] == "spiffe://warrant.local/agent/B1"
    assert claims["act"]["act"]["sub"] == "spiffe://warrant.local/agent/A17"  # nested, not flattened
    assert claims["scope"] == ["read"]


def test_chain_rejects_a_widen_attempt_at_the_second_hop(session):
    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],  # narrow — no export
    )
    try:
        exchange_chained(
            session,
            parent_token=hop1,
            sub_actor_cert_pem=CA.issue("B1").cert_pem,
            requested_actions=["read", "export"],  # sub-agent tries to widen beyond the parent
        )
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "exceeds the parent token's own scope" in str(exc)


def test_chain_rejects_an_unverifiable_sub_actor(session):
    from warrant.identity import LocalCA

    subject_token = issue_subject_token("user:rick")
    hop1 = exchange(
        session,
        subject_token=subject_token,
        actor_cert_pem=CA.issue("A17").cert_pem,
        case="case:42",
        requested_actions=["read"],
    )
    forged = LocalCA().issue("B1").cert_pem
    try:
        exchange_chained(session, parent_token=hop1, sub_actor_cert_pem=forged, requested_actions=["read"])
        assert False, "expected ExchangeError"
    except ExchangeError as exc:
        assert "verification" in str(exc)
