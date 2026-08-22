def test_audit_log_lists_every_decision(client):
    client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:123"},
    )
    client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:999"},
    )
    log = client.get("/audit/log").json()
    assert len(log) == 2
    assert log[0]["decision"] == "PERMIT"
    assert log[1]["decision"] == "FORBID"
    assert isinstance(log[0]["facts"], list)
