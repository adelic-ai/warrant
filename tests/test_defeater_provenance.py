def test_permit_decision_surfaces_delegation_provenance(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:123"},
    )
    facts = " ".join(resp.json()["facts"])
    assert "owner=user:rick" in facts
    assert "reason=" in facts
    assert "Agent17 assists Rick" in facts
    assert "reviewed=" in facts
    assert "never reviewed" not in facts  # seed data sets reviewed_at explicitly


def test_forbid_explicit_still_shows_why_the_delegation_wasnt_a_blanket_deny(client):
    # 'modify' is explicitly forbidden — the response should still show whose delegation this
    # is and why it exists, not just "forbidden", since the reader needs to see the same
    # delegation that permits read is what's being consulted here.
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "modify", "resource": "doc:123"},
    )
    facts = " ".join(resp.json()["facts"])
    assert "owner=user:rick" in facts
