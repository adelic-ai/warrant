from __future__ import annotations

from sqlmodel import select

from warrant.models import AuditRecord, Decision


def test_permit_read_in_scope(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:123"},
    )
    body = resp.json()
    assert resp.status_code == 200
    assert body["decision"] == "PERMIT"
    assert body["obligation_id"] is None
    assert body["facts"]  # justified, not a bare boolean
    assert "case:42" in " ".join(body["facts"])


def test_require_approval_export(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "export", "resource": "doc:123"},
    )
    body = resp.json()
    assert body["decision"] == "REQUIRE_APPROVAL"
    assert body["obligation_id"] is not None
    assert body["policy"] == "CASE-DOCUMENT-EXPORT-01"


def test_forbid_out_of_scope(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:999"},
    )
    body = resp.json()
    assert body["decision"] == "FORBID"
    assert "case:99" in " ".join(body["facts"])
    assert body["reason"]


def test_forbid_explicit_modify(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "modify", "resource": "doc:123"},
    )
    body = resp.json()
    assert body["decision"] == "FORBID"
    assert "forbid" in body["reason"].lower()


def test_forbid_unknown_resource(client):
    resp = client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:does-not-exist"},
    )
    assert resp.json()["decision"] == "FORBID"


def test_every_decision_is_audited(client, engine):
    client.post(
        "/authorize",
        json={"subject": "agent:A17", "principal": "user:rick", "action": "read", "resource": "doc:123"},
    )
    from sqlmodel import Session

    with Session(engine) as s:
        records = s.exec(select(AuditRecord)).all()
    assert len(records) == 1
    assert records[0].decision == Decision.PERMIT
    assert records[0].facts  # non-empty JSON facts, never a bare boolean
