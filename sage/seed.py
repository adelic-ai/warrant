"""Canonical demo data — the same scenario used throughout the README and the test suite:

Rick (human) delegates read + export-with-approval on Case 42 to Agent17. Document123 is in
Case42; Document999 is in a different case Rick never delegated.
"""
from __future__ import annotations

from datetime import timedelta

from sqlmodel import Session

from sage.models import Delegation, Identity, IdentityKind, Resource, utcnow


def seed_demo(session: Session) -> None:
    session.add(Identity(id="user:rick", kind=IdentityKind.HUMAN, display_name="Rick"))
    session.add(Identity(id="user:approver", kind=IdentityKind.HUMAN, display_name="Rick (approver context)"))
    session.add(Identity(id="agent:A17", kind=IdentityKind.AGENT, display_name="Agent17"))
    session.add(Resource(id="doc:123", kind="SensitiveDocument", belongs_to="case:42"))
    session.add(Resource(id="doc:999", kind="SensitiveDocument", belongs_to="case:99"))
    session.add(
        Delegation(
            id="del_demo42",
            principal_id="user:rick",
            delegate_id="agent:A17",
            scope="case:42",
            permitted_actions="read",
            requires_approval_actions="export",
            forbidden_actions="modify",
            expires_at=utcnow() + timedelta(minutes=30),
            granted_reason="Agent17 assists Rick's review of Case 42 documents",
            reviewed_at=utcnow(),
        )
    )
    session.commit()
