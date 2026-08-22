from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from sage.models import Decision


class AuthorizeRequest(BaseModel):
    subject: str  # agent identity, e.g. "agent:A17"
    principal: str  # human identity, e.g. "user:rick"
    action: str
    resource: str
    context: dict = {}


class AuthorizeResponse(BaseModel):
    decision: Decision
    subject: str
    principal: str
    action: str
    resource: str
    policy: str
    facts: list[str]
    reason: str
    obligation_id: Optional[str] = None


class ApproveRequest(BaseModel):
    obligation_id: str
    approver: str  # must be a HUMAN identity distinct from the agent that triggered it
