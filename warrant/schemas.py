from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from warrant.models import Decision


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


class ApproveResponse(BaseModel):
    obligation_id: str
    discharged: bool
    discharged_by: str
    discharged_at: str


class SubjectTokenRequest(BaseModel):
    principal: str


class SubjectTokenResponse(BaseModel):
    subject_token: str


class IssueIdentityRequest(BaseModel):
    agent_id: str


class IssueIdentityResponse(BaseModel):
    spiffe_id: str
    cert_pem: str


class TokenExchangeRequest(BaseModel):
    subject_token: str
    actor_cert_pem: str
    case: str
    requested_actions: list[str]


class TokenExchangeResponse(BaseModel):
    access_token: str


class ChainedExchangeRequest(BaseModel):
    parent_token: str
    sub_actor_cert_pem: str
    requested_actions: list[str]


class GatewayResponse(BaseModel):
    decision: Decision
    policy: str
    facts: list[str]
    reason: str
    obligation_id: Optional[str] = None
    content: Optional[str] = None


class EgressAllocateRequest(BaseModel):
    access_token: str


class EgressAllocateResponse(BaseModel):
    uid: int
    username: str


class EgressReleaseRequest(BaseModel):
    access_token: str
