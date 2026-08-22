from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlmodel import Session

from sage.audit import full_log, reconcile
from sage.db import get_session, init_db
from sage.gateway import GatewayError, handle as gateway_handle
from sage.identity import CA
from sage.obligations import ApprovalError, discharge
from sage.pdp import PDP_BACKEND, decide
from sage.schemas import (
    ApproveRequest,
    ApproveResponse,
    AuthorizeRequest,
    AuthorizeResponse,
    ChainedExchangeRequest,
    GatewayResponse,
    IssueIdentityRequest,
    IssueIdentityResponse,
    SubjectTokenRequest,
    SubjectTokenResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from sage.tokens import ExchangeError, exchange, exchange_chained, issue_subject_token


def _bearer_token(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="expected 'Authorization: Bearer <token>'")
    return authorization.removeprefix("Bearer ")


@asynccontextmanager
async def _lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="sage",
    description="Delegated authorization for AI agents acting on behalf of human principals.",
    lifespan=_lifespan,
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "pdp_backend": PDP_BACKEND}


@app.post("/authorize", response_model=AuthorizeResponse)
def authorize(req: AuthorizeRequest, session: Session = Depends(get_session)) -> AuthorizeResponse:
    result = decide(
        session,
        subject_id=req.subject,
        principal_id=req.principal,
        action=req.action,
        resource_id=req.resource,
    )
    return AuthorizeResponse(
        decision=result.decision,
        subject=result.subject_id,
        principal=result.principal_id,
        action=result.action,
        resource=result.resource_id,
        policy=result.policy,
        facts=result.facts,
        reason=result.reason,
        obligation_id=result.obligation_id,
    )


@app.post("/identity/issue", response_model=IssueIdentityResponse)
def issue_identity(req: IssueIdentityRequest) -> IssueIdentityResponse:
    """Issues a SPIFFE-shaped SVID for the given agent id. No attestation of the caller — the
    disclosed gap from sage/identity.py's docstring; a real deployment would verify what's
    actually running before minting an identity for it."""
    svid = CA.issue(req.agent_id)
    return IssueIdentityResponse(spiffe_id=svid.spiffe_id, cert_pem=svid.cert_pem.decode())


@app.post("/token/subject", response_model=SubjectTokenResponse)
def token_subject(req: SubjectTokenRequest) -> SubjectTokenResponse:
    """Stands in for a real IdP issuing an OIDC ID token to an authenticated human — see
    sage/tokens.py's module docstring for what a production version would do instead."""
    return SubjectTokenResponse(subject_token=issue_subject_token(req.principal))


@app.post("/token/exchange", response_model=TokenExchangeResponse)
def token_exchange(
    req: TokenExchangeRequest, session: Session = Depends(get_session)
) -> TokenExchangeResponse:
    try:
        token = exchange(
            session,
            subject_token=req.subject_token,
            actor_cert_pem=req.actor_cert_pem.encode(),
            case=req.case,
            requested_actions=req.requested_actions,
        )
    except ExchangeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return TokenExchangeResponse(access_token=token)


@app.post("/token/exchange/chain", response_model=TokenExchangeResponse)
def token_exchange_chain(
    req: ChainedExchangeRequest, session: Session = Depends(get_session)
) -> TokenExchangeResponse:
    try:
        token = exchange_chained(
            session,
            parent_token=req.parent_token,
            sub_actor_cert_pem=req.sub_actor_cert_pem.encode(),
            requested_actions=req.requested_actions,
        )
    except ExchangeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return TokenExchangeResponse(access_token=token)


@app.get("/audit/log")
def audit_log(session: Session = Depends(get_session)) -> list[dict]:
    return full_log(session)


@app.get("/audit/reconcile")
def audit_reconcile(session: Session = Depends(get_session)) -> dict:
    violations = reconcile(session)
    return {"violations": violations, "clean": len(violations) == 0}


@app.post("/approve", response_model=ApproveResponse)
def approve(req: ApproveRequest, session: Session = Depends(get_session)) -> ApproveResponse:
    try:
        obligation = discharge(session, obligation_id=req.obligation_id, approver_id=req.approver)
    except ApprovalError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return ApproveResponse(
        obligation_id=obligation.id,
        discharged=obligation.discharged,
        discharged_by=obligation.discharged_by,
        discharged_at=obligation.discharged_at.isoformat(),
    )


@app.get("/gateway/documents/{doc_id}", response_model=GatewayResponse)
def gateway_read(
    doc_id: str, token: str = Depends(_bearer_token), session: Session = Depends(get_session)
) -> GatewayResponse:
    return _gateway_call(session, token, "read", doc_id)


@app.post("/gateway/documents/{doc_id}/export", response_model=GatewayResponse)
def gateway_export(
    doc_id: str, token: str = Depends(_bearer_token), session: Session = Depends(get_session)
) -> GatewayResponse:
    return _gateway_call(session, token, "export", doc_id)


def _gateway_call(session: Session, token: str, action: str, doc_id: str) -> GatewayResponse:
    try:
        result = gateway_handle(session, access_token=token, action=action, resource_id=doc_id)
    except GatewayError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    return GatewayResponse(
        decision=result.decision,
        policy=result.policy,
        facts=result.facts,
        reason=result.reason,
        obligation_id=result.obligation_id,
        content=result.content,
    )
