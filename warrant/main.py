from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlmodel import Session

from warrant.audit import full_log, reconcile
from warrant.db import get_session, init_db
from warrant.egress_session import allocate_session_uid, reconcile_egress, release_session_uid, start_live_proxy
from warrant.gateway import GatewayError, handle as gateway_handle
from warrant.identity import CA, check_bootstrap_token
from warrant.obligations import ApprovalError, discharge
from warrant.pdp import PDP_BACKEND, decide
from warrant.schemas import (
    ApproveRequest,
    ApproveResponse,
    AuthorizeRequest,
    AuthorizeResponse,
    ChainedExchangeRequest,
    EgressAllocateRequest,
    EgressAllocateResponse,
    EgressReleaseRequest,
    GatewayResponse,
    IssueIdentityRequest,
    IssueIdentityResponse,
    SubjectTokenRequest,
    SubjectTokenResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from warrant.tokens import ExchangeError, exchange, exchange_chained, issue_subject_token, verify_exchanged_token
from warrant.uid_pool import ensure_nftables_rule, username_for


def _bearer_token(authorization: str = Header(...)) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="expected 'Authorization: Bearer <token>'")
    return authorization.removeprefix("Bearer ")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    proxy = None
    # Read fresh at startup, not cached at import time -- so a test (or a deployment's own env)
    # setting this right before the app actually starts takes effect, rather than only whatever
    # was set when this module first happened to be imported. Opt-in, off by default: every
    # existing test (TestClient, no root, often not even Linux) keeps starting the app exactly as
    # it did before this feature existed. Fails loudly rather than silently skipping enforcement
    # if set without root/Linux -- never a downgrade nobody asked for.
    enabled = os.environ.get("WARRANT_EGRESS_PROXY_ENABLED", "").strip().lower() in ("1", "true", "yes")
    if enabled:
        port = int(os.environ.get("WARRANT_EGRESS_PROXY_PORT", "18080"))
        proxy = start_live_proxy(port=port)
        ensure_nftables_rule(proxy.port)
        app.state.egress_proxy = proxy
    yield
    if proxy is not None:
        proxy.stop()


app = FastAPI(
    title="Warrant",
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
def issue_identity(
    req: IssueIdentityRequest, x_bootstrap_token: str = Header(default=None)
) -> IssueIdentityResponse:
    """Issues a SPIFFE-shaped SVID for the given agent id, gated on a pre-shared bootstrap token
    for that specific agent_id (WARRANT_BOOTSTRAP_TOKENS) — not real attestation of what's
    actually running (the remaining disclosed gap, see warrant/identity.py's docstring), but it
    closes "any caller can mint an identity for any agent_id" down to "you need the secret
    provisioned out-of-band for this one"."""
    if not check_bootstrap_token(req.agent_id, x_bootstrap_token):
        raise HTTPException(
            status_code=401, detail=f"missing or invalid bootstrap token for agent_id={req.agent_id!r}"
        )
    svid = CA.issue(req.agent_id)
    return IssueIdentityResponse(spiffe_id=svid.spiffe_id, cert_pem=svid.cert_pem.decode())


@app.post("/token/subject", response_model=SubjectTokenResponse)
def token_subject(req: SubjectTokenRequest) -> SubjectTokenResponse:
    """Stands in for a real IdP issuing an OIDC ID token to an authenticated human — see
    warrant/tokens.py's module docstring for what a production version would do instead."""
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


@app.get("/audit/reconcile/egress")
def audit_reconcile_egress(session: Session = Depends(get_session)) -> dict:
    """Kept as a separate endpoint from /audit/reconcile rather than merged into it: these are two
    different kinds of check (obligation-discharge timing vs. independently-observed network
    egress), and combining them into one violations list would lose that distinction the same way
    a single combined 'deviation' number would (see the considerations doc's own citation of
    agentwatch's CONFIRMED/GAP/NONE staying separate on purpose)."""
    violations = reconcile_egress(session)
    return {"violations": violations, "clean": len(violations) == 0}


@app.post("/egress/allocate", response_model=EgressAllocateResponse)
def egress_allocate(
    req: EgressAllocateRequest, session: Session = Depends(get_session)
) -> EgressAllocateResponse:
    """Provisions a real ephemeral OS user for this token's work window. The caller — whoever is
    about to actually launch the agent process this token authorizes — uses the returned uid/
    username to run that process as; this endpoint does not launch anything itself."""
    try:
        claims = verify_exchanged_token(req.access_token)
    except ExchangeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    uid = allocate_session_uid(session, token_jti=claims["jti"])
    return EgressAllocateResponse(uid=uid, username=username_for(uid))


@app.post("/egress/release")
def egress_release(req: EgressReleaseRequest, session: Session = Depends(get_session)) -> dict:
    try:
        claims = verify_exchanged_token(req.access_token)
    except ExchangeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    release_session_uid(session, token_jti=claims["jti"])
    return {"released": True}


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
