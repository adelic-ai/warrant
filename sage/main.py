from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from sqlmodel import Session

from sage.db import get_session, init_db
from sage.identity import CA
from sage.pdp import PDP_BACKEND, decide
from sage.schemas import (
    AuthorizeRequest,
    AuthorizeResponse,
    IssueIdentityRequest,
    IssueIdentityResponse,
    SubjectTokenRequest,
    SubjectTokenResponse,
    TokenExchangeRequest,
    TokenExchangeResponse,
)
from sage.tokens import ExchangeError, exchange, issue_subject_token


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
