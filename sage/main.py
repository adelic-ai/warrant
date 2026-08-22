from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlmodel import Session

from sage.db import get_session, init_db
from sage.pdp import PDP_BACKEND, decide
from sage.schemas import AuthorizeRequest, AuthorizeResponse


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
