from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlalchemy.pool import StaticPool

from warrant.db import get_session
from warrant.main import app
from warrant.seed import seed_demo

# Fixed per-agent bootstrap secrets for the two agent ids the test suite ever issues identities
# for (A17, B1) — /identity/issue requires one of these since it started gating on
# check_bootstrap_token. Use bootstrap_headers(agent_id) at call sites rather than hardcoding
# the header dict, so a future rename here only touches one place.
BOOTSTRAP_TOKENS = {"A17": "test-bootstrap-a17", "B1": "test-bootstrap-b1"}


def bootstrap_headers(agent_id: str) -> dict[str, str]:
    return {"X-Bootstrap-Token": BOOTSTRAP_TOKENS[agent_id]}


@pytest.fixture(autouse=True)
def _bootstrap_tokens_env(monkeypatch):
    monkeypatch.setenv("WARRANT_BOOTSTRAP_TOKENS", json.dumps(BOOTSTRAP_TOKENS))


@pytest.fixture()
def engine():
    eng = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        seed_demo(s)
    return eng


@pytest.fixture()
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture()
def client(engine):
    def _override():
        with Session(engine) as s:
            yield s

    app.dependency_overrides[get_session] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
