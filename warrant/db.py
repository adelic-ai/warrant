from __future__ import annotations

import os
from typing import Iterator

from sqlmodel import Session, SQLModel, create_engine

DB_PATH = os.environ.get("WARRANT_DB_PATH", "warrant.db")
ENGINE = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})


def init_db(engine=ENGINE) -> None:
    SQLModel.metadata.create_all(engine)


def get_session() -> Iterator[Session]:
    with Session(ENGINE) as session:
        yield session
