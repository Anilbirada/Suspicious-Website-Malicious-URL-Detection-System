"""SQLAlchemy database engine and session management."""

from __future__ import annotations

from typing import Generator

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Base declarative class for SQLAlchemy ORM models."""


def create_engine_from_url(db_url: str):
    connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
    return create_engine(db_url, connect_args=connect_args, future=True)


engine = create_engine_from_url(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db(target_engine=None) -> None:
    """Create database tables if they do not exist."""
    from app.models import entities  # noqa: F401

    Base.metadata.create_all(bind=target_engine or engine)


def get_db(request: Request) -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session bound to the current app's session factory."""
    session_factory = getattr(request.app.state, "session_factory", SessionLocal)
    db = session_factory()
    try:
        yield db
    finally:
        db.close()
