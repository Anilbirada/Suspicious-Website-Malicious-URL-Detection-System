"""SQLAlchemy ORM entities for ANALYSIS_RECORD and MODEL_METADATA."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import Boolean, DateTime, Float, Index, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisRecord(Base):
    """Stores URL analysis history records when history persistence is enabled."""

    __tablename__ = "analysis_records"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    submitted_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    registrable_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    url_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    risk_category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    analysis_method: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_fallback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    model_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    calibrated_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    features_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    indicators_json: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False)
    recommended_actions_json: Mapped[List[str]] = mapped_column(JSON, nullable=False)
    limitations_notice: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    analyzed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    __table_args__ = (
        Index("ix_analysis_records_category_analyzed_at", "risk_category", "analyzed_at"),
    )


class ModelMetadataRecord(Base):
    """Stores metadata and evaluation provenance for registered ML models."""

    __tablename__ = "model_metadata"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    model_type: Mapped[str] = mapped_column(String(128), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    dataset_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    evaluation_metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
    )
