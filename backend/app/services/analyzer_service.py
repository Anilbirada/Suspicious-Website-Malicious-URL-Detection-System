"""Application orchestration service for URL analysis and history management."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import delete, desc, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings, settings
from app.features.url_extractor import (
    extract_lexical_features,
    validate_and_parse_url,
)
from app.ml.inference import IncompatibleModelError, MLModelService, ModelUnavailableError
from app.models.entities import AnalysisRecord
from app.schemas.analysis import (
    AnalysisMethod,
    AnalyzeURLRequest,
    AnalyzeURLResponse,
    DeleteHistoryResponse,
    HistoryDetailResponse,
    HistoryItemSchema,
    HistoryListResponse,
    IndicatorSchema,
    RiskCategory,
)
from app.services.fallback_analyzer import run_rule_based_fallback


class ServiceUnavailableError(RuntimeError):
    """Raised when neither a trained ML model nor fallback mode is permitted/available."""


class HistoryDisabledError(PermissionError):
    """Raised when history operations are requested while history storage is disabled."""


class URLAnalyzerOrchestrator:
    """Coordinates validation, feature extraction, ML/fallback inference, and persistence."""

    def __init__(self, ml_service: MLModelService, app_settings: Settings = settings) -> None:
        self.ml_service = ml_service
        self.settings = app_settings

    def analyze_url(
        self,
        payload: AnalyzeURLRequest,
        db: Optional[Session] = None,
    ) -> AnalyzeURLResponse:
        """Validate, extract features, run ML or fallback analysis, and optionally store history."""
        parsed = validate_and_parse_url(payload.url, max_length=self.settings.max_url_length)
        features = extract_lexical_features(parsed)

        use_fallback = payload.force_fallback or not self.ml_service.is_loaded
        if use_fallback and not self.settings.allow_fallback_mode and not payload.force_fallback:
            raise ServiceUnavailableError(
                "Trained machine-learning model is currently unavailable and fallback mode is disabled."
            )

        if not use_fallback:
            try:
                ml_res = self.ml_service.predict(parsed, features)
                risk_category = ml_res.risk_category
                analysis_method = ml_res.analysis_method
                is_fallback = False
                model_version = ml_res.model_version
                model_type = ml_res.model_type
                feature_schema_version = ml_res.feature_schema_version
                calibrated_score = ml_res.calibrated_score
                heuristic_score_note = ml_res.heuristic_score_note
                indicators = ml_res.indicators
                recommended_actions = ml_res.recommended_actions
                limitations_notice = ml_res.limitations_notice
            except (ModelUnavailableError, IncompatibleModelError) as exc:
                if not self.settings.allow_fallback_mode:
                    raise ServiceUnavailableError(
                        "Trained ML model could not complete inference and fallback mode is disabled."
                    ) from exc
                use_fallback = True

        if use_fallback:
            fb_res = run_rule_based_fallback(parsed, features)
            risk_category = fb_res.risk_category
            analysis_method = fb_res.analysis_method
            is_fallback = True
            model_version = None
            model_type = "Deterministic Lexical Heuristic Engine"
            feature_schema_version = fb_res.feature_schema_version
            calibrated_score = None
            heuristic_score_note = fb_res.heuristic_score_note
            indicators = fb_res.indicators
            recommended_actions = fb_res.recommended_actions
            limitations_notice = fb_res.limitations_notice

        analysis_id = str(uuid.uuid4())
        analyzed_at = datetime.now(timezone.utc)
        stored_in_history = False

        if self.settings.enable_history and payload.save_to_history and db is not None:
            stored_url = (
                parsed.original_url
                if self.settings.store_raw_url_in_history
                else f"{parsed.scheme}://{parsed.ascii_hostname}/[redacted]"
            )
            record = AnalysisRecord(
                id=analysis_id,
                submitted_url=stored_url,
                normalized_url=parsed.normalized_url,
                hostname=parsed.ascii_hostname,
                registrable_domain=parsed.registrable_domain,
                url_sha256=parsed.url_sha256,
                risk_category=risk_category.value,
                analysis_method=analysis_method.value,
                is_fallback=is_fallback,
                model_version=model_version,
                feature_schema_version=feature_schema_version,
                calibrated_score=calibrated_score,
                features_json=features,
                indicators_json=[ind.model_dump() for ind in indicators],
                recommended_actions_json=recommended_actions,
                limitations_notice=limitations_notice,
                status="completed",
                analyzed_at=analyzed_at,
            )
            db.add(record)
            db.commit()
            stored_in_history = True

        return AnalyzeURLResponse(
            analysis_id=analysis_id,
            submitted_url=parsed.original_url,
            normalized_url=parsed.normalized_url,
            hostname=parsed.ascii_hostname,
            registrable_domain=parsed.registrable_domain,
            url_sha256=parsed.url_sha256,
            risk_category=risk_category,
            analysis_method=analysis_method,
            is_fallback=is_fallback,
            model_version=model_version,
            model_type=model_type,
            feature_schema_version=feature_schema_version,
            calibrated_score=calibrated_score,
            heuristic_score_note=heuristic_score_note,
            features=features,
            indicators=indicators,
            recommended_actions=recommended_actions,
            limitations_notice=limitations_notice,
            analyzed_at=analyzed_at,
            stored_in_history=stored_in_history,
        )

    def list_history(
        self,
        db: Session,
        search: Optional[str] = None,
        risk_category: Optional[RiskCategory] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> HistoryListResponse:
        """Retrieve permitted analysis history using parameterized ORM queries."""
        if not self.settings.enable_history:
            return HistoryListResponse(history_enabled=False, total=0, items=[])

        stmt = select(AnalysisRecord)
        if search and search.strip():
            pattern = f"%{search.strip()}%"
            stmt = stmt.where(
                or_(
                    AnalysisRecord.submitted_url.ilike(pattern),
                    AnalysisRecord.hostname.ilike(pattern),
                    AnalysisRecord.registrable_domain.ilike(pattern),
                )
            )
        if risk_category is not None:
            stmt = stmt.where(AnalysisRecord.risk_category == risk_category.value)

        all_matching = db.scalars(stmt.order_by(desc(AnalysisRecord.analyzed_at))).all()
        total = len(all_matching)
        sliced = all_matching[offset : offset + limit]

        items: List[HistoryItemSchema] = [
            HistoryItemSchema(
                analysis_id=rec.id,
                submitted_url=rec.submitted_url,
                normalized_url=rec.normalized_url,
                hostname=rec.hostname,
                url_sha256=rec.url_sha256,
                risk_category=RiskCategory(rec.risk_category),
                analysis_method=AnalysisMethod(rec.analysis_method),
                is_fallback=rec.is_fallback,
                model_version=rec.model_version,
                calibrated_score=rec.calibrated_score,
                analyzed_at=rec.analyzed_at,
            )
            for rec in sliced
        ]

        return HistoryListResponse(
            history_enabled=True,
            total=total,
            items=items,
        )

    def get_history_record(self, db: Session, analysis_id: str) -> Optional[HistoryDetailResponse]:
        """Return a single analysis record by ID if history is enabled."""
        if not self.settings.enable_history:
            raise HistoryDisabledError("Analysis history storage and retrieval are currently disabled.")

        stmt = select(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
        rec = db.scalar(stmt)
        if rec is None:
            return None

        return HistoryDetailResponse(
            analysis_id=rec.id,
            submitted_url=rec.submitted_url,
            normalized_url=rec.normalized_url,
            hostname=rec.hostname,
            registrable_domain=rec.registrable_domain,
            url_sha256=rec.url_sha256,
            risk_category=RiskCategory(rec.risk_category),
            analysis_method=AnalysisMethod(rec.analysis_method),
            is_fallback=rec.is_fallback,
            model_version=rec.model_version,
            feature_schema_version=rec.feature_schema_version,
            calibrated_score=rec.calibrated_score,
            features=rec.features_json,
            indicators=[IndicatorSchema(**ind) for ind in rec.indicators_json],
            recommended_actions=rec.recommended_actions_json,
            limitations_notice=rec.limitations_notice,
            analyzed_at=rec.analyzed_at,
        )

    def delete_history(self, db: Session, analysis_id: Optional[str] = None) -> DeleteHistoryResponse:
        """Delete either a specific history item or all stored history items."""
        if not self.settings.enable_history:
            raise HistoryDisabledError("Analysis history storage is currently disabled.")

        if analysis_id:
            stmt = delete(AnalysisRecord).where(AnalysisRecord.id == analysis_id)
            result = db.execute(stmt)
            db.commit()
            count = result.rowcount or 0
            return DeleteHistoryResponse(
                deleted_count=count,
                message=f"Deleted {count} history record(s)." if count else "Record not found.",
            )

        stmt = delete(AnalysisRecord)
        result = db.execute(stmt)
        db.commit()
        count = result.rowcount or 0
        return DeleteHistoryResponse(
            deleted_count=count,
            message=f"Cleared {count} analysis history record(s).",
        )
