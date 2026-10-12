"""REST API v1 endpoints for the Suspicious Website / Malicious URL Detection System."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import enforce_rate_limit
from app.features.url_extractor import URLValidationError
from app.models.database import get_db
from app.schemas.analysis import (
    AnalyzeURLRequest,
    AnalyzeURLResponse,
    DeleteHistoryResponse,
    HealthResponse,
    HistoryDetailResponse,
    HistoryListResponse,
    ModelStatusResponse,
    RiskCategory,
)
from app.services.analyzer_service import (
    HistoryDisabledError,
    ServiceUnavailableError,
    URLAnalyzerOrchestrator,
)

router = APIRouter(prefix="/api/v1", tags=["URL Analysis API v1"])


def get_orchestrator(request: Request) -> URLAnalyzerOrchestrator:
    """Retrieve the configured URLAnalyzerOrchestrator instance from app state."""
    return request.app.state.orchestrator


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Report application availability without exposing secrets",
)
def get_health(
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> HealthResponse:
    return HealthResponse(
        status="ok",
        app_name=orchestrator.settings.app_name,
        app_version=orchestrator.settings.app_version,
        developer=orchestrator.settings.developer_name,
        model_loaded=orchestrator.ml_service.is_loaded,
        fallback_available=orchestrator.settings.allow_fallback_mode,
        history_enabled=orchestrator.settings.enable_history,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/model/status",
    response_model=ModelStatusResponse,
    summary="Report whether a trained ML model is loaded and provide safe evaluation metadata",
)
def get_model_status(
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> ModelStatusResponse:
    return orchestrator.ml_service.get_status()


@router.post(
    "/analyze",
    response_model=AnalyzeURLResponse,
    dependencies=[Depends(enforce_rate_limit)],
    summary="Validate, parse, extract lexical features, and assess a submitted URL",
)
def analyze_url_endpoint(
    payload: AnalyzeURLRequest,
    request: Request,
    db: Session = Depends(get_db),
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> AnalyzeURLResponse:
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/json"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail={
                "error_code": "UNSUPPORTED_MEDIA_TYPE",
                "message": "Content-Type must be 'application/json'.",
            },
        )

    try:
        return orchestrator.analyze_url(payload=payload, db=db)
    except URLValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error_code": exc.code,
                "message": exc.message,
            },
        ) from exc
    except ServiceUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error_code": "MODEL_UNAVAILABLE",
                "message": str(exc),
            },
        ) from exc


@router.get(
    "/history",
    response_model=HistoryListResponse,
    dependencies=[Depends(enforce_rate_limit)],
    summary="Return permitted URL analysis history when history storage is enabled",
)
def list_history_endpoint(
    search: Optional[str] = Query(default=None, max_length=256, description="Filter by hostname or URL substring"),
    risk_category: Optional[RiskCategory] = Query(default=None, description="Filter by assessment category"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> HistoryListResponse:
    if not orchestrator.settings.enable_history:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "HISTORY_DISABLED",
                "message": "Analysis history storage and retrieval are disabled by privacy configuration.",
            },
        )
    return orchestrator.list_history(
        db=db,
        search=search,
        risk_category=risk_category,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/history/{analysis_id}",
    response_model=HistoryDetailResponse,
    dependencies=[Depends(enforce_rate_limit)],
    summary="Return a single permitted analysis history record by ID",
)
def get_history_record_endpoint(
    analysis_id: str,
    db: Session = Depends(get_db),
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> HistoryDetailResponse:
    try:
        record = orchestrator.get_history_record(db=db, analysis_id=analysis_id)
    except HistoryDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "HISTORY_DISABLED",
                "message": str(exc),
            },
        ) from exc

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error_code": "RECORD_NOT_FOUND",
                "message": "Requested analysis history record was not found.",
            },
        )
    return record


@router.delete(
    "/history",
    response_model=DeleteHistoryResponse,
    dependencies=[Depends(enforce_rate_limit)],
    summary="Delete permitted analysis history (all records or a specific analysis_id)",
)
def delete_history_endpoint(
    analysis_id: Optional[str] = Query(default=None, max_length=64, description="Optional specific analysis ID to delete"),
    db: Session = Depends(get_db),
    orchestrator: URLAnalyzerOrchestrator = Depends(get_orchestrator),
) -> DeleteHistoryResponse:
    try:
        return orchestrator.delete_history(db=db, analysis_id=analysis_id)
    except HistoryDisabledError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "HISTORY_DISABLED",
                "message": str(exc),
            },
        ) from exc
