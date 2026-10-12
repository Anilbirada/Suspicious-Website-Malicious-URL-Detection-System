"""Validated Pydantic v2 schemas for URL analysis, model status, and history endpoints."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BaseSchema(BaseModel):
    """Base Pydantic schema with protected_namespaces disabled for model_* fields."""

    model_config = ConfigDict(protected_namespaces=())


class RiskCategory(str, Enum):
    """Approved assessment categories required by specification."""

    POTENTIALLY_MALICIOUS = "Potentially Malicious"
    SUSPICIOUS = "Suspicious"
    LOWER_RISK = "Lower Risk Indicators Found"
    UNABLE_TO_DETERMINE = "Unable to Determine"


class AnalysisMethod(str, Enum):
    """Distinguishes trained ML inference from the isolated rule-based fallback mode."""

    TRAINED_ML = "trained_ml_model"
    RULE_BASED_FALLBACK = "rule_based_fallback"


class AnalyzeURLRequest(BaseSchema):
    """Request payload for POST /api/v1/analyze."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    url: str = Field(
        ...,
        description="The HTTP or HTTPS URL string to inspect lexically.",
        examples=["https://example.com/documentation"],
    )
    force_fallback: bool = Field(
        default=False,
        description="If true, bypasses the trained ML model and runs the isolated rule-based fallback engine.",
    )
    save_to_history: bool = Field(
        default=True,
        description="Whether to record this analysis in local history when history storage is enabled.",
    )


class IndicatorSchema(BaseSchema):
    """Individual explainable indicator associated with an analysis."""

    code: str
    title: str
    severity: str = Field(description="One of: info, low, medium, high")
    description: str
    observed_value: str
    source: str = Field(default="lexical", description="Origin of indicator (lexical, ml_contribution, or fallback_rule)")


class AnalyzeURLResponse(BaseSchema):
    """Structured assessment returned by POST /api/v1/analyze."""

    analysis_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    registrable_domain: str
    url_sha256: str
    risk_category: RiskCategory
    analysis_method: AnalysisMethod
    is_fallback: bool
    model_version: Optional[str] = None
    model_type: Optional[str] = None
    feature_schema_version: str
    calibrated_score: Optional[float] = Field(
        default=None,
        description="Calibrated ML risk score in [0.0, 1.0] when evaluated by a calibrated ML model; null in fallback mode.",
    )
    heuristic_score_note: Optional[str] = Field(
        default=None,
        description="Explanation of scoring method or fallback rule summary.",
    )
    features: Dict[str, float | int]
    indicators: List[IndicatorSchema]
    recommended_actions: List[str]
    limitations_notice: str
    analyzed_at: datetime
    stored_in_history: bool


class EvaluationMetricsSchema(BaseSchema):
    """Documented evaluation metrics from held-out test set evaluation."""

    dataset_name: str
    dataset_source: str
    dataset_licence: str
    split_method: str
    train_sample_size: int
    evaluation_sample_size: int
    precision: float
    recall: float
    f1_score: float
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    confusion_matrix: Dict[str, int]
    per_class_metrics: Dict[str, Dict[str, float]]
    thresholds: Dict[str, float]
    known_limitations: List[str]
    evaluated_at: str


class ModelStatusResponse(BaseSchema):
    """Response schema for GET /api/v1/model/status."""

    model_loaded: bool
    active_mode: AnalysisMethod
    fallback_mode_active: bool
    allow_fallback_mode: bool
    model_version: Optional[str] = None
    model_type: Optional[str] = None
    feature_schema_version: str
    expected_feature_count: int
    feature_names: List[str]
    trained_at: Optional[str] = None
    evaluation_metadata: Optional[EvaluationMetricsSchema] = None
    status_message: str


class HistoryItemSchema(BaseSchema):
    """Summary item for GET /api/v1/history."""

    analysis_id: str
    submitted_url: str
    normalized_url: str
    hostname: str
    url_sha256: str
    risk_category: RiskCategory
    analysis_method: AnalysisMethod
    is_fallback: bool
    model_version: Optional[str] = None
    calibrated_score: Optional[float] = None
    analyzed_at: datetime


class HistoryDetailResponse(HistoryItemSchema):
    """Detailed history record for GET /api/v1/history/{analysis_id}."""

    registrable_domain: str
    feature_schema_version: str
    features: Dict[str, float | int]
    indicators: List[IndicatorSchema]
    recommended_actions: List[str]
    limitations_notice: str


class HistoryListResponse(BaseSchema):
    """Paginated/filtered list of analysis history records."""

    history_enabled: bool
    total: int
    items: List[HistoryItemSchema]


class DeleteHistoryResponse(BaseSchema):
    """Response returned when deleting history records."""

    deleted_count: int
    message: str


class HealthResponse(BaseSchema):
    """Response schema for GET /api/v1/health."""

    status: str
    app_name: str
    app_version: str
    developer: str
    model_loaded: bool
    fallback_available: bool
    history_enabled: bool
    timestamp: datetime


class ErrorDetailSchema(BaseSchema):
    """Consistent error response structure that never leaks internal stack traces."""

    error_code: str
    message: str
    details: Optional[Dict[str, Any]] = None
