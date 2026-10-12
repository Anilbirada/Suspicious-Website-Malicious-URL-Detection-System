"""Machine learning model loader, schema verifier, and calibrated inference service.

Enforces strict feature schema compatibility between training and inference.
Never fabricates evaluation metrics or exposes internal filesystem paths.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

from app.features.url_extractor import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    LexicalIndicator,
    ParsedURLInfo,
    build_explainable_indicators,
)
from app.schemas.analysis import (
    AnalysisMethod,
    EvaluationMetricsSchema,
    IndicatorSchema,
    ModelStatusResponse,
    RiskCategory,
)
from app.services.fallback_analyzer import _build_recommendations

logger = logging.getLogger(__name__)


class ModelUnavailableError(RuntimeError):
    """Raised when no trained ML model artefact is available for inference."""


class IncompatibleModelError(RuntimeError):
    """Raised when a model artefact has an incompatible feature schema or structure."""


@dataclass(frozen=True)
class MLInferenceResult:
    """Structured prediction output from a verified trained ML model."""

    risk_category: RiskCategory
    analysis_method: AnalysisMethod
    is_fallback: bool
    model_version: str
    model_type: str
    feature_schema_version: str
    calibrated_score: Optional[float]
    heuristic_score_note: str
    indicators: List[IndicatorSchema]
    recommended_actions: List[str]
    limitations_notice: str


class MLModelService:
    """Manages loading, schema verification, and inference for the URL detection ML model."""

    def __init__(self, artefact_path: str | Path, allow_fallback: bool = True) -> None:
        self._artefact_path = Path(artefact_path)
        self._allow_fallback = allow_fallback
        self._bundle: Optional[Dict[str, Any]] = None
        self._load_error_reason: Optional[str] = None
        self.reload_model()

    @property
    def is_loaded(self) -> bool:
        return self._bundle is not None

    @property
    def allow_fallback(self) -> bool:
        return self._allow_fallback

    def reload_model(self, custom_path: Optional[str | Path] = None) -> bool:
        """Load and validate the model artefact from disk."""
        if custom_path is not None:
            self._artefact_path = Path(custom_path)

        self._bundle = None
        self._load_error_reason = None

        if not self._artefact_path.exists() or not self._artefact_path.is_file():
            self._load_error_reason = "Trained model artefact is not present. Rule-based fallback mode is active."
            logger.info("ML model artefact not found at configured path; fallback mode active.")
            return False

        try:
            raw_bundle = joblib.load(self._artefact_path)
        except Exception as exc:
            self._load_error_reason = "Failed to deserialize model artefact safely."
            logger.warning("Failed to load ML model artefact: %s", type(exc).__name__)
            return False

        try:
            self._validate_bundle(raw_bundle)
        except IncompatibleModelError as exc:
            self._load_error_reason = str(exc)
            logger.warning("Incompatible ML model artefact rejected: %s", exc)
            return False

        self._bundle = raw_bundle
        return True

    def _validate_bundle(self, bundle: Any) -> None:
        """Verify that the loaded joblib bundle contains required keys and matching schema."""
        if not isinstance(bundle, dict):
            raise IncompatibleModelError("Model artefact must be a structured metadata dictionary.")

        required_keys = {
            "pipeline",
            "model_version",
            "model_type",
            "feature_schema_version",
            "feature_names",
            "thresholds",
            "evaluation_metadata",
        }
        missing = required_keys - set(bundle.keys())
        if missing:
            raise IncompatibleModelError(
                f"Model artefact is missing required metadata keys: {', '.join(sorted(missing))}."
            )

        schema_ver = str(bundle.get("feature_schema_version", ""))
        if schema_ver != FEATURE_SCHEMA_VERSION:
            raise IncompatibleModelError(
                f"Incompatible feature schema version '{schema_ver}'. Expected '{FEATURE_SCHEMA_VERSION}'."
            )

        bundle_features = list(bundle.get("feature_names", []))
        if bundle_features != FEATURE_NAMES:
            raise IncompatibleModelError(
                "Model feature names or ordering do not match the application feature extractor schema."
            )

        pipeline = bundle.get("pipeline")
        if not hasattr(pipeline, "predict"):
            raise IncompatibleModelError("Loaded model object does not implement a valid 'predict' interface.")

    def get_status(self) -> ModelStatusResponse:
        """Return safe, accurate model status and evaluation metadata without exposing internal paths."""
        if self._bundle is not None:
            eval_meta_dict = self._bundle.get("evaluation_metadata")
            eval_schema = EvaluationMetricsSchema(**eval_meta_dict) if isinstance(eval_meta_dict, dict) else None
            return ModelStatusResponse(
                model_loaded=True,
                active_mode=AnalysisMethod.TRAINED_ML,
                fallback_mode_active=False,
                allow_fallback_mode=self._allow_fallback,
                model_version=str(self._bundle["model_version"]),
                model_type=str(self._bundle["model_type"]),
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                expected_feature_count=len(FEATURE_NAMES),
                feature_names=FEATURE_NAMES,
                trained_at=self._bundle.get("trained_at"),
                evaluation_metadata=eval_schema,
                status_message=(
                    f"Trained ML model ({self._bundle['model_version']}) is loaded and verified against "
                    f"feature schema v{FEATURE_SCHEMA_VERSION}."
                ),
            )

        reason = self._load_error_reason or "No trained ML model loaded."
        return ModelStatusResponse(
            model_loaded=False,
            active_mode=AnalysisMethod.RULE_BASED_FALLBACK,
            fallback_mode_active=True,
            allow_fallback_mode=self._allow_fallback,
            model_version=None,
            model_type=None,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            expected_feature_count=len(FEATURE_NAMES),
            feature_names=FEATURE_NAMES,
            trained_at=None,
            evaluation_metadata=None,
            status_message=reason,
        )

    def predict(
        self,
        parsed: ParsedURLInfo,
        features: Dict[str, float | int],
    ) -> MLInferenceResult:
        """Run calibrated ML inference on validated URL features."""
        if self._bundle is None:
            raise ModelUnavailableError(self._load_error_reason or "Trained ML model is not loaded.")

        missing_features = [f for f in FEATURE_NAMES if f not in features]
        if missing_features:
            raise IncompatibleModelError(
                f"Input feature dictionary is missing required features: {', '.join(missing_features)}"
            )

        ordered_row = {name: float(features[name]) for name in FEATURE_NAMES}
        feature_df = pd.DataFrame([ordered_row], columns=FEATURE_NAMES)

        pipeline = self._bundle["pipeline"]
        is_calibrated = bool(self._bundle.get("is_calibrated", False))
        thresholds = self._bundle.get("thresholds", {})
        suspicious_threshold = float(thresholds.get("suspicious_threshold", 0.40))
        malicious_threshold = float(thresholds.get("malicious_threshold", 0.75))

        calibrated_score: Optional[float] = None
        if hasattr(pipeline, "predict_proba") and is_calibrated:
            probs = pipeline.predict_proba(feature_df)
            raw_prob = float(probs[0][1])
            if np.isnan(raw_prob) or np.isinf(raw_prob):
                raise RuntimeError("Model produced a non-finite probability value.")
            calibrated_score = round(raw_prob, 4)

            if calibrated_score >= malicious_threshold:
                category = RiskCategory.POTENTIALLY_MALICIOUS
            elif calibrated_score >= suspicious_threshold:
                category = RiskCategory.SUSPICIOUS
            else:
                category = RiskCategory.LOWER_RISK
        else:
            pred_label = int(pipeline.predict(feature_df)[0])
            category = (
                RiskCategory.POTENTIALLY_MALICIOUS
                if pred_label == 1
                else RiskCategory.LOWER_RISK
            )

        base_indicators: List[LexicalIndicator] = build_explainable_indicators(parsed, features)
        indicators: List[IndicatorSchema] = [
            IndicatorSchema(
                code=ind.code,
                title=ind.title,
                severity=ind.severity,
                description=ind.description,
                observed_value=ind.observed_value,
                source="lexical",
            )
            for ind in base_indicators
        ]

        # Add transparent model contribution summary if feature weights/means are stored in the bundle
        top_contributors = self._compute_top_contributors(ordered_row)
        if top_contributors:
            indicators.append(
                IndicatorSchema(
                    code="ML_FEATURE_CONTRIBUTIONS",
                    title="Top Lexical Features Influencing Model Score",
                    severity="info" if category == RiskCategory.LOWER_RISK else "medium",
                    description=(
                        "Standardized lexical features with the largest positive contribution toward "
                        f"the model assessment ({self._bundle['model_version']}): "
                        + ", ".join(top_contributors)
                    ),
                    observed_value=(
                        f"Calibrated score: {calibrated_score:.4f}"
                        if calibrated_score is not None
                        else "Discrete class prediction"
                    ),
                    source="ml_contribution",
                )
            )

        recommended_actions = _build_recommendations(category, is_fallback=False)
        limitations_notice = (
            "IMPORTANT LIMITATIONS: This assessment is generated by a lexical machine-learning model "
            f"({self._bundle['model_version']}) trained on URL string characteristics only. "
            "It does NOT visit the website, inspect page content, verify domain ownership, or guarantee "
            "that a destination is safe or malicious. Newly registered phishing domains with benign-looking "
            "words can evade lexical detection, and complex legitimate URLs may occasionally be flagged."
        )

        score_note = (
            f"Calibrated ML probability score: {calibrated_score:.4f} "
            f"(thresholds: Suspicious >= {suspicious_threshold:.2f}, Potentially Malicious >= {malicious_threshold:.2f})."
            if calibrated_score is not None
            else "Uncalibrated discrete classifier prediction."
        )

        return MLInferenceResult(
            risk_category=category,
            analysis_method=AnalysisMethod.TRAINED_ML,
            is_fallback=False,
            model_version=str(self._bundle["model_version"]),
            model_type=str(self._bundle["model_type"]),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            calibrated_score=calibrated_score,
            heuristic_score_note=score_note,
            indicators=indicators,
            recommended_actions=recommended_actions,
            limitations_notice=limitations_notice,
        )

    def _compute_top_contributors(self, ordered_row: Dict[str, float]) -> List[str]:
        """Compute top positive standardized feature contributions when linear weights are available."""
        if not self._bundle:
            return []
        stats = self._bundle.get("feature_explanation_stats")
        if not isinstance(stats, dict):
            return []

        means = stats.get("means", {})
        scales = stats.get("scales", {})
        weights = stats.get("weights", {})
        if not (means and scales and weights):
            return []

        contributions = []
        for fname in FEATURE_NAMES:
            val = ordered_row.get(fname, 0.0)
            mean = float(means.get(fname, 0.0))
            scale = float(scales.get(fname, 1.0)) or 1.0
            weight = float(weights.get(fname, 0.0))
            z_val = (val - mean) / scale
            contrib = z_val * weight
            if contrib > 0.08 and val > 0:
                contributions.append((contrib, f"{fname}={val:g}"))

        contributions.sort(key=lambda item: item[0], reverse=True)
        return [label for _, label in contributions[:4]]
