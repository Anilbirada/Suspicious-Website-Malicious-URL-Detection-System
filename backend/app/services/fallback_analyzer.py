"""Isolated rule-based demonstration fallback analyzer.

IMPORTANT:
This module is strictly separated from the machine-learning inference service.
It uses deterministic lexical rules when no trained ML model is loaded or when
fallback mode is explicitly requested. It NEVER outputs calibrated probability
scores or claims machine-learning prediction capability.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from app.features.url_extractor import (
    FEATURE_SCHEMA_VERSION,
    LexicalIndicator,
    ParsedURLInfo,
    build_explainable_indicators,
)
from app.schemas.analysis import AnalysisMethod, IndicatorSchema, RiskCategory


@dataclass(frozen=True)
class FallbackAssessment:
    """Structured result produced exclusively by the rule-based fallback engine."""

    risk_category: RiskCategory
    analysis_method: AnalysisMethod
    is_fallback: bool
    feature_schema_version: str
    heuristic_score_note: str
    indicators: List[IndicatorSchema]
    recommended_actions: List[str]
    limitations_notice: str


def run_rule_based_fallback(
    parsed: ParsedURLInfo,
    features: Dict[str, float | int],
) -> FallbackAssessment:
    """Evaluate extracted URL features using transparent, deterministic lexical rules."""
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

    rule_points = 0
    triggered_rules: List[str] = []

    if features["has_at_symbol"] == 1:
        rule_points += 45
        triggered_rules.append("Authority '@' userinfo obfuscation rule (+45 rule pts)")

    if features["is_ip_address"] == 1:
        rule_points += 35
        triggered_rules.append("Literal IP address hostname rule (+35 rule pts)")

    if int(features["suspicious_keyword_count"]) >= 2:
        rule_points += 30
        triggered_rules.append("Multiple sensitive credential/account keywords (+30 rule pts)")
    elif int(features["suspicious_keyword_count"]) == 1:
        rule_points += 15
        triggered_rules.append("Single sensitive credential/account keyword (+15 rule pts)")

    if int(features["hostname_hyphen_count"]) >= 2:
        rule_points += 20
        triggered_rules.append("Multiple hyphens in hostname (+20 rule pts)")

    if int(features["subdomain_count"]) >= 3:
        rule_points += 20
        triggered_rules.append("Deep subdomain hierarchy (>=3 subdomains) (+20 rule pts)")

    if features["has_punycode"] == 1:
        rule_points += 20
        triggered_rules.append("Internationalized / Punycode domain label (+20 rule pts)")

    if int(features["url_length"]) >= 120:
        rule_points += 10
        triggered_rules.append("Extended URL length (>=120 chars) (+10 rule pts)")

    if int(features["percent_encoding_count"]) >= 4:
        rule_points += 10
        triggered_rules.append("Elevated percent-encoding count (+10 rule pts)")

    if features["is_https"] == 0 and int(features["suspicious_keyword_count"]) >= 1:
        rule_points += 20
        triggered_rules.append("Unencrypted HTTP combined with credential keyword (+20 rule pts)")

    if rule_points >= 60:
        category = RiskCategory.POTENTIALLY_MALICIOUS
    elif rule_points >= 25:
        category = RiskCategory.SUSPICIOUS
    else:
        category = RiskCategory.LOWER_RISK

    if triggered_rules:
        indicators.append(
            IndicatorSchema(
                code="FALLBACK_HEURISTIC_SUMMARY",
                title="Rule-Based Fallback Heuristic Triggered",
                severity="medium" if rule_points < 60 else "high",
                description="Deterministic fallback rules triggered: " + "; ".join(triggered_rules),
                observed_value=f"{rule_points} heuristic rule points (not a probability)",
                source="fallback_rule",
            )
        )

    recommended_actions = _build_recommendations(category, is_fallback=True)
    limitations_notice = (
        "FALLBACK DEMONSTRATION MODE ACTIVE: This assessment was produced by deterministic lexical rules, "
        "NOT a trained machine-learning model. Heuristic rule points are not calibrated probabilities. "
        "Lexical URL inspection does not inspect live page content, WHOIS registration age, or TLS certificates, "
        "and cannot guarantee that a website is safe or malicious."
    )

    return FallbackAssessment(
        risk_category=category,
        analysis_method=AnalysisMethod.RULE_BASED_FALLBACK,
        is_fallback=True,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        heuristic_score_note=(
            f"Rule-based heuristic index: {rule_points} points (uncalibrated deterministic rules; "
            "not a machine-learning probability)."
        ),
        indicators=indicators,
        recommended_actions=recommended_actions,
        limitations_notice=limitations_notice,
    )


def _build_recommendations(category: RiskCategory, is_fallback: bool) -> List[str]:
    mode_note = (
        "Note: Because rule-based fallback mode was used, verify critical links with additional threat-intelligence tools."
        if is_fallback
        else "Always verify the registrable domain independently before entering sensitive credentials."
    )
    if category == RiskCategory.POTENTIALLY_MALICIOUS:
        return [
            "Do NOT enter passwords, multi-factor authentication codes, financial details, or personal data on this URL.",
            "Do not open or download files from this link.",
            "If this link arrived via email or SMS claiming to be from a known institution, navigate to the official website manually via a trusted bookmark.",
            mode_note,
        ]
    if category == RiskCategory.SUSPICIOUS:
        return [
            "Treat this URL with caution and verify the registrable domain spelling carefully before proceeding.",
            "Avoid submitting login credentials unless you can independently confirm domain ownership.",
            "Check whether the link uses subdomains, hyphens, or look-alike characters to imitate a familiar brand.",
            mode_note,
        ]
    if category == RiskCategory.LOWER_RISK:
        return [
            "Fewer high-risk lexical indicators were found in the URL string itself, but lexical structure alone never guarantees a website is safe.",
            "Confirm that the domain name belongs to the organization you expect before logging in or downloading files.",
            mode_note,
        ]
    return [
        "The system could not determine a reliable risk category for this input.",
        "Exercise standard caution and verify the destination domain independently.",
    ]
