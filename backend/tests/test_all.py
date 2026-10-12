"""Comprehensive automated test suite covering TC-01 through TC-29.

Verifies URL validation, lexical feature extraction, ML loading/evaluation,
isolated fallback mode, REST API endpoints, and application security controls.

Developed by Anil Biradar.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import joblib
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

from app.core.config import PROJECT_ROOT, Settings
from app.core.security import rate_limiter
from app.features.url_extractor import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    URLValidationError,
    extract_lexical_features,
    validate_and_parse_url,
)
from app.main import create_app
from app.ml.inference import IncompatibleModelError, MLModelService
from app.models.database import Base, engine
from app.schemas.analysis import AnalysisMethod, RiskCategory


@pytest.fixture(autouse=True)
def reset_state():
    """Reset rate limiter and ensure database tables exist before each test."""
    rate_limiter.reset()
    Base.metadata.create_all(bind=engine)
    yield
    rate_limiter.reset()


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    """Create a FastAPI TestClient backed by an isolated SQLite database in tmp_path."""
    db_file = tmp_path / "test_analysis.db"
    test_settings = Settings(
        database_url=f"sqlite:///{db_file.as_posix()}",
        enable_history=True,
        store_raw_url_in_history=True,
        allow_fallback_mode=True,
    )
    app = create_app(custom_settings=test_settings)
    return TestClient(app)


# ============================================================================
# URL VALIDATION TESTS (TC-01 to TC-10)
# ============================================================================


def test_tc01_valid_http_url():
    """TC-01: Valid HTTP URL is accepted and parsed accurately."""
    parsed = validate_and_parse_url("http://example.com/docs/index.html")
    assert parsed.scheme == "http"
    assert parsed.ascii_hostname == "example.com"
    assert parsed.registrable_domain == "example.com"
    assert parsed.path == "/docs/index.html"
    assert parsed.is_ip is False


def test_tc02_valid_https_url():
    """TC-02: Valid HTTPS URL is accepted and normalized accurately."""
    parsed = validate_and_parse_url("https://www.python.org:443/downloads/?release=3.12")
    assert parsed.scheme == "https"
    assert parsed.ascii_hostname == "www.python.org"
    assert parsed.registrable_domain == "python.org"
    assert parsed.normalized_url == "https://www.python.org/downloads/?release=3.12"


@pytest.mark.parametrize("empty_val", ["", "   ", "\t\n"])
def test_tc03_empty_url_input(empty_val: str):
    """TC-03: Empty or whitespace-only URL input raises EMPTY_URL."""
    with pytest.raises(URLValidationError) as exc_info:
        validate_and_parse_url(empty_val)
    assert exc_info.value.code == "EMPTY_URL"


@pytest.mark.parametrize(
    "malformed_val",
    [
        "not-a-valid-url",
        "http:///missing-host",
        "https://..invalid.com/path",
        "https://invalid..domain.com",
        "https://-leadinghyphen.com",
        "https://hostname-only/path",
        "https://999.999.999.999/login",
        "https://example.com:99999/path",
    ],
)
def test_tc04_malformed_url(malformed_val: str):
    """TC-04: Malformed URL raises MALFORMED_URL safely without crashing."""
    with pytest.raises(URLValidationError) as exc_info:
        validate_and_parse_url(malformed_val)
    assert exc_info.value.code == "MALFORMED_URL"


@pytest.mark.parametrize(
    "bad_scheme_url",
    [
        "ftp://files.example.com/archive.zip",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "mailto:user@example.com",
    ],
)
def test_tc05_unsupported_url_scheme(bad_scheme_url: str):
    """TC-05: Unsupported URL scheme raises UNSUPPORTED_SCHEME."""
    with pytest.raises(URLValidationError) as exc_info:
        validate_and_parse_url(bad_scheme_url)
    assert exc_info.value.code == "UNSUPPORTED_SCHEME"


def test_tc06_extremely_long_url():
    """TC-06: Oversized URL exceeding max_length raises URL_TOO_LONG."""
    oversized = "https://example.com/" + ("a" * 2050)
    with pytest.raises(URLValidationError) as exc_info:
        validate_and_parse_url(oversized, max_length=2048)
    assert exc_info.value.code == "URL_TOO_LONG"


def test_tc07_url_containing_special_characters():
    """TC-07: Valid percent-encoded special chars are parsed; raw control chars are rejected."""
    parsed = validate_and_parse_url("https://example.com/search?q=hello%20world%21&filter=a%26b")
    feats = extract_lexical_features(parsed)
    assert feats["percent_encoding_count"] == 3
    assert feats["query_param_count"] == 2

    with pytest.raises(URLValidationError) as exc_info:
        validate_and_parse_url("https://example.com/path with spaces/index.html")
    assert exc_info.value.code == "MALFORMED_URL"


def test_tc08_ipv4_address_as_hostname():
    """TC-08: IPv4 address as hostname is detected with is_ip_address == 1."""
    parsed = validate_and_parse_url("http://192.0.2.45:8080/login/verify")
    feats = extract_lexical_features(parsed)
    assert parsed.is_ip is True
    assert feats["is_ip_address"] == 1
    assert feats["subdomain_count"] == 0


def test_tc09_internationalised_or_punycode_hostname():
    """TC-09: Unicode IDN and ASCII Punycode hostnames are normalized and flagged."""
    parsed_unicode = validate_and_parse_url("https://münchen.de/rathaus")
    feats_unicode = extract_lexical_features(parsed_unicode)
    assert parsed_unicode.ascii_hostname == "xn--mnchen-3ya.de"
    assert parsed_unicode.is_punycode is True
    assert feats_unicode["has_punycode"] == 1

    parsed_puny = validate_and_parse_url("https://xn--mnchen-3ya.de/rathaus")
    feats_puny = extract_lexical_features(parsed_puny)
    assert parsed_puny.ascii_hostname == "xn--mnchen-3ya.de"
    assert feats_puny["has_punycode"] == 1


def test_tc10_url_containing_userinfo_or_at_sign():
    """TC-10: URL containing '@' in authority identifies actual destination host and sets has_at_symbol."""
    parsed = validate_and_parse_url("https://trusted-bank.com@198.51.100.77/login")
    feats = extract_lexical_features(parsed)
    assert parsed.has_userinfo is True
    assert parsed.ascii_hostname == "198.51.100.77"
    assert feats["has_at_symbol"] == 1
    assert feats["is_ip_address"] == 1


# ============================================================================
# FEATURE EXTRACTION TESTS (TC-11 to TC-13)
# ============================================================================


def test_tc11_expected_output_for_known_url_fixture():
    """TC-11: Feature extraction returns deterministic values for a known URL fixture."""
    url = "https://sub1.sub2.secure-example.com/account/login?id=123&mode=verify%20now"
    parsed = validate_and_parse_url(url)
    feats = extract_lexical_features(parsed)

    assert set(feats.keys()) == set(FEATURE_NAMES)
    assert feats["url_length"] == len(url)
    assert feats["hostname_length"] == len("sub1.sub2.secure-example.com")
    assert feats["path_length"] == len("/account/login")
    assert feats["query_length"] == len("id=123&mode=verify%20now")
    assert feats["dot_count"] == 3
    assert feats["hostname_hyphen_count"] == 1
    assert feats["query_param_count"] == 2
    assert feats["subdomain_count"] == 2
    assert feats["is_ip_address"] == 0
    assert feats["has_at_symbol"] == 0
    assert feats["is_https"] == 1
    assert feats["has_punycode"] == 0
    assert feats["percent_encoding_count"] == 1
    assert feats["suspicious_keyword_count"] >= 2  # account, login, verify


def test_tc12_missing_or_malformed_feature_values_handled(tmp_path: Path):
    """TC-12: MLModelService rejects feature dictionaries with missing keys safely."""
    artefact_path = PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib"
    service = MLModelService(artefact_path=artefact_path)
    parsed = validate_and_parse_url("https://example.com/")
    incomplete_features = {"url_length": 20}  # Missing 17 required features

    with pytest.raises(IncompatibleModelError):
        service.predict(parsed, incomplete_features)


def test_tc13_training_and_inference_feature_schema_consistency():
    """TC-13: Saved model artefact schema version and feature ordering match url_extractor."""
    artefact_path = PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib"
    bundle = joblib.load(artefact_path)
    assert bundle["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert bundle["feature_names"] == FEATURE_NAMES


# ============================================================================
# MACHINE LEARNING TESTS (TC-14 to TC-19)
# ============================================================================


def test_tc14_loading_valid_model():
    """TC-14: MLModelService loads the trained model artefact and reports model_loaded=True."""
    artefact_path = PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib"
    service = MLModelService(artefact_path=artefact_path)
    status_resp = service.get_status()
    assert service.is_loaded is True
    assert status_resp.model_loaded is True
    assert status_resp.active_mode == AnalysisMethod.TRAINED_ML
    assert status_resp.model_version == "1.0.0-logreg-calibrated"


def test_tc15_handling_missing_model(tmp_path: Path):
    """TC-15: Missing model file cleanly activates rule-based fallback mode."""
    missing_path = tmp_path / "non_existent_model.joblib"
    service = MLModelService(artefact_path=missing_path, allow_fallback=True)
    status_resp = service.get_status()
    assert service.is_loaded is False
    assert status_resp.model_loaded is False
    assert status_resp.fallback_mode_active is True
    assert status_resp.active_mode == AnalysisMethod.RULE_BASED_FALLBACK


def test_tc16_handling_incompatible_model_version(tmp_path: Path):
    """TC-16: Model bundle with mismatched feature_schema_version is rejected safely."""
    bad_bundle_path = tmp_path / "incompatible_model.joblib"
    joblib.dump(
        {
            "pipeline": object(),
            "model_version": "0.0.1-broken",
            "model_type": "Dummy",
            "feature_schema_version": "999.0.0",
            "feature_names": ["wrong_feature"],
            "thresholds": {},
            "evaluation_metadata": {},
        },
        bad_bundle_path,
    )
    service = MLModelService(artefact_path=bad_bundle_path, allow_fallback=True)
    status_resp = service.get_status()
    assert service.is_loaded is False
    assert status_resp.fallback_mode_active is True
    assert "Incompatible feature schema version" in status_resp.status_message


def test_tc17_valid_prediction_output_categories():
    """TC-17: ML and fallback predictions always map to approved RiskCategory values."""
    artefact_path = PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib"
    service = MLModelService(artefact_path=artefact_path)

    benign_parsed = validate_and_parse_url("https://www.wikipedia.org/wiki/URL")
    benign_res = service.predict(benign_parsed, extract_lexical_features(benign_parsed))
    assert benign_res.risk_category in set(RiskCategory)
    assert benign_res.risk_category == RiskCategory.LOWER_RISK

    mal_parsed = validate_and_parse_url(
        "http://trusted.com@192.0.2.88/login/verify-account-password?token=%61%62%63"
    )
    mal_res = service.predict(mal_parsed, extract_lexical_features(mal_parsed))
    assert mal_res.risk_category == RiskCategory.POTENTIALLY_MALICIOUS


def test_tc18_no_fabricated_evaluation_metrics(tmp_path: Path):
    """TC-18: When no model is loaded, status returns evaluation_metadata=None and fallback returns calibrated_score=None."""
    missing_path = tmp_path / "missing.joblib"
    test_settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'fb.db').as_posix()}",
        model_artefact_path=str(missing_path),
        allow_fallback_mode=True,
    )
    app = create_app(custom_settings=test_settings)
    fb_client = TestClient(app)

    status_data = fb_client.get("/api/v1/model/status").json()
    assert status_data["model_loaded"] is False
    assert status_data["evaluation_metadata"] is None

    analyze_data = fb_client.post(
        "/api/v1/analyze",
        json={"url": "http://192.0.2.15/login/verify"},
    ).json()
    assert analyze_data["analysis_method"] == "rule_based_fallback"
    assert analyze_data["is_fallback"] is True
    assert analyze_data["calibrated_score"] is None


def test_tc19_evaluation_report_matches_actual_model_predictions():
    """TC-19: Saved evaluation_report.json metrics exactly match actual model predictions on held-out split."""
    eval_json_path = PROJECT_ROOT / "ml" / "reports" / "evaluation_report.json"
    dataset_path = PROJECT_ROOT / "ml" / "data" / "curated_url_benchmark.csv"
    artefact_path = PROJECT_ROOT / "backend" / "app" / "ml" / "artefacts" / "url_model_v1.joblib"

    eval_report = json.loads(eval_json_path.read_text(encoding="utf-8"))
    bundle = joblib.load(artefact_path)
    pipeline = bundle["pipeline"]

    raw_df = pd.read_csv(dataset_path, keep_default_na=False)
    seen = set()
    rows = []
    for _, r in raw_df.iterrows():
        u = str(r["url"]).strip()
        lbl_str = str(r["label"]).strip()
        if not u or lbl_str not in {"0", "1"} or u in seen:
            continue
        try:
            p = validate_and_parse_url(u)
            f = extract_lexical_features(p)
        except URLValidationError:
            continue
        seen.add(u)
        item = {"registrable_domain": p.registrable_domain, "label": int(lbl_str)}
        item.update(f)
        rows.append(item)

    df = pd.DataFrame(rows)
    X = df[FEATURE_NAMES].astype(float)
    y = df["label"].astype(int).values
    groups = df["registrable_domain"].values

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    _, test_idx = next(splitter.split(X, y, groups=groups))
    X_test, y_test = X.iloc[test_idx], y[test_idx]

    y_prob = pipeline.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.50).astype(int)

    actual_precision = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
    actual_recall = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
    actual_f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)

    assert eval_report["evaluation_sample_size"] == len(X_test)
    assert eval_report["precision"] == actual_precision
    assert eval_report["recall"] == actual_recall
    assert eval_report["f1_score"] == actual_f1


# ============================================================================
# BACKEND API TESTS (TC-20 to TC-24)
# ============================================================================


def test_tc20_valid_request_produces_structured_result(client: TestClient):
    """TC-20: POST /api/v1/analyze with valid URL returns structured 200 assessment."""
    resp = client.post("/api/v1/analyze", json={"url": "https://www.python.org/doc/"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["submitted_url"] == "https://www.python.org/doc/"
    assert data["hostname"] == "www.python.org"
    assert data["registrable_domain"] == "python.org"
    assert data["risk_category"] in [c.value for c in RiskCategory]
    assert data["analysis_method"] == "trained_ml_model"
    assert isinstance(data["features"], dict)
    assert len(data["features"]) == len(FEATURE_NAMES)
    assert isinstance(data["indicators"], list) and len(data["indicators"]) >= 1
    assert isinstance(data["recommended_actions"], list) and len(data["recommended_actions"]) >= 1
    assert "limitations_notice" in data


def test_tc21_invalid_request_produces_controlled_error(client: TestClient):
    """TC-21: POST /api/v1/analyze with invalid URL returns 422 with structured error_code."""
    resp = client.post("/api/v1/analyze", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422
    data = resp.json()
    assert data["error_code"] == "UNSUPPORTED_SCHEME"
    assert "Unsupported URL scheme" in data["message"]


def test_tc22_unsupported_methods_and_content_types_handled(client: TestClient):
    """TC-22: GET on /api/v1/analyze returns 405; text/plain on POST returns 415/422."""
    get_resp = client.get("/api/v1/analyze")
    assert get_resp.status_code == 405

    text_resp = client.post(
        "/api/v1/analyze",
        content="https://example.com",
        headers={"Content-Type": "text/plain"},
    )
    assert text_resp.status_code in (415, 422)


def test_tc23_rate_limiting_behaves_as_designed(tmp_path: Path):
    """TC-23: Exceeding configured rate limit returns HTTP 429 RATE_LIMIT_EXCEEDED."""
    rate_limiter.max_requests = 3
    rate_limiter.reset()
    try:
        db_file = tmp_path / "ratelimit.db"
        app = create_app(Settings(database_url=f"sqlite:///{db_file.as_posix()}"))
        rl_client = TestClient(app)

        for _ in range(3):
            ok_resp = rl_client.post("/api/v1/analyze", json={"url": "https://example.com"})
            assert ok_resp.status_code == 200

        blocked_resp = rl_client.post("/api/v1/analyze", json={"url": "https://example.com"})
        assert blocked_resp.status_code == 429
        assert blocked_resp.json()["error_code"] == "RATE_LIMIT_EXCEEDED"
    finally:
        rate_limiter.max_requests = 60
        rate_limiter.reset()


def test_tc24_error_responses_do_not_expose_internal_details(client: TestClient):
    """TC-24: Error responses do not contain stack traces, Traceback strings, or file paths."""
    resp = client.post("/api/v1/analyze", json={"url": "http://[::1:bad-ipv6]/test"})
    assert resp.status_code == 422
    body_text = resp.text
    assert "Traceback" not in body_text
    assert "File \"" not in body_text
    assert "OneDrive" not in body_text


# ============================================================================
# SECURITY & PRIVACY TESTS (TC-25 to TC-29)
# ============================================================================


def test_tc25_submitted_urls_are_never_fetched_by_analysis_service(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """TC-25: Analysis service never opens network sockets or HTTP requests to submitted URLs."""
    def forbid_network(*_args, **_kwargs):
        raise AssertionError("SECURITY VIOLATION: Outbound network call attempted during URL analysis!")

    monkeypatch.setattr(socket, "create_connection", forbid_network)
    monkeypatch.setattr(urllib.request, "urlopen", forbid_network)

    resp = client.post(
        "/api/v1/analyze",
        json={"url": "https://198.51.100.99/login/verify-credentials?session=12345"},
    )
    assert resp.status_code == 200


def test_tc26_submitted_input_cannot_execute_as_html(client: TestClient):
    """TC-26: XSS payload in URL is safely handled with JSON Content-Type and nosniff header."""
    xss_url = "https://example.com/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    resp = client.post("/api/v1/analyze", json={"url": xss_url})
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"


def test_tc27_user_input_cannot_manipulate_database_queries(client: TestClient):
    """TC-27: SQL injection strings in URL and history search parameters do not corrupt queries."""
    client.post("/api/v1/analyze", json={"url": "https://example.com/normal-page"})
    sqli_url = "https://example.com/path?id=1'%20OR%20'1'='1'--+"
    resp = client.post("/api/v1/analyze", json={"url": sqli_url})
    assert resp.status_code == 200

    # Attempt SQL injection in GET /api/v1/history?search=...
    search_resp = client.get("/api/v1/history", params={"search": "' OR 1=1; DROP TABLE analysis_records; --"})
    assert search_resp.status_code == 200
    assert search_resp.json()["total"] == 0

    # Verify the table and original records remain intact
    all_hist = client.get("/api/v1/history").json()
    assert all_hist["total"] == 2


def test_tc28_status_endpoints_do_not_expose_secrets(client: TestClient):
    """TC-28: /api/v1/health and /api/v1/model/status do not expose database URLs or filesystem paths."""
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    health_text = health_resp.text
    assert "sqlite" not in health_text.lower()
    assert "OneDrive" not in health_text

    status_resp = client.get("/api/v1/model/status")
    assert status_resp.status_code == 200
    status_text = status_resp.text
    assert "OneDrive" not in status_text
    assert "C:\\" not in status_text and "c:/" not in status_text.lower()


def test_tc29_history_access_follows_approved_privacy_rules(tmp_path: Path):
    """TC-29: History respects enable_history=False, save_to_history=False, and deletion controls."""
    # Case A: History enabled - test opt-out per request and deletion
    db_a = tmp_path / "hist_a.db"
    client_a = TestClient(
        create_app(Settings(database_url=f"sqlite:///{db_a.as_posix()}", enable_history=True))
    )

    # Submit with save_to_history=False
    res_no_save = client_a.post(
        "/api/v1/analyze",
        json={"url": "https://example.com/private-link", "save_to_history": False},
    ).json()
    assert res_no_save["stored_in_history"] is False
    assert client_a.get("/api/v1/history").json()["total"] == 0

    # Submit with save_to_history=True
    res_saved = client_a.post(
        "/api/v1/analyze",
        json={"url": "https://example.com/stored-link", "save_to_history": True},
    ).json()
    assert res_saved["stored_in_history"] is True
    hist_list = client_a.get("/api/v1/history").json()
    assert hist_list["total"] == 1

    # Fetch detail record
    detail_resp = client_a.get(f"/api/v1/history/{res_saved['analysis_id']}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["submitted_url"] == "https://example.com/stored-link"

    # Delete history
    del_resp = client_a.delete("/api/v1/history")
    assert del_resp.status_code == 200
    assert del_resp.json()["deleted_count"] == 1
    assert client_a.get("/api/v1/history").json()["total"] == 0

    # Case B: History disabled globally -> GET /api/v1/history returns 403
    db_b = tmp_path / "hist_b.db"
    client_b = TestClient(
        create_app(Settings(database_url=f"sqlite:///{db_b.as_posix()}", enable_history=False))
    )
    assert client_b.get("/api/v1/history").status_code == 403
