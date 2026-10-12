# Test Plan and Verification Cases

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Execution Date**: 2026-10-12  

---

## 1. Test Execution Summary

- **Backend Automated Test Suite**: `python -m pytest backend/tests -v`
  - **Outcome**: `42 passed in 6.58s` (`TC-01` through `TC-29`, including parametrized edge cases).
- **Frontend Automated Test Suite**: `npm.cmd run test` (Vitest + React Testing Library)
  - **Outcome**: `4 passed` covering `TC-30` through `TC-34` and developer branding verification.

---

## 2. Detailed Test Case Execution Log (`TC-01` to `TC-34`)

| Test ID | Purpose | Preconditions | Steps | Expected Result | Actual Result | Status | Defect Ref |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Valid HTTP URL | Extractor initialized | Call `validate_and_parse_url("http://example.com/docs/index.html")` | Parses scheme `http`, host `example.com`, `is_ip=False` | Parsed accurately as expected | **Pass** | None |
| **TC-02** | Valid HTTPS URL | Extractor initialized | Call `validate_and_parse_url("https://www.python.org:443/downloads/?release=3.12")` | Normalizes default port 443 and extracts `registrable_domain="python.org"` | Normalized URL and domain matched | **Pass** | None |
| **TC-03** | Empty URL input | Extractor initialized | Pass `""`, `"   "`, `"\t\n"` to `validate_and_parse_url` | Raises `URLValidationError` with `code="EMPTY_URL"` | Raised `EMPTY_URL` on all 3 inputs | **Pass** | None |
| **TC-04** | Malformed URL | Extractor initialized | Pass 8 malformed URLs (`not-a-valid-url`, `http:///missing-host`, `https://..invalid.com`, etc.) | Raises `URLValidationError` with `code="MALFORMED_URL"` | Raised `MALFORMED_URL` on all 8 inputs without crashing | **Pass** | None |
| **TC-05** | Unsupported URL scheme | Extractor initialized | Pass `ftp://`, `javascript:`, `data:`, `file://`, `mailto:` URLs | Raises `URLValidationError` with `code="UNSUPPORTED_SCHEME"` | Raised `UNSUPPORTED_SCHEME` on all 5 inputs | **Pass** | None |
| **TC-06** | Extremely long URL | `max_length=2048` | Pass URL with 2,069 characters | Raises `URLValidationError` with `code="URL_TOO_LONG"` | Raised `URL_TOO_LONG` | **Pass** | None |
| **TC-07** | URL containing special characters | Extractor initialized | Test valid `%20`/`%21` URL and invalid unencoded space URL | Counts 3 percent encodings; rejects raw space with `MALFORMED_URL` | Matched expected behavior | **Pass** | None |
| **TC-08** | IPv4 address as hostname | Extractor initialized | Pass `http://192.0.2.45:8080/login/verify` | Sets `is_ip=True`, `is_ip_address=1`, `subdomain_count=0` | Matched expected feature values | **Pass** | None |
| **TC-09** | Internationalised or punycode hostname | `idna` installed | Pass `https://münchen.de/rathaus` and `https://xn--mnchen-3ya.de/rathaus` | Normalizes both to `xn--mnchen-3ya.de` and sets `has_punycode=1` | Normalized and flagged `has_punycode=1` | **Pass** | None |
| **TC-10** | URL containing userinfo or `@` sign | Extractor initialized | Pass `https://trusted-bank.com@198.51.100.77/login` | Identifies destination host `198.51.100.77`, sets `has_at_symbol=1` and `is_ip_address=1` | Extracted destination IP and `has_at_symbol=1` | **Pass** | None |
| **TC-11** | Expected output for known URL fixture | Extractor initialized | Extract features for `https://sub1.sub2.secure-example.com/account/login?id=123&mode=verify%20now` | All 18 features match deterministic expected counts | All 18 features matched exact assertions | **Pass** | None |
| **TC-12** | Missing or malformed feature values | `MLModelService` loaded | Call `service.predict` with incomplete feature dict `{"url_length": 20}` | Raises `IncompatibleModelError` safely | Raised `IncompatibleModelError` | **Pass** | None |
| **TC-13** | Training and inference feature schema consistency | `url_model_v1.joblib` generated | Compare bundle `feature_schema_version` and `feature_names` with `url_extractor` | Both equal `1.0.0` and identical 18-feature list | Exact match verified | **Pass** | None |
| **TC-14** | Loading a valid model | `url_model_v1.joblib` present | Initialize `MLModelService` and call `get_status()` | `model_loaded=True`, `model_version="1.0.0-logreg-calibrated"` | Loaded and verified | **Pass** | None |
| **TC-15** | Handling a missing model | Non-existent model path | Initialize `MLModelService` with missing file path | `model_loaded=False`, `fallback_mode_active=True` | Cleanly activated fallback mode | **Pass** | None |
| **TC-16** | Handling an incompatible model version | Corrupted schema bundle (`999.0.0`) | Load bundle with mismatched `feature_schema_version` | Rejects model (`model_loaded=False`), reports schema mismatch | Rejected incompatible bundle safely | **Pass** | None |
| **TC-17** | Valid prediction output categories | `MLModelService` loaded | Predict on benign reference URL and malicious fixture URL | Outputs valid `RiskCategory` enum values (`Lower Risk Indicators Found`, `Potentially Malicious`) | Returned valid categories | **Pass** | None |
| **TC-18** | No fabricated evaluation metrics | Missing model configuration | Call `GET /api/v1/model/status` and `POST /api/v1/analyze` in fallback mode | `evaluation_metadata` is `null`; `calibrated_score` is `null` | Verified zero fabricated metrics/scores | **Pass** | None |
| **TC-19** | Evaluation report matches actual model predictions | `evaluation_report.json` & test split | Recompute held-out test predictions using `url_model_v1.joblib` and compare Precision/Recall/F1 | JSON report matches actual model predictions (`0.9667`) | Exact match verified (`n=58`, `F1=0.9667`) | **Pass** | None |
| **TC-20** | Valid request produces structured result | FastAPI `TestClient` | `POST /api/v1/analyze` with `https://www.python.org/doc/` | Returns HTTP 200 with 18 features, indicators, actions, and limitations | Returned HTTP 200 with full schema | **Pass** | None |
| **TC-21** | Invalid request produces controlled error | FastAPI `TestClient` | `POST /api/v1/analyze` with `javascript:alert(1)` | Returns HTTP 422 with `error_code="UNSUPPORTED_SCHEME"` | Returned HTTP 422 with structured JSON | **Pass** | None |
| **TC-22** | Unsupported methods & content types handled | FastAPI `TestClient` | Send `GET /api/v1/analyze` and `POST` with `Content-Type: text/plain` | Returns HTTP 405 and HTTP 415/422 respectively | Returned expected status codes | **Pass** | None |
| **TC-23** | Rate limiting behaves as designed | `max_requests=3` | Send 4 consecutive `POST /api/v1/analyze` requests | First 3 return 200; 4th returns HTTP 429 `RATE_LIMIT_EXCEEDED` | Returned HTTP 429 on 4th request | **Pass** | None |
| **TC-24** | Error responses do not expose internal details | FastAPI `TestClient` | Trigger validation error with invalid IPv6 URL | Response body contains no `Traceback`, file paths, or env vars | Verified clean error response | **Pass** | None |
| **TC-25** | Submitted URLs are not fetched by service | Monkeypatch `socket.create_connection` & `urllib.request.urlopen` | `POST /api/v1/analyze` with external URL | Completes with HTTP 200 and zero network calls | Zero socket/HTTP calls attempted | **Pass** | None |
| **TC-26** | Submitted input cannot execute as HTML | FastAPI `TestClient` | Submit URL with `%3Cscript%3Ealert(1)%3C%2Fscript%3E` | Returns `application/json` with `X-Content-Type-Options: nosniff` | Headers and safe JSON verified | **Pass** | None |
| **TC-27** | User input cannot manipulate DB queries | FastAPI `TestClient` | Submit SQLi payload in `url` and `GET /api/v1/history?search=' OR 1=1; DROP TABLE...` | Parameterized ORM query treats input as literal text; records remain intact | Verified table integrity (`total == 2`) | **Pass** | Fixed per-app DB session binding during Stage E |
| **TC-28** | Status endpoints do not expose secrets | FastAPI `TestClient` | Inspect `/api/v1/health` and `/api/v1/model/status` | No database credentials or filesystem paths present in response | Verified clean output | **Pass** | None |
| **TC-29** | History access follows approved privacy rules | FastAPI `TestClient` | Test `save_to_history=False`, `DELETE /api/v1/history`, and `enable_history=False` | Opt-out skips DB write; DELETE purges records; disabled history returns HTTP 403 | All privacy rules verified | **Pass** | Fixed per-app DB session binding during Stage E |
| **TC-30** | Frontend main analysis flow works | Vitest + JSDOM | Enter URL in `DashboardPage` and click `Analyse URL` | Renders `AnalysisResultCard` with category badge, score, and indicators | Rendered assessment card accurately | **Pass** | None |
| **TC-31** | Frontend loading states appear correctly | Vitest + JSDOM | Submit URL while fetch promise is pending | Button displays `Analysing URL...` and is disabled until resolved | Loading state verified | **Pass** | None |
| **TC-32** | Frontend errors are understandable | Vitest + JSDOM | Submit empty URL and `ftp://` URL | Displays accessible `role="alert"` banner with clear message | Error banner verified | **Pass** | None |
| **TC-33** | Frontend results are displayed accessibly | Vitest + JSDOM | Inspect rendered result card and landmarks | Escaped URL text, semantic headings, and limitations notice are present | Landmarks and escaped text verified | **Pass** | None |
| **TC-34** | Navigation & responsive layout usability | Vitest + JSDOM | Navigate across Dashboard, Model Status, History, and About/Credits | All views render cleanly alongside `Developed by Anil Biradar` footer | Verified across all 4 tabs | **Pass** | None |
