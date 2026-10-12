# Software Requirements Specification (SRS)

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Functional Requirements

### 1.1 URL Validation & Normalization (`FR-01` to `FR-05`)
- **FR-01**: The system shall accept a URL string up to `MAX_URL_LENGTH` (default 2,048 characters).
- **FR-02**: The system shall reject empty strings, whitespace-only strings, control characters, and URLs lacking a valid hostname.
- **FR-03**: The system shall permit only `http` and `https` schemes and explicitly reject `javascript`, `data`, `file`, `ftp`, `mailto`, and other schemes (`UNSUPPORTED_SCHEME`).
- **FR-04**: The system shall normalize valid IPv4, IPv6, and Internationalized Domain Name (IDN / Punycode `xn--`) hostnames safely in memory.
- **FR-05**: The system shall identify `@` userinfo components in the authority section and extract the actual destination hostname following the last `@`.

### 1.2 Lexical Feature Extraction (`FR-06` to `FR-08`)
- **FR-06**: The system shall extract 18 deterministic lexical features defined by `FEATURE_SCHEMA_VERSION = "1.0.0"`.
- **FR-07**: Feature extraction shall be decoupled from HTTP routing and shared identically by training (`ml/scripts/train_and_evaluate.py`) and inference (`backend/app/ml/inference.py`).
- **FR-08**: The system shall generate human-readable `IndicatorSchema` items describing notable lexical features and their limitations.

### 1.3 Machine Learning & Fallback Analysis (`FR-09` to `FR-13`)
- **FR-09**: When a valid, schema-compatible `.joblib` model bundle is loaded, the system shall compute a calibrated risk score in `[0.0, 1.0]` and classify the URL into:
  - `Potentially Malicious` ($\ge 0.70$)
  - `Suspicious` ($\ge 0.35$ and $< 0.70$)
  - `Lower Risk Indicators Found` ($< 0.35$)
  - `Unable to Determine` (when analysis cannot be completed)
- **FR-10**: If the model artefact is missing, incompatible, or bypassed via `force_fallback: true`, the system shall execute the isolated rule-based fallback analyzer (`backend/app/services/fallback_analyzer.py`) and set `analysis_method = "rule_based_fallback"` and `calibrated_score = null`.
- **FR-11**: The `/api/v1/model/status` endpoint shall report live model availability, version, feature schema version, and held-out evaluation metadata without exposing filesystem paths.

### 1.4 Analysis History (`FR-14` to `FR-16`)
- **FR-14**: When `ENABLE_HISTORY=true` and `save_to_history=true`, completed analyses shall be persisted in `analysis_records`.
- **FR-15**: Users shall be able to list, search by URL/hostname substring, filter by `RiskCategory`, and inspect individual history records.
- **FR-16**: Users shall be able to delete a single history record or clear all history records via `DELETE /api/v1/history`.

## 2. Non-Functional Requirements

- **NFR-01 (Security — Zero Remote Execution)**: 0 outbound HTTP/DNS/socket calls to submitted URLs (`TC-25`).
- **NFR-02 (Security — Output Encoding & Headers)**: All API responses use `application/json` with `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` (`TC-26`).
- **NFR-03 (Availability & Rate Limiting)**: Sliding-window rate limiting per client IP (default 60 requests / 60 seconds) returning HTTP 429 (`TC-23`).
- **NFR-04 (Usability & Responsiveness)**: Dark-themed cybersecurity UI usable across desktop, tablet, and mobile viewports (`TC-34`).
- **NFR-05 (Branding)**: Display `Developed by Anil Biradar` in the application footer across all pages and `Developer: Anil Biradar` on the About & Credits page.
