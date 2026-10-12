# Threat Model (STRIDE Analysis)

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. System Trust Boundaries

1. **Untrusted User Input Boundary**: The URL string and query parameters submitted to `POST /api/v1/analyze` and `GET /api/v1/history`.
2. **Application Service Boundary**: FastAPI backend, lexical feature extractor, and ML/fallback engines running in local process memory.
3. **Persistence Boundary**: Local SQLite database (`url_analysis.db`) and serialized model artefact (`url_model_v1.joblib`).

---

## 2. STRIDE Threat Analysis & Mitigations

| Threat Category | Threat Scenario | Risk Level | Implemented Mitigation |
| :--- | :--- | :--- | :--- |
| **Server-Side Request Forgery (SSRF)** | Attacker submits `http://169.254.169.254/latest/meta-data/` or `http://127.0.0.1:8000/admin` hoping the backend fetches the URL. | **Critical** (if unmitigated) | **Eliminated by Design**: The backend analyses only the lexical string in memory and never makes outbound HTTP or DNS requests (`TC-25`). |
| **Cross-Site Scripting (XSS)** | Attacker submits `javascript:alert(1)` or `https://example.com/?q=<script>alert(1)</script>` hoping it executes in the analyst's browser. | **High** | Scheme whitelist rejects `javascript:`/`data:` (`TC-05`); React escapes all text nodes; API sets `X-Content-Type-Options: nosniff` (`TC-26`). |
| **SQL Injection (Tampering / Info Disclosure)** | Attacker passes `' OR 1=1; DROP TABLE analysis_records; --` in URL or history search filter. | **High** | SQLAlchemy 2.0 ORM parameterized statements bind all parameters safely (`TC-27`). |
| **Denial of Service (DoS)** | Attacker floods `/api/v1/analyze` or submits multi-megabyte URLs to exhaust CPU/memory. | **Medium** | `MAX_REQUEST_BYTES` middleware (`16 KB`), `MAX_URL_LENGTH` (`2048` chars), and sliding-window IP rate limiter (`TC-06`, `TC-23`). |
| **Model Deserialization / Schema Tampering** | Incompatible or corrupted model artefact loaded into the inference service. | **Medium** | Model artefact path is server-controlled (never user-supplied), and `MLModelService._validate_bundle()` enforces strict `FEATURE_SCHEMA_VERSION` and feature-name verification (`TC-16`). |
| **Information Disclosure via Error Traces** | Malformed input triggers an unhandled exception exposing internal file paths or environment variables. | **Medium** | Global FastAPI exception handlers return sanitized JSON error codes without stack traces or file paths (`TC-24`, `TC-28`). |
| **Evasion / Adversarial URLs (ML Limitation)** | Attacker hosts a phishing page on a newly registered domain with clean lexical structure (`https://clean-domain.com/welcome`). | **Inherent to Lexical Scope** | Explicitly disclosed in the UI and API `limitations_notice`: lexical analysis is a risk indicator, not a guarantee of safety. |
