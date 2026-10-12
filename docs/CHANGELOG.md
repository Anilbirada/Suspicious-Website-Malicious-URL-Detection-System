# Changelog

All notable changes to the **Suspicious Website / Malicious URL Detection System** are documented in this file.

**Developer**: Anil Biradar

---

## [1.0.0] - 2026-10-12

### Added
- **Lexical URL Validator & 18-Feature Extractor (`backend/app/features/url_extractor.py`)**:
  - Strict zero-fetch validation for `http://` and `https://` URLs up to 2,048 characters.
  - Safe normalization of IPv4, IPv6, Punycode/IDN (`idna`), and `@` authority userinfo patterns.
  - 18 documented lexical features (`FEATURE_SCHEMA_VERSION = "1.0.0"`) and explainable indicator builder.
- **Reproducible Machine Learning Pipeline (`ml/`)**:
  - Curated lexical benchmark dataset (`ml/data/curated_url_benchmark.csv`) with documented provenance.
  - Automated data-quality auditor (`ml/reports/data_quality_report.json` & `.md`).
  - Domain-grouped train/test split (`GroupShuffleSplit` by `registrable_domain`, 0 overlapping domains).
  - Calibrated logistic regression pipeline (`1.0.0-logreg-calibrated`) and held-out evaluation report (`ml/reports/evaluation_report.json` & `.md`).
- **Backend FastAPI Service (`backend/app/`)**:
  - REST API v1 endpoints: `/api/v1/health`, `/api/v1/model/status`, `/api/v1/analyze`, `/api/v1/history`, `/api/v1/history/{analysis_id}`, and `DELETE /api/v1/history`.
  - Isolated rule-based fallback engine (`backend/app/services/fallback_analyzer.py`).
  - SQLAlchemy 2.0 ORM persistence (`AnalysisRecord`, `ModelMetadataRecord`), per-IP sliding-window rate limiting, request size limits, and security response headers.
- **Frontend Cybersecurity Dashboard (`frontend/`)**:
  - React 18 + TypeScript + Vite responsive interface with `DashboardPage`, `HistoryPage`, `ModelStatusPage`, and `AboutPage`.
  - Production developer credit (`Developed by Anil Biradar` in persistent footer and `Developer: Anil Biradar` on About & Credits page).
- **Automated Testing & Documentation**:
  - 42 passing backend test executions (`TC-01` through `TC-29` in `backend/tests/test_all.py`).
  - 4 passing frontend test suites (`TC-30` through `TC-34` in `frontend/src/tests/App.test.tsx`).
  - Complete set of 15 engineering, API, database, security, threat model, and user guide documents in `docs/` and `README.md`.
