# Database Design Document

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Persistence Strategy

- **Local Development / Prototype**: SQLite (`sqlite:///./url_analysis.db`) managed via SQLAlchemy 2.0 ORM (`backend/app/models/`).
- **Shared / Production Deployment**: Compatible with PostgreSQL by setting `DATABASE_URL="postgresql+psycopg://..."` in `.env`.
- **Proportional Design**: Only entities that provide genuine functional value (`analysis_records` and `model_metadata`) are created. `USER_ACCOUNT` and `AUDIT_EVENT` tables are intentionally omitted from the single-user MVP to avoid unnecessary complexity, as documented in `docs/DECISION_LOG.md`.

## 2. Entity-Relationship Schema

### 2.1 `analysis_records` (`AnalysisRecord`)

Stores completed URL risk assessments when `ENABLE_HISTORY=true` and `save_to_history=true`.

| Column | Type | Nullable | Indexed | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` (UUID) | No (PK) | Primary Key | Unique identifier for the analysis record |
| `submitted_url` | `Text` | No | No | Original submitted URL (or redacted path if `STORE_RAW_URL_IN_HISTORY=false`) |
| `normalized_url` | `Text` | No | No | Normalized canonical URL string |
| `hostname` | `String(255)` | No | Yes | Normalized ASCII destination hostname |
| `registrable_domain` | `String(255)` | No | Yes | Estimated registrable domain (e.g., `python.org`) |
| `url_sha256` | `String(64)` | No | Yes | SHA-256 hex digest of the normalized URL |
| `risk_category` | `String(64)` | No | Yes | Assessment category (`Potentially Malicious`, `Suspicious`, `Lower Risk Indicators Found`, `Unable to Determine`) |
| `analysis_method` | `String(64)` | No | Yes | `trained_ml_model` or `rule_based_fallback` |
| `is_fallback` | `Boolean` | No | No | Whether fallback mode was used |
| `model_version` | `String(64)` | Yes | No | Model version string (null in fallback mode) |
| `feature_schema_version` | `String(32)` | No | No | Lexical feature schema version (`1.0.0`) |
| `calibrated_score` | `Float` | Yes | No | Calibrated ML score in `[0.0, 1.0]` (null in fallback mode) |
| `features_json` | `JSON` | No | No | Dictionary of all 18 extracted lexical features |
| `indicators_json` | `JSON` | No | No | Array of explainable indicator objects |
| `recommended_actions_json` | `JSON` | No | No | Array of recommended cautionary actions |
| `limitations_notice` | `Text` | No | No | Limitations and uncertainty disclosure text |
| `status` | `String(32)` | No | No | Execution status (`completed`) |
| `analyzed_at` | `DateTime(timezone=True)` | No | Yes | UTC timestamp of analysis |

Composite Index: `ix_analysis_records_category_analyzed_at` on `(risk_category, analyzed_at)`.

### 2.2 `model_metadata` (`ModelMetadataRecord`)

Stores registered model metadata and held-out evaluation provenance.

| Column | Type | Nullable | Indexed | Description |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` (UUID) | No (PK) | Primary Key | Unique identifier |
| `model_version` | `String(64)` | No | Unique Index | Semantic model version (`1.0.0-logreg-calibrated`) |
| `model_type` | `String(128)` | No | No | Classifier architecture description |
| `feature_schema_version` | `String(32)` | No | No | Compatible feature schema version (`1.0.0`) |
| `dataset_reference` | `String(255)` | No | No | Training dataset identifier |
| `evaluation_metadata_json` | `JSON` | No | No | Held-out evaluation metrics and confusion matrix |
| `created_at` | `DateTime(timezone=True)` | No | No | UTC registration timestamp |

## 3. Data Retention, Privacy & Query Safety

- **Parameterized Queries**: All database reads, searches (`ilike`), and deletions use SQLAlchemy 2.0 parameterized statements (`select()`, `delete()`), preventing SQL injection (`TC-27`).
- **Retention & Deletion**: Users can delete individual records (`DELETE /api/v1/history?analysis_id=...`) or purge the entire table (`DELETE /api/v1/history`).
