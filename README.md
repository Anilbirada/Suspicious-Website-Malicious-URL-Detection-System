# Suspicious Website / Malicious URL Detection System

An explainable, security-first web application and machine-learning pipeline that evaluates submitted URLs for lexical and structural characteristics associated with phishing, deceptive, or potentially malicious websites.

---

## Project Credit

**Developer**  
Anil Biradar

**Project**  
Suspicious Website / Malicious URL Detection System

---

## 1. Overview & Problem Statement

Malicious and phishing links frequently use deceptive lexical structures—such as raw IP addresses, `@` userinfo authority obfuscation, deep subdomain chains, hyphenated brand-impersonation hostnames, Punycode/IDN homographs, and credential-lure paths—to trick users into surrendering credentials or downloading malware.

Visiting an untrusted URL directly in a browser or fetching it from an unhardened backend exposes users and servers to drive-by downloads, Server-Side Request Forgery (SSRF), and tracking beacons.

The **Suspicious Website / Malicious URL Detection System** addresses this by:
1. **Inspecting URL strings strictly lexically in memory** without ever visiting, resolving, or fetching the destination website.
2. **Extracting 18 documented, deterministic lexical features** shared identically between training and inference (`FEATURE_SCHEMA_VERSION = "1.0.0"`).
3. **Scoring URLs using a calibrated machine-learning pipeline** (`CalibratedClassifierCV` with `StandardScaler` + `LogisticRegression`) evaluated on a domain-grouped held-out split (`GroupShuffleSplit` by `registrable_domain`), or transparently switching to an **isolated rule-based fallback engine** when no model is loaded.
4. **Explaining every assessment** with human-readable indicators, observed values, recommended cautionary actions, and explicit uncertainty/limitations disclosures.

> **Important Limitation Notice**: A prediction is a lexical risk assessment, not proof that a website is guaranteed safe or malicious. HTTPS transport encryption alone never proves that a website owner is legitimate.

---

## 2. Key Features

- **Strict Zero-Fetch Security**: Never opens sockets, resolves DNS, or fetches remote content from submitted URLs.
- **18-Feature Lexical Extractor**: Parses and normalizes URLs (`urllib.parse`, `ipaddress`, `idna`) and computes 18 documented features including Shannon character entropy, Punycode/IDN detection, authority `@` detection, subdomain depth, and credential keyword counts.
- **Calibrated ML Inference + Isolated Fallback Mode**:
  - **Trained ML Mode**: Uses `1.0.0-logreg-calibrated` with held-out evaluation metadata and top standardized feature contribution explanations.
  - **Rule-Based Fallback Mode**: Explicitly labelled deterministic heuristic mode that never fabricates probabilities or claims ML inference.
- **Four Clear Assessment Categories**:
  1. `Potentially Malicious`
  2. `Suspicious`
  3. `Lower Risk Indicators Found`
  4. `Unable to Determine`
- **Privacy-Aware Local History**: Optional SQLite persistence with search, category filtering, detail inspection, per-request opt-out (`save_to_history: false`), and one-click single or bulk deletion.
- **Cybersecurity Dashboard UI**: Responsive React + TypeScript interface with deep navy/charcoal theme, accessible form controls, live model status inspection, and persistent attribution (`Developed by Anil Biradar`).

---

## 3. Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Frontend** | React 18, TypeScript 5, Vite 5, Responsive CSS |
| **Backend** | Python 3.12, FastAPI, Pydantic v2, Uvicorn |
| **Machine Learning** | scikit-learn, pandas, NumPy, joblib, idna |
| **Database** | SQLite (via SQLAlchemy 2.0 ORM; PostgreSQL-compatible) |
| **Testing** | pytest, FastAPI TestClient, Vitest, React Testing Library |

---

## 4. Architecture & Repository Structure

```text
AI SUSPECIOUS/
├── backend/
│   ├── app/
│   │   ├── api/routes.py             # REST API v1 endpoints
│   │   ├── core/config.py            # Environment-driven Pydantic Settings
│   │   ├── core/security.py          # Sliding-window rate limiter & log sanitizer
│   │   ├── features/url_extractor.py # Pure lexical validator & 18-feature extractor
│   │   ├── ml/inference.py           # Model loader, schema verifier & ML inference
│   │   ├── ml/artefacts/             # Trained joblib model bundle (url_model_v1.joblib)
│   │   ├── models/                   # SQLAlchemy database setup & ORM entities
│   │   ├── schemas/analysis.py       # Strict Pydantic v2 request/response schemas
│   │   ├── services/                 # Fallback heuristic engine & orchestrator service
│   │   └── main.py                   # FastAPI application factory & middleware
│   ├── tests/test_all.py             # 42 automated backend tests (TC-01 to TC-29)
│   ├── requirements.txt
│   └── pyproject.toml
├── ml/
│   ├── data/curated_url_benchmark.csv
│   ├── scripts/train_and_evaluate.py # Data quality check, training & held-out evaluation
│   ├── reports/                      # Generated JSON & Markdown quality/evaluation reports
│   └── README.md
├── frontend/
│   ├── src/
│   │   ├── components/               # Navbar, Footer, RiskBadge, AnalysisResultCard
│   │   ├── pages/                    # DashboardPage, HistoryPage, ModelStatusPage, AboutPage
│   │   ├── services/apiClient.py     # Typed REST API client
│   │   ├── types/api.ts              # TypeScript interfaces
│   │   ├── styles/app.css            # Deep navy cybersecurity dashboard stylesheet
│   │   └── tests/App.test.tsx        # Automated frontend tests (TC-30 to TC-34)
│   ├── package.json
│   └── vite.config.ts
├── docs/                             # 15 engineering, API, test, and security documents
├── .env.example
├── .gitignore
└── README.md
```

---

## 5. Prerequisites & Installation

### Prerequisites
- **Python**: `3.11+` (tested on `3.12.10`)
- **Node.js**: `18+` (tested on `v26.7.0` / `npm 11.19.0`)

### 1. Environment Setup
Copy `.env.example` to `.env` if custom settings are needed (safe defaults work out of the box):
```bash
cp .env.example .env
```

### 2. Install Backend Dependencies
```bash
python -m pip install -r backend/requirements.txt
```

### 3. Prepare and Load the Machine Learning Model
Run the reproducible ML pipeline script to audit the dataset, train the calibrated model, generate quality and evaluation reports in `ml/reports/`, and save the verified model artefact to `backend/app/ml/artefacts/url_model_v1.joblib`:
```bash
python ml/scripts/train_and_evaluate.py
```

### 4. Start the Backend API Server
```bash
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```
- API Base URL: `http://127.0.0.1:8000/api/v1`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 5. Install and Start the Frontend Application
```bash
cd frontend
npm install
npm run dev
```
> *Note for Windows PowerShell users with restricted script execution policies*: Use `npm.cmd install` and `npm.cmd run dev`.

- Frontend URL: `http://localhost:5173`

---

## 6. Running Automated Tests

### Backend Test Suite (`TC-01` through `TC-29` — 42 test executions)
```bash
python -m pytest backend/tests -v
```

### Frontend Test Suite (`TC-30` through `TC-34`)
```bash
cd frontend
npm run test
```

---

## 7. Dataset Requirements & Provenance

- **File**: `ml/data/curated_url_benchmark.csv`
- **Schema**: `url,label,source_id,collected_at,licence_ref` (`label`: `0` = benign reference URL, `1` = synthetic/defanged phishing or malicious lexical pattern).
- **Provenance**: Combines standard public reference domains (RFC/documentation/educational/open-source domains under CC0-1.0) and defanged synthetic phishing lexical patterns using RFC 2606 / RFC 5737 reserved test ranges under MIT.
- **Data Quality & Leakage Prevention**: Audited automatically by `ml/scripts/train_and_evaluate.py` (`287` raw rows -> `283` valid cleaned rows across `132` unique registrable domains after removing 1 missing URL, 1 invalid label, 1 exact duplicate, and 1 unsupported-scheme URL). Split via `GroupShuffleSplit` (75% train = 225 rows, 25% held-out test = 58 rows) grouped by `registrable_domain` with **zero overlapping domains** between train and test splits.
- **Held-Out Evaluation Metrics (`1.0.0-logreg-calibrated`, $n = 58$)**:
  - Precision: `0.9667`
  - Recall: `0.9667`
  - F1-Score: `0.9667`
  - ROC-AUC: `0.9976`
  - PR-AUC: `0.9978`
  - Confusion Matrix: `TN = 27, FP = 1, FN = 1, TP = 29`

---

## 8. REST API Summary

| Method | Endpoint | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Application availability and high-level capability status |
| `GET` | `/api/v1/model/status` | Loaded model metadata, feature schema v1.0.0, and held-out evaluation report |
| `POST` | `/api/v1/analyze` | Validate URL, extract 18 lexical features, and return explainable risk assessment |
| `GET` | `/api/v1/history` | List/filter permitted analysis history (`search`, `risk_category`, `limit`, `offset`) |
| `GET` | `/api/v1/history/{analysis_id}` | Retrieve full detail for a specific analysis record |
| `DELETE` | `/api/v1/history` | Delete a specific history record (`?analysis_id=...`) or clear all history |

See [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md) for complete request and response examples.

---

## 9. Security, Privacy & Limitations

1. **No Outbound Fetching**: The backend never visits or resolves submitted URLs (`TC-25`), eliminating SSRF and remote payload execution risks.
2. **Safe Output Encoding**: Submitted URLs are rendered strictly as escaped text nodes (`TC-26`) with `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.
3. **Lexical Scope Limitation**: Lexical URL analysis inspects only the URL string itself. It cannot detect malicious content hosted on a compromised legitimate domain with a clean URL path, nor can it verify live TLS certificates or WHOIS domain age.
4. **Privacy Controls**: Users can uncheck *"Save result in local analysis history"* on any submission, delete individual or all history entries at any time, or disable history globally via `ENABLE_HISTORY=false`.

---

## 10. Documentation Index

All 15 required engineering documents are maintained in the repository:
1. [`README.md`](README.md)
2. [`docs/PROJECT_CHARTER.md`](docs/PROJECT_CHARTER.md)
3. [`docs/BRS.md`](docs/BRS.md)
4. [`docs/SRS.md`](docs/SRS.md)
5. [`docs/SYSTEM_DESIGN.md`](docs/SYSTEM_DESIGN.md)
6. [`docs/DATABASE_DESIGN.md`](docs/DATABASE_DESIGN.md)
7. [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md)
8. [`docs/TEST_PLAN_AND_CASES.md`](docs/TEST_PLAN_AND_CASES.md)
9. [`docs/SECURITY_AND_PRIVACY.md`](docs/SECURITY_AND_PRIVACY.md)
10. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
11. [`docs/SETUP_AND_DEPLOYMENT.md`](docs/SETUP_AND_DEPLOYMENT.md)
12. [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md)
13. [`docs/DECISION_LOG.md`](docs/DECISION_LOG.md)
14. [`docs/RISKS_AND_MITIGATIONS.md`](docs/RISKS_AND_MITIGATIONS.md)
15. [`docs/CHANGELOG.md`](docs/CHANGELOG.md)
