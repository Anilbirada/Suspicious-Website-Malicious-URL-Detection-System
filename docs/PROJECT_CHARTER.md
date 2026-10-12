# Project Charter

**Project Name**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  
**Date**: 2026-10-12  

---

## 1. Executive Summary

The **Suspicious Website / Malicious URL Detection System** is a standalone cybersecurity web application and reproducible machine-learning system that helps users evaluate whether a submitted HTTP/HTTPS URL exhibits lexical and structural characteristics associated with phishing or malicious websites—without ever visiting or fetching the destination link.

## 2. Project Objectives

1. **Explainable Lexical Assessment**: Parse and validate submitted URLs safely in memory, extract 18 defensible lexical features, and explain which specific characteristics influenced the assessment.
2. **Honest Machine Learning & Fallback Isolation**: Provide a reproducible scikit-learn training and held-out evaluation pipeline alongside an isolated, clearly disclosed rule-based fallback mode.
3. **Zero-Fetch Security**: Guarantee that neither the frontend nor the backend connects to, resolves, or renders content from untrusted submitted URLs.
4. **User-Controlled Privacy**: Offer optional local analysis history with search, filtering, per-request opt-out, and deletion controls.
5. **Verifiable Quality**: Back all core requirements with automated backend (`pytest`) and frontend (`Vitest`) tests.

## 3. Target Users

- **Security Analysts & SOC Trainees**: Inspecting suspicious links reported by users without triggering remote payloads.
- **Software Engineers & Students**: Studying explainable lexical URL feature engineering, domain-grouped ML evaluation, and secure API design.
- **General Users**: Checking unfamiliar links before navigating to them in a web browser.

## 4. Scope

### In Scope (MVP)
- Lexical validation and normalization of `http://` and `https://` URLs (including IPv4, IPv6, and Punycode/IDN domains).
- Extraction of 18 documented lexical URL features (`FEATURE_SCHEMA_VERSION = "1.0.0"`).
- Reproducible dataset auditing, domain-grouped training (`GroupShuffleSplit`), probability calibration, and held-out evaluation reporting.
- FastAPI REST API (`/api/v1/health`, `/api/v1/model/status`, `/api/v1/analyze`, `/api/v1/history`).
- Responsive React + TypeScript cybersecurity dashboard with Dashboard, History, Model Status, and About/Credits views.
- Production attribution (`Developed by Anil Biradar`).

### Out of Scope (Exclusions)
- Live fetching, crawling, or headless-browser rendering of submitted URLs.
- External third-party threat intelligence API calls that transmit user-submitted URLs outside the local environment.
- Multi-tenant user authentication or role-based access control (unnecessary for local single-user operation).

## 5. Success Criteria

- Application starts and runs cleanly using documented commands.
- All 34 core test case specifications (`TC-01` through `TC-34`) are implemented and verified.
- Model evaluation metrics match actual held-out predictions with zero fabrication.
- Developer credit (`Anil Biradar`) is visibly and consistently rendered in the application footer, About page, and documentation.
