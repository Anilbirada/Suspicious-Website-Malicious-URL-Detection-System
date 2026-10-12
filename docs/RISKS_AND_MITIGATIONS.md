# Risks, Limitations, and Mitigations

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Technical & Machine Learning Risks

| Risk ID | Risk Description | Impact | Likelihood | Mitigation Implemented |
| :--- | :--- | :--- | :--- | :--- |
| **RM-01** | **False Negatives on Clean-Looking Phishing Domains**: Attackers register a benign-looking domain (`https://quarterly-report-portal.com/view`) with no lexical anomalies. | High | Medium | Prominently display `limitations_notice` on every result reminding users that lexical analysis cannot guarantee a website is safe and domain ownership must be verified independently. |
| **RM-02** | **False Positives on Complex Enterprise/OAuth URLs**: Legitimate SSO/OAuth links often contain `login`, `verify`, `account`, and long percent-encoded redirect parameters. | Medium | Medium | Include complex benign SSO/OAuth URLs in the benchmark dataset and explain each triggered indicator transparently so analysts can inspect the registrable domain (`registrable_domain`). |
| **RM-03** | **Benchmark Dataset Scope vs. Live Threat Feeds**: Local curated benchmark (`283` valid URLs across `132` domains) is smaller than commercial threat feeds. | Medium | High | Explicitly document dataset provenance, sample size, and limitations in `/api/v1/model/status`, `ml/reports/EVALUATION_REPORT.md`, and the UI Model Status page. |
| **RM-04** | **URL Shorteners Concealing Destination**: Shortened links (`bit.ly/...`) hide the final destination URL from lexical inspection. | Medium | Medium | Detect known shortening services in `build_explainable_indicators()` and emit a `URL_SHORTENER_SERVICE` medium-severity warning. |
| **RM-05** | **Feature Schema Drift Between Training & Inference**: Updating feature extraction without retraining breaks model predictions. | High | Low | Enforce `FEATURE_SCHEMA_VERSION == "1.0.0"` and exact `FEATURE_NAMES` list comparison in `MLModelService._validate_bundle()` (`TC-13`, `TC-16`). |
| **RM-06** | **Sensitive Tokens Submitted in URL Query Strings**: Users paste URLs containing private session tokens into history. | Medium | Medium | Provide a per-request *"Save result in local analysis history"* toggle, `STORE_RAW_URL_IN_HISTORY=false` redaction mode, and one-click history deletion (`TC-29`). |
