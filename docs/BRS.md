# Business Requirements Specification (BRS)

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Business Context & Problem Statement

Organizations and individuals routinely encounter suspicious links in emails, chat messages, and documents. Opening an unknown link directly in a browser risks credential theft or malware infection, while black-box URL scanners often fail to explain *why* a URL was flagged or whether a real machine-learning model was used.

## 2. Business Goals

| Goal ID | Business Goal | Measurable Outcome |
| :--- | :--- | :--- |
| **BG-01** | Safe Pre-Navigation URL Triage | Users can assess any `http`/`https` URL string with zero outbound network contact to the target host. |
| **BG-02** | Transparent & Honest Risk Communication | Every assessment uses one of four clear categories and explicitly discloses whether ML inference or rule-based fallback mode was used. |
| **BG-03** | Reproducible ML Governance | Training data quality issues and held-out evaluation metrics are audited and reported automatically without fabricated metrics. |
| **BG-04** | Privacy Preservation | Users control whether URLs are saved in local history and can delete history records at any time. |
| **BG-05** | Clear Production Attribution | The application consistently credits `Anil Biradar` in the footer, About section, and README. |

## 3. Business Rules

- **BR-01 (No Guarantee Claim)**: The system must never claim a URL is 100% safe or 100% malicious; predictions are lexical risk assessments.
- **BR-02 (HTTPS Neutrality)**: The presence of `https://` must never be treated as proof of legitimacy.
- **BR-03 (Model vs. Fallback Disclosure)**: Rule-based heuristic scores must never be presented as calibrated machine-learning probabilities.
- **BR-04 (Zero Outbound Fetch)**: Submitted URLs must never be visited, crawled, or resolved over the network during analysis.
- **BR-05 (Opt-In/Opt-Out History Retention)**: Users must be able to disable history storage per request or clear stored history completely.
