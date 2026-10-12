"""Reproducible ML Pipeline: Dataset Ingestion, Quality Audit, Training & Held-Out Evaluation.

Steps performed:
1. Generates or ingests the documented lexical benchmark dataset (`ml/data/curated_url_benchmark.csv`),
   including intentional edge cases for the data-quality auditor (duplicates, malformed rows, missing values).
2. Runs comprehensive data-quality checks and outputs `ml/reports/data_quality_report.json`
   and `ml/reports/DATA_QUALITY_REPORT.md`.
3. Extracts the exact 18 lexical features via `backend/app/features/url_extractor.py`.
4. Splits cleaned records using `GroupShuffleSplit` grouped by `registrable_domain` to prevent
   train/test leakage across related URLs from the same domain.
5. Trains and compares baseline classifiers (Calibrated Logistic Regression vs. Calibrated Random Forest),
   saves the verified model bundle to `backend/app/ml/artefacts/url_model_v1.joblib`, and writes
   actual held-out evaluation metrics to `ml/reports/evaluation_report.json` and `ml/reports/EVALUATION_REPORT.md`.

Developed by Anil Biradar.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.features.url_extractor import (  # noqa: E402
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    URLValidationError,
    extract_lexical_features,
    validate_and_parse_url,
)

DATA_DIR = PROJECT_ROOT / "ml" / "data"
REPORTS_DIR = PROJECT_ROOT / "ml" / "reports"
ARTEFACT_DIR = BACKEND_DIR / "app" / "ml" / "artefacts"

DATASET_PATH = DATA_DIR / "curated_url_benchmark.csv"
QUALITY_REPORT_JSON = REPORTS_DIR / "data_quality_report.json"
QUALITY_REPORT_MD = REPORTS_DIR / "DATA_QUALITY_REPORT.md"
EVAL_REPORT_JSON = REPORTS_DIR / "evaluation_report.json"
EVAL_REPORT_MD = REPORTS_DIR / "EVALUATION_REPORT.md"
MODEL_ARTEFACT_PATH = ARTEFACT_DIR / "url_model_v1.joblib"


def build_curated_benchmark_csv(csv_path: Path) -> None:
    """Create a documented, deterministic lexical URL benchmark dataset with provenance columns."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    benign_domains = [
        ("example.com", ["/", "/about", "/docs/getting-started", "/pricing", "/contact-us"]),
        ("wikipedia.org", ["/wiki/Computer_security", "/wiki/URL", "/wiki/Phishing", "/wiki/Transport_Layer_Security"]),
        ("python.org", ["/", "/downloads/", "/doc/3.12/library/urllib.parse.html", "/psf/landing/"]),
        ("fastapi.tiangolo.com", ["/", "/tutorial/", "/advanced/security/", "/deployment/"]),
        ("scikit-learn.org", ["/stable/", "/stable/modules/calibration.html", "/stable/user_guide.html"]),
        ("github.com", ["/tiangolo/fastapi", "/scikit-learn/scikit-learn", "/pytest-dev/pytest", "/explore"]),
        ("mozilla.org", ["/en-US/firefox/", "/en-US/security/", "/en-US/privacy/"]),
        ("w3.org", ["/TR/html52/", "/Protocols/rfc2616/rfc2616.html", "/WAI/standards-guidelines/"]),
        ("ietf.org", ["/rfc/rfc3986.txt", "/rfc/rfc5890.txt", "/standards/rfcs/"]),
        ("nist.gov", ["/cyberframework", "/publications", "/itl/csd"]),
        ("owasp.org", ["/www-project-top-ten/", "/www-community/attacks/Phishing", "/chapters/"]),
        ("debian.org", ["/", "/security/", "/distrib/packages", "/doc/"]),
        ("kernel.org", ["/", "/category/releases.html", "/doc/html/latest/"]),
        ("apache.org", ["/", "/licenses/LICENSE-2.0", "/foundation/"]),
        ("postgresql.org", ["/", "/docs/current/", "/download/"]),
        ("sqlite.org", ["/index.html", "/docs.html", "/features.html"]),
        ("react.dev", ["/", "/learn", "/reference/react"]),
        ("typescriptlang.org", ["/", "/docs/handbook/intro.html", "/play"]),
        ("vitejs.dev", ["/", "/guide/", "/config/"]),
        ("npmjs.com", ["/package/react", "/package/typescript", "/about"]),
        ("pypi.org", ["/project/fastapi/", "/project/pydantic/", "/help/"]),
        ("arxiv.org", ["/list/cs.CR/recent", "/abs/2101.00001", "/help"]),
        ("acm.org", ["/", "/publications/digital-library", "/education"]),
        ("ieee.org", ["/", "/conferences", "/publications"]),
        ("mit.edu", ["/", "/research/", "/academics/"]),
        ("stanford.edu", ["/", "/admission/", "/research/"]),
        ("berkeley.edu", ["/", "/academics/", "/campus-life/"]),
        ("ox.ac.uk", ["/", "/admissions/undergraduate", "/research"]),
        ("cam.ac.uk", ["/", "/research", "/colleges-and-departments"]),
        ("iisc.ac.in", ["/", "/admissions/", "/research/"]),
        ("gov.uk", ["/", "/browse/Working", "/government/publications"]),
        ("usa.gov", ["/", "/agency-index", "/benefits"]),
        ("who.int", ["/", "/health-topics", "/news-room"]),
        ("un.org", ["/en/", "/en/about-us", "/en/global-issues"]),
        ("cloudflare.com", ["/learning/security/what-is-phishing/", "/dns/", "/trust-hub/"]),
        ("letsencrypt.org", ["/", "/docs/", "/how-it-works/"]),
        ("readthedocs.io", ["/", "/projects/", "/pricing/"]),
        ("jupyter.org", ["/", "/install", "/community"]),
        ("pandas.pydata.org", ["/", "/docs/user_guide/index.html", "/community/"]),
        ("numpy.org", ["/", "/doc/stable/", "/learn/"]),
        ("matplotlib.org", ["/", "/stable/gallery/index.html", "/stable/tutorials/index.html"]),
        ("sqlalchemy.org", ["/", "/library.html", "/support.html"]),
        ("pydantic.dev", ["/", "/docs/validation/", "/articles/"]),
        ("Docker.com", ["/", "/products/docker-desktop/", "/resources/"]),
        ("linuxfoundation.org", ["/", "/projects", "/research"]),
        ("cncf.io", ["/", "/projects/", "/blog/"]),
        ("rust-lang.org", ["/", "/learn", "/tools"]),
        ("golang.org", ["/", "/doc/", "/pkg/"]),
        ("eclipse.org", ["/", "/downloads/", "/projects/"]),
        ("gnu.org", ["/", "/licenses/gpl-3.0.html", "/software/"]),
        ("creativecommons.org", ["/", "/licenses/", "/about/"]),
        ("archive.org", ["/", "/about/", "/projects/"]),
    ]

    # Benign URLs that also include query parameters, hyphens, or longer paths (including hard boundary cases)
    benign_complex = [
        ("docs.python.org", "/3/search.html?q=urlsplit&check_keywords=yes&area=default"),
        ("github.com", "/search?q=url+lexical+analysis&type=repositories&s=stars&o=desc"),
        ("en.wikipedia.org", "/w/index.php?title=Uniform_Resource_Identifier&action=history"),
        ("developer.mozilla.org", "/en-US/docs/Web/Security/Types_of_attacks?utm_source=mdn&utm_medium=doc"),
        ("portal.stanford.edu", "/student-services/account-overview/academic-calendar-2026"),
        ("id.atlassian.com", "/login?continue=https%3A%2F%2Fstart.atlassian.com%2F"),
        ("accounts.google.com", "/ServiceLogin?hl=en&passive=true"),
        ("login.microsoftonline.com", "/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000"),
        ("auth.sso.enterprise-cloud-portal.org", "/account/login/verify-session?redirect=%2Fdashboard%2Fbilling&mode=secure"),
        ("id.campus-student-account.edu", "/signin/password-update/confirm?token=%31%32%33%34&acct=99812"),
        ("sso.login.regional-health-portal.org", "/verify/account/signin?continue=%2Fpatient%2Fbilling-update"),
    ]

    # Synthetic / Defanged Malicious & Phishing Lexical Patterns (RFC 2606 / documentation / reserved ranges)
    malicious_patterns = [
        # Subtle short phishing/malicious URLs with minimal lexical indicators (hard false-negative cases)
        ("https://docs-viewer.org/file.html", 1),
        ("https://cdn-assets-static.net/app.js", 1),
        ("https://mail-archive-node.org/read", 1),
        ("https://cloud-share-drive.net/open", 1),
        # IP address hostnames with credential/malware paths
        ("http://192.0.2.14/login/verify-account.php?session=981723981723", 1),
        ("http://198.51.100.42:8080/secure/banking/update-credentials.html", 1),
        ("http://203.0.113.88/wp-admin/includes/wallet-recover-login.php?uid=4412", 1),
        ("https://192.0.2.99/signin/confirm-password-reset?token=a8f9d01b2c3e4f", 1),
        ("http://198.51.100.115:8443/account/unlock-suspended-billing/index.php", 1),
        ("http://203.0.113.19/verify/security-update/login.jsp?redirect=%2Fhome", 1),
        ("http://192.0.2.210/bin/confirm-account-credential.sh", 1),
        ("http://198.51.100.7/portal/signin-verification-alert.php?id=88312", 1),
        ("http://203.0.113.250:9000/secure-login/password-update/auth", 1),
        ("http://192.0.2.55/banking/login-confirm-session.htm?user=admin%40test", 1),
        # '@' userinfo obfuscation patterns
        ("https://trusted-bank.example.com@malicious-auth-host.xyz/login/verify", 1),
        ("http://accounts.google.com@198.51.100.24/signin/v2/identifier", 1),
        ("https://microsoft-secure.com@update-credential-check.top/account/login", 1),
        ("http://paypal.com.secure-verify@auth-node-77.click/confirm-billing", 1),
        ("https://corporate-portal.org@login-verify-session.work/password/reset", 1),
        ("http://support.apple.com@id-unlock-service.xyz/signin/recover", 1),
        ("https://chase.com@secure-banking-verification.loan/login.php", 1),
        ("http://amazon.com@account-update-billing-alert.buzz/verify/signin", 1),
        # Deep subdomain + hyphenated brand-spoofing lexical patterns
        ("https://login.verify.secure-account.auth-update-portal.xyz/signin/confirm?acct=10928", 1),
        ("http://signin.banking.account-unlock.customer-verify-alert.top/update/password.php", 1),
        ("https://secure.account.update.billing-confirm-service.click/login/verification", 1),
        ("http://verify.password.recover-wallet.crypto-auth-portal.work/unlock/account", 1),
        ("https://account-verify.secure-login.banking-update.portal-check.xyz/confirm/signin", 1),
        ("http://mail.office.login-secure-update.credential-check.top/auth/verify.php?id=9912", 1),
        ("https://idp.sso.verify-account-login.security-alert-node.click/password/update", 1),
        ("http://support.billing.suspend-account-unlock.verify-now.xyz/login/confirm", 1),
        ("https://wallet.recover.secure-signin-verification.token-auth.work/account/unlock", 1),
        ("http://netbanking.confirm.user-credential-update.alert-desk.loan/signin/verify", 1),
        ("https://cloud.admin.password-reset-verify.secure-auth-node99.buzz/login/update", 1),
        ("http://portal.payroll.account-verification-required.hr-login-check.xyz/signin", 1),
        # Punycode / IDN homograph combined with credential lure paths
        ("https://xn--pple-43d.com/login/verify-account-id/unlock", 1),
        ("https://xn--pypal-4ve.secure-verify-service.xyz/signin/confirm-billing", 1),
        ("http://xn--mcrosoft-90a.account-update-portal.top/login/password-reset", 1),
        ("https://xn--chse-4na.banking-verify-login.click/account/unlock-session", 1),
        ("http://xn--amzon-rqa.billing-confirm-update.work/signin/verify-credential", 1),
        ("https://xn--gogle-1ua.secure-login-check.xyz/account/recover-password", 1),
        # Multi-hyphen + heavy percent-encoding + long credential traps
        (
            "http://secure-login-verify-account-update-2026.xyz/auth/signin.php"
            "?redirect=%68%74%74%70%3A%2F%2Fevil%2Eexample%2Fconfirm&user=%61%64%6D%69%6E&mode=verify",
            1,
        ),
        (
            "https://banking-account-unlock-verification-center.top/portal/login/confirm-password"
            "?token=%39%38%61%62%63%64&session=update_credential_now_9918273645",
            1,
        ),
        (
            "http://wallet-recovery-seed-verify-secure-login.click/connect/unlock-wallet"
            "?callback=%2F%2F198.51.100.88%2Fsteal&verify=%74%72%75%65&account=suspend",
            1,
        ),
        (
            "https://update-billing-suspended-account-alert.work/customer/signin/verify"
            "?return=%2Faccount%2Fpassword%2Fconfirm%3Fid%3D44918273&step=credential",
            1,
        ),
        (
            "http://confirm-identity-secure-banking-portal-99.loan/login/verify-update.php"
            "?acct=%30%30%31%39%32&auth=%70%61%73%73%77%6F%72%64&unlock=1",
            1,
        ),
        (
            "https://signin-verification-account-recovery-service.buzz/oauth/login/confirm"
            "?client=%61%63%63%6F%75%6E%74&redirect_uri=%68%74%74%70%3A%2F%2F192.0.2.11%2F",
            1,
        ),
        # Additional diverse malicious lexical structures across distinct domains
        ("http://secure-update-appleid-locks.xyz/verify/login/confirm-billing.php", 1),
        ("http://netflix-billing-account-suspend.top/signin/update-payment-method", 1),
        ("https://dhl-parcel-delivery-fee-confirm.click/track/login-verify-address", 1),
        ("http://usps-redelivery-schedule-update.work/portal/confirm-account-billing", 1),
        ("https://irs-tax-refund-verify-identity.loan/gov/signin-credential-confirm", 1),
        ("http://steam-community-trade-offer-verify.buzz/login/openid-unlock-account", 1),
        ("https://binance-wallet-kyc-verification-alert.xyz/account/login-confirm-seed", 1),
        ("http://metamask-vault-decrypt-recover-wallet.top/unlock/verify-password-phrase", 1),
        ("https://coinbase-security-device-confirm-login.click/signin/verify-account-2fa", 1),
        ("http://outlook-web-app-quota-exceeded-update.work/owa/login-confirm-password", 1),
        ("https://onedrive-shared-document-auth-verify.xyz/view/signin-account-credential", 1),
        ("http://docusign-secure-envelope-review-login.top/sign/verify-email-password", 1),
        ("https://dropbox-file-transfer-secure-signin.click/download/login-verify-account", 1),
        ("http://adobe-pdf-cloud-document-unlock-login.work/auth/signin-confirm-credential", 1),
        ("https://linkedin-security-notice-verify-account.loan/checkpoint/login-update", 1),
        ("http://instagram-copyright-appeal-verify-login.buzz/help/confirm-account-password", 1),
        ("https://facebook-business-suite-policy-verify.xyz/security/login-confirm-identity", 1),
        ("http://whatsapp-backup-chat-verify-account.top/restore/signin-confirm-pin", 1),
        ("https://telegram-web-verify-active-session.click/auth/login-unlock-account", 1),
        ("http://discord-nitro-gift-claim-verify-login.work/billing/signin-confirm-token", 1),
        ("https://stripe-merchant-payout-suspended-verify.loan/dashboard/login-update-bank", 1),
        ("http://shopify-store-compliance-verify-account.buzz/admin/login-confirm-billing", 1),
        ("https://intuit-quickbooks-invoice-verify-login.xyz/auth/signin-update-password", 1),
        ("http://wells-fargo-online-banking-verify-alert.top/connect/login-unlock-account", 1),
        ("https://citibank-card-security-verify-signin.click/banking/login-confirm-pin", 1),
        ("http://hsbc-net-security-token-update-login.work/portal/verify-account-credential", 1),
        ("https://barclays-ibanking-membership-verify.loan/auth/login-confirm-passcode", 1),
        ("http://santander-particulares-acceso-verify.buzz/login/confirm-account-update", 1),
    ]

    rows: List[Dict[str, Any]] = []
    timestamp = "2026-10-12T00:00:00Z"

    for domain, paths in benign_domains:
        for idx, path in enumerate(paths):
            scheme = "https" if idx % 5 != 4 else "http"
            rows.append(
                {
                    "url": f"{scheme}://{domain}{path}",
                    "label": 0,
                    "source_id": "curated_benign_reference_v1",
                    "collected_at": timestamp,
                    "licence_ref": "CC0-1.0 / Public Standard Domains",
                }
            )

    for domain, path in benign_complex:
        rows.append(
            {
                "url": f"https://{domain}{path}",
                "label": 0,
                "source_id": "curated_benign_complex_v1",
                "collected_at": timestamp,
                "licence_ref": "CC0-1.0 / Public Standard Domains",
            }
        )

    for url_str, label in malicious_patterns:
        rows.append(
            {
                "url": url_str,
                "label": label,
                "source_id": "synthetic_phishing_lexical_patterns_v1",
                "collected_at": timestamp,
                "licence_ref": "MIT / Synthetic Defanged Lexical Patterns (RFC 2606 / RFC 5737)",
            }
        )

    # Add a second path variation for each malicious domain so group-splitting is realistically exercised
    for url_str, label in malicious_patterns[:35]:
        variant = url_str + ("&step=2" if "?" in url_str else "?step=verify")
        rows.append(
            {
                "url": variant,
                "label": label,
                "source_id": "synthetic_phishing_lexical_patterns_v1",
                "collected_at": timestamp,
                "licence_ref": "MIT / Synthetic Defanged Lexical Patterns (RFC 2606 / RFC 5737)",
            }
        )

    # Intentionally include a small number of quality anomalies so Step 2 Data Quality Audit
    # detects and reports real anomalies transparently without silently discarding large volumes:
    # 1 exact duplicate, 1 missing URL, 1 invalid label, 1 malformed URL
    rows.append(rows[0].copy())  # exact duplicate
    rows.append(
        {
            "url": "",
            "label": 0,
            "source_id": "quality_audit_fixture",
            "collected_at": timestamp,
            "licence_ref": "CC0-1.0",
        }
    )
    rows.append(
        {
            "url": "https://example.org/invalid-label-row",
            "label": 99,
            "source_id": "quality_audit_fixture",
            "collected_at": timestamp,
            "licence_ref": "CC0-1.0",
        }
    )
    rows.append(
        {
            "url": "ftp://unsupported-scheme.example.org/file.zip",
            "label": 1,
            "source_id": "quality_audit_fixture",
            "collected_at": timestamp,
            "licence_ref": "CC0-1.0",
        }
    )

    fieldnames = ["url", "label", "source_id", "collected_at", "licence_ref"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def audit_and_clean_dataset(csv_path: Path) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """Run Step 2 Data Quality Checks and return cleaned DataFrame + quality report."""
    raw_df = pd.read_csv(csv_path, keep_default_na=False)
    total_raw_rows = len(raw_df)

    missing_url_count = 0
    missing_label_count = 0
    invalid_label_count = 0
    malformed_url_count = 0
    exact_duplicate_count = 0
    conflicting_label_urls: List[str] = []

    url_to_labels: Dict[str, set] = {}
    for _, row in raw_df.iterrows():
        u = str(row.get("url", "")).strip()
        lbl_raw = str(row.get("label", "")).strip()
        if u and lbl_raw in {"0", "1"}:
            url_to_labels.setdefault(u, set()).add(int(lbl_raw))

    for u, lbl_set in url_to_labels.items():
        if len(lbl_set) > 1:
            conflicting_label_urls.append(u)

    seen_urls: set = set()
    valid_records: List[Dict[str, Any]] = []

    for idx, row in raw_df.iterrows():
        u = str(row.get("url", "")).strip()
        lbl_raw = str(row.get("label", "")).strip()

        if not u:
            missing_url_count += 1
            continue

        if lbl_raw == "":
            missing_label_count += 1
            continue

        try:
            lbl = int(lbl_raw)
        except ValueError:
            invalid_label_count += 1
            continue

        if lbl not in (0, 1):
            invalid_label_count += 1
            continue

        if u in conflicting_label_urls:
            continue

        if u in seen_urls:
            exact_duplicate_count += 1
            continue

        try:
            parsed = validate_and_parse_url(u)
            feats = extract_lexical_features(parsed)
        except URLValidationError:
            malformed_url_count += 1
            continue

        seen_urls.add(u)
        record = {
            "url": u,
            "normalized_url": parsed.normalized_url,
            "registrable_domain": parsed.registrable_domain,
            "label": lbl,
            "source_id": str(row.get("source_id", "unknown")),
            "collected_at": str(row.get("collected_at", "")),
            "licence_ref": str(row.get("licence_ref", "")),
        }
        record.update(feats)
        valid_records.append(record)

    cleaned_df = pd.DataFrame(valid_records)
    class_counts = Counter(cleaned_df["label"].tolist())
    benign_count = int(class_counts.get(0, 0))
    malicious_count = int(class_counts.get(1, 0))
    imbalance_ratio = round(benign_count / max(1, malicious_count), 4)

    quality_report = {
        "dataset_path": "ml/data/curated_url_benchmark.csv",
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "total_raw_records": total_raw_rows,
        "valid_cleaned_records": len(cleaned_df),
        "missing_urls": missing_url_count,
        "missing_labels": missing_label_count,
        "invalid_labels": invalid_label_count,
        "exact_duplicates_removed": exact_duplicate_count,
        "conflicting_label_urls": len(conflicting_label_urls),
        "malformed_or_unsupported_urls": malformed_url_count,
        "class_distribution": {
            "benign_0": benign_count,
            "malicious_1": malicious_count,
            "benign_to_malicious_ratio": imbalance_ratio,
        },
        "unique_registrable_domains": int(cleaned_df["registrable_domain"].nunique()),
        "dataset_provenance": {
            "source": "Curated Local Lexical Benchmark Dataset (Standard Public Domains + Defanged Synthetic Phishing Lexical Patterns)",
            "licence": "CC0-1.0 / MIT (RFC 2606 & RFC 5737 safe test ranges)",
            "collection_limitations": [
                "Curated local lexical benchmark dataset intended for reproducible pipeline verification and baseline lexical model training.",
                "Does not represent a live internet-wide threat feed or real-time WHOIS/DNS intelligence.",
            ],
        },
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    QUALITY_REPORT_JSON.write_text(json.dumps(quality_report, indent=2), encoding="utf-8")

    md_lines = [
        "# Data Quality Report",
        "",
        f"- **Dataset**: `{quality_report['dataset_path']}`",
        f"- **Audited At**: `{quality_report['audited_at']}`",
        f"- **Total Raw Records**: {total_raw_rows}",
        f"- **Valid Cleaned Records**: {len(cleaned_df)}",
        f"- **Unique Registrable Domains**: {quality_report['unique_registrable_domains']}",
        "",
        "## Quality Check Findings",
        "",
        "| Check | Count | Handling |",
        "| :--- | ---: | :--- |",
        f"| Missing URLs | {missing_url_count} | Excluded prior to feature extraction |",
        f"| Missing Labels | {missing_label_count} | Excluded prior to feature extraction |",
        f"| Invalid Labels (not in {{0, 1}}) | {invalid_label_count} | Excluded prior to feature extraction |",
        f"| Exact Duplicate URLs | {exact_duplicate_count} | Deduplicated to prevent train/test inflation |",
        f"| Conflicting Labels | {len(conflicting_label_urls)} | Excluded |",
        f"| Malformed / Unsupported Scheme URLs | {malformed_url_count} | Rejected by `validate_and_parse_url` |",
        "",
        "## Class Balance",
        "",
        f"- **Benign (`0`)**: {benign_count}",
        f"- **Potentially Malicious (`1`)**: {malicious_count}",
        f"- **Benign-to-Malicious Ratio**: {imbalance_ratio}",
        "",
        "## Provenance & Limitations",
        "",
        f"- **Source**: {quality_report['dataset_provenance']['source']}",
        f"- **Licence**: {quality_report['dataset_provenance']['licence']}",
        "- **Limitations**: This dataset is a curated lexical benchmark for reproducible pipeline verification and local baseline model training. It is not a substitute for live threat intelligence feeds.",
    ]
    QUALITY_REPORT_MD.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    return cleaned_df, quality_report


def train_and_evaluate(cleaned_df: pd.DataFrame, quality_report: Dict[str, Any]) -> Dict[str, Any]:
    """Train baseline models with domain-grouped split, evaluate on held-out data, and save artefacts."""
    X = cleaned_df[FEATURE_NAMES].astype(float)
    y = cleaned_df["label"].astype(int).values
    groups = cleaned_df["registrable_domain"].values

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(splitter.split(X, y, groups=groups))

    # Verify zero registrable_domain overlap between train and test splits
    train_domains = set(groups[train_idx])
    test_domains = set(groups[test_idx])
    domain_overlap = len(train_domains.intersection(test_domains))
    assert domain_overlap == 0, f"Leakage detected: {domain_overlap} domains overlap between train and test!"

    X_train, y_train = X.iloc[train_idx], y[train_idx]
    X_test, y_test = X.iloc[test_idx], y[test_idx]

    # Candidate 1: Standardized Logistic Regression + Sigmoid Calibration
    base_lr = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                LogisticRegression(
                    C=1.0,
                    solver="newton-cholesky",
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=42,
                ),
            ),
        ]
    )
    calibrated_lr = CalibratedClassifierCV(estimator=base_lr, method="sigmoid", cv=5)
    calibrated_lr.fit(X_train, y_train)

    # Fit an uncalibrated copy on X_train solely to extract interpretable standardized linear weights
    base_lr.fit(X_train, y_train)
    scaler_step: StandardScaler = base_lr.named_steps["scaler"]
    clf_step: LogisticRegression = base_lr.named_steps["clf"]
    feature_explanation_stats = {
        "means": {fname: round(float(m), 6) for fname, m in zip(FEATURE_NAMES, scaler_step.mean_)},
        "scales": {fname: round(float(s), 6) for fname, s in zip(FEATURE_NAMES, scaler_step.scale_)},
        "weights": {fname: round(float(w), 6) for fname, w in zip(FEATURE_NAMES, clf_step.coef_[0])},
    }

    # Candidate 2: Random Forest for comparison
    rf_clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        class_weight="balanced",
        random_state=42,
    )
    rf_clf.fit(X_train, y_train)

    # Evaluate Calibrated Logistic Regression on held-out test set
    y_prob = calibrated_lr.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.50).astype(int)

    prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
    rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
    f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
    roc_auc = round(float(roc_auc_score(y_test, y_prob)), 4)
    pr_auc = round(float(average_precision_score(y_test, y_prob)), 4)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred, labels=[0, 1]).ravel()
    p_class, r_class, f1_class, support_class = precision_recall_fscore_support(
        y_test, y_pred, labels=[0, 1], zero_division=0
    )

    # Also compute Random Forest F1 for comparison log
    rf_pred = rf_clf.predict(X_test)
    rf_f1 = round(float(f1_score(y_test, rf_pred, zero_division=0)), 4)

    evaluated_at = datetime.now(timezone.utc).isoformat()
    thresholds = {
        "suspicious_threshold": 0.35,
        "malicious_threshold": 0.70,
    }

    evaluation_metadata = {
        "dataset_name": "curated_url_benchmark.csv",
        "dataset_source": quality_report["dataset_provenance"]["source"],
        "dataset_licence": quality_report["dataset_provenance"]["licence"],
        "split_method": "GroupShuffleSplit (75% train / 25% held-out test, grouped by registrable_domain; 0 overlapping domains)",
        "train_sample_size": int(len(X_train)),
        "evaluation_sample_size": int(len(X_test)),
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "per_class_metrics": {
            "benign_0": {
                "precision": round(float(p_class[0]), 4),
                "recall": round(float(r_class[0]), 4),
                "f1_score": round(float(f1_class[0]), 4),
                "support": float(support_class[0]),
            },
            "malicious_1": {
                "precision": round(float(p_class[1]), 4),
                "recall": round(float(r_class[1]), 4),
                "f1_score": round(float(f1_class[1]), 4),
                "support": float(support_class[1]),
            },
        },
        "thresholds": thresholds,
        "known_limitations": [
            f"Trained on a curated lexical benchmark ({len(cleaned_df)} valid URLs across {quality_report['unique_registrable_domains']} registrable domains); performance on this benchmark does not guarantee equivalent precision/recall on novel internet-wide zero-day phishing campaigns.",
            "Analyses only lexical URL string features; does not inspect live HTML content, JavaScript behavior, DNS age, or TLS certificate chains.",
            "Compromised legitimate domains hosting malicious pages on clean paths may produce false negatives.",
            "Legitimate enterprise OAuth or redirect URLs with many parameters and keywords may produce false positives.",
        ],
        "evaluated_at": evaluated_at,
    }

    model_version = "1.0.0-logreg-calibrated"
    model_type = "CalibratedClassifierCV(StandardScaler + LogisticRegression, sigmoid, 5-fold)"

    bundle = {
        "pipeline": calibrated_lr,
        "model_version": model_version,
        "model_type": model_type,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": FEATURE_NAMES,
        "is_calibrated": True,
        "trained_at": evaluated_at,
        "thresholds": thresholds,
        "evaluation_metadata": evaluation_metadata,
        "feature_explanation_stats": feature_explanation_stats,
        "candidate_comparison": {
            "calibrated_logistic_regression_f1": f1,
            "random_forest_f1": rf_f1,
        },
    }

    ARTEFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_ARTEFACT_PATH)

    EVAL_REPORT_JSON.write_text(json.dumps(evaluation_metadata, indent=2), encoding="utf-8")

    eval_md = [
        "# Model Evaluation Report",
        "",
        f"- **Model Version**: `{model_version}`",
        f"- **Model Type**: `{model_type}`",
        f"- **Feature Schema Version**: `{FEATURE_SCHEMA_VERSION}` ({len(FEATURE_NAMES)} lexical features)",
        f"- **Evaluated At**: `{evaluated_at}`",
        f"- **Split Method**: {evaluation_metadata['split_method']}",
        f"- **Train Sample Size**: {evaluation_metadata['train_sample_size']}",
        f"- **Held-Out Evaluation Sample Size**: {evaluation_metadata['evaluation_sample_size']}",
        "",
        "## Held-Out Test Set Metrics (Actual Predictions)",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| **Precision (Class 1 - Potentially Malicious)** | {prec:.4f} |",
        f"| **Recall (Class 1 - Potentially Malicious)** | {rec:.4f} |",
        f"| **F1-Score (Class 1)** | {f1:.4f} |",
        f"| **ROC-AUC** | {roc_auc:.4f} |",
        f"| **PR-AUC** | {pr_auc:.4f} |",
        f"| **Comparison Baseline (Random Forest F1)** | {rf_f1:.4f} |",
        "",
        "## Confusion Matrix (Held-Out Test Set)",
        "",
        "| | Predicted Benign (0) | Predicted Malicious (1) |",
        "| :--- | ---: | ---: |",
        f"| **Actual Benign (0)** | TN = {tn} | FP = {fp} |",
        f"| **Actual Malicious (1)** | FN = {fn} | TP = {tp} |",
        "",
        "## Decision Thresholds",
        "",
        f"- **Lower Risk Indicators Found**: Calibrated probability `< {thresholds['suspicious_threshold']:.2f}`",
        f"- **Suspicious**: Calibrated probability `>= {thresholds['suspicious_threshold']:.2f}` and `< {thresholds['malicious_threshold']:.2f}`",
        f"- **Potentially Malicious**: Calibrated probability `>= {thresholds['malicious_threshold']:.2f}`",
        "",
        "## Known Limitations",
        "",
    ]
    for lim in evaluation_metadata["known_limitations"]:
        eval_md.append(f"- {lim}")

    EVAL_REPORT_MD.write_text("\n".join(eval_md) + "\n", encoding="utf-8")
    return evaluation_metadata


def main() -> None:
    print("Step 1: Building/ingesting curated URL benchmark dataset...")
    build_curated_benchmark_csv(DATASET_PATH)
    print(f"  -> Saved dataset to {DATASET_PATH}")

    print("Step 2: Running data quality checks and generating report...")
    cleaned_df, quality_report = audit_and_clean_dataset(DATASET_PATH)
    print(
        f"  -> Audited {quality_report['total_raw_records']} raw rows; "
        f"{quality_report['valid_cleaned_records']} valid rows across "
        f"{quality_report['unique_registrable_domains']} unique registrable domains."
    )

    print("Step 3 & 4: Training baseline models with domain-grouped split and evaluating on held-out test set...")
    eval_meta = train_and_evaluate(cleaned_df, quality_report)
    print(
        f"  -> Held-out evaluation (n={eval_meta['evaluation_sample_size']}): "
        f"Precision={eval_meta['precision']:.4f}, Recall={eval_meta['recall']:.4f}, "
        f"F1={eval_meta['f1_score']:.4f}, ROC-AUC={eval_meta['roc_auc']:.4f}, PR-AUC={eval_meta['pr_auc']:.4f}"
    )
    print(f"  -> Saved model artefact to {MODEL_ARTEFACT_PATH}")


if __name__ == "__main__":
    main()
