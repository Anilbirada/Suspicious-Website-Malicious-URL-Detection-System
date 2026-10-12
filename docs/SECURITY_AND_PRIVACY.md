# Security and Privacy Specification

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Security Controls Implemented

| Control Domain | Implementation Details | Verification Test |
| :--- | :--- | :--- |
| **Zero-Fetch Lexical Analysis** | Submitted URLs are parsed strictly in memory (`urllib.parse`, `ipaddress`, `idna`). The backend never opens sockets, resolves DNS, or fetches remote content. | `TC-25` |
| **Input Validation & Scheme Whitelisting** | Only `http` and `https` schemes are accepted. `javascript:`, `data:`, `file:`, `ftp:`, and `mailto:` schemes, control characters, and URLs $> 2048$ characters are rejected at the boundary. | `TC-03` – `TC-07`, `TC-21` |
| **Cross-Site Scripting (XSS) Prevention** | React renders all URL strings as escaped text nodes (never `dangerouslySetInnerHTML`). Backend responses enforce `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`. | `TC-26`, `TC-33` |
| **SQL Injection Prevention** | All database operations use SQLAlchemy 2.0 ORM parameterized queries (`select`, `delete`). No raw string concatenation is used in SQL statements. | `TC-27` |
| **Rate Limiting & Payload Size Limits** | Sliding-window per-IP rate limiter (`backend/app/core/security.py`, default 60 requests / 60s) and `MAX_REQUEST_BYTES` middleware (`16384` bytes, HTTP 413). | `TC-23` |
| **Safe Error Handling** | Custom FastAPI exception handlers return structured `error_code` and `message` fields without exposing stack traces, internal file paths, or environment variables. | `TC-24`, `TC-28` |
| **Secret Management** | Configuration is loaded from environment variables via `pydantic-settings`. `.env` and `*.db` files are excluded via `.gitignore`, and `.env.example` contains only safe placeholders. | `TC-28` |
| **Log Sanitization** | `sanitize_for_log()` strips CR/LF and control characters before logging untrusted strings to prevent log injection. | Code Review |

---

## 2. Privacy & Data Minimisation Policy

1. **No Personal Data Collection**: The application does not collect names, email addresses, IP geolocation profiles, or browser telemetry.
2. **User-Controlled History Storage**:
   - Users can uncheck *"Save result in local analysis history"* (`save_to_history: false`) on any individual URL check.
   - Administrators can disable history globally (`ENABLE_HISTORY=false`) or redact URL paths/queries (`STORE_RAW_URL_IN_HISTORY=false`).
   - Users can delete single history entries or clear all stored history at any time via the History page or `DELETE /api/v1/history` (`TC-29`).
3. **No External Data Sharing**: Submitted URLs are never transmitted to third-party APIs or external cloud services.

---

## 3. Application Security Checklist

- [x] Submitted URLs are never visited, crawled, or resolved over the network (`TC-25`).
- [x] Unsafe schemes (`javascript:`, `data:`, `file:`, `ftp:`) are rejected (`TC-05`).
- [x] Oversized URLs and oversized HTTP payloads are rejected (`TC-06`).
- [x] All user-supplied URLs are rendered as escaped text, never raw HTML (`TC-26`).
- [x] Parameterized ORM queries prevent SQL injection (`TC-27`).
- [x] Rate limiting protects analysis and history endpoints (`TC-23`).
- [x] Error and status responses never leak stack traces, file paths, or secrets (`TC-24`, `TC-28`).
- [x] `.env.example` contains only safe placeholder values and `.gitignore` excludes `.env` and SQLite databases.
