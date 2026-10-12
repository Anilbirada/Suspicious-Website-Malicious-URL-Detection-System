"""Pure lexical URL validation, normalization, and feature extraction module.

SECURITY NOTICE:
This module inspects URL strings strictly lexically in memory.
It NEVER performs network requests, DNS resolution, socket connections,
shell execution, or filesystem lookups based on submitted URLs.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import idna

FEATURE_SCHEMA_VERSION = "1.0.0"

SUPPORTED_SCHEMES = {"http", "https"}

# Common two-level public suffixes to improve registrable domain and subdomain counting
COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "co.in",
    "ac.in",
    "gov.in",
    "org.in",
    "edu.in",
    "com.au",
    "org.au",
    "edu.au",
    "co.jp",
    "com.br",
    "co.za",
}

SUSPICIOUS_LEXICAL_TOKENS = (
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "banking",
    "password",
    "credential",
    "wallet",
    "unlock",
    "suspend",
    "billing",
    "recover",
)

SUSPICIOUS_TLD_SET = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "zip",
    "mov",
    "click",
    "work",
    "loan",
    "buzz",
}

PERCENT_ENCODING_RE = re.compile(r"%[0-9a-fA-F]{2}")
CONTROL_CHAR_RE = re.compile(r"[\x00-\x20\x7f]")
HOSTNAME_LABEL_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
SHORTENING_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
}

FEATURE_DOCUMENTATION: Dict[str, Dict[str, str]] = {
    "url_length": {
        "type": "int",
        "description": "Total character length of the trimmed URL string.",
        "limitation": "Long URLs are common in legitimate e-commerce, analytics, and OAuth flows.",
    },
    "hostname_length": {
        "type": "int",
        "description": "Character length of the normalized ASCII hostname.",
        "limitation": "Long hostnames may occur in legitimate cloud or enterprise subdomains.",
    },
    "path_length": {
        "type": "int",
        "description": "Character length of the URL path component.",
        "limitation": "Deep paths are normal in documentation sites, CMS platforms, and REST APIs.",
    },
    "query_length": {
        "type": "int",
        "description": "Character length of the URL query string.",
        "limitation": "Search queries and tracking links routinely contain long query strings.",
    },
    "dot_count": {
        "type": "int",
        "description": "Total count of dot ('.') characters across the entire URL.",
        "limitation": "File extensions, version numbers, and subdomains increase dot count benignly.",
    },
    "hyphen_count": {
        "type": "int",
        "description": "Total count of hyphen ('-') characters across the entire URL.",
        "limitation": "Readable article slugs and UUIDs legitimately contain many hyphens.",
    },
    "hostname_hyphen_count": {
        "type": "int",
        "description": "Count of hyphen ('-') characters specifically within the hostname.",
        "limitation": "Some legitimate organizations and cloud environments use hyphenated domains.",
    },
    "digit_count": {
        "type": "int",
        "description": "Total count of numeric digits ('0'-'9') in the URL.",
        "limitation": "Product IDs, dates, and pagination parameters contain digits naturally.",
    },
    "hostname_digit_count": {
        "type": "int",
        "description": "Count of numeric digits ('0'-'9') within the hostname.",
        "limitation": "CDN nodes and regional servers may include digits in hostnames.",
    },
    "query_param_count": {
        "type": "int",
        "description": "Number of key-value parameters present in the URL query string.",
        "limitation": "Filtering and pagination views legitimately pass multiple query parameters.",
    },
    "subdomain_count": {
        "type": "int",
        "description": "Estimated number of subdomain labels preceding the registrable domain.",
        "limitation": "University, government, and enterprise portals often use multi-level subdomains.",
    },
    "is_ip_address": {
        "type": "int (0 or 1)",
        "description": "1 if the hostname is a literal IPv4 or IPv6 address; 0 otherwise.",
        "limitation": "Local routers, lab servers, and development hosts legitimately use IP addresses.",
    },
    "has_at_symbol": {
        "type": "int (0 or 1)",
        "description": "1 if '@' appears in the URL or authority component; 0 otherwise.",
        "limitation": "In authority sections, text before '@' is treated as userinfo, which can obscure the actual destination host.",
    },
    "is_https": {
        "type": "int (0 or 1)",
        "description": "1 if the URL uses the 'https' scheme; 0 if 'http'.",
        "limitation": "HTTPS only indicates transport encryption; phishing sites routinely use free TLS certificates.",
    },
    "has_punycode": {
        "type": "int (0 or 1)",
        "description": "1 if the hostname uses Punycode ('xn--') or non-ASCII internationalized labels.",
        "limitation": "Internationalized Domain Names (IDNs) serve legitimate non-English communities worldwide.",
    },
    "percent_encoding_count": {
        "type": "int",
        "description": "Count of '%XX' hexadecimal percent-encoded byte sequences in the URL.",
        "limitation": "Spaces, Unicode paths, and redirect parameters legitimately use percent encoding.",
    },
    "suspicious_keyword_count": {
        "type": "int",
        "description": "Count of sensitive account/credential keywords found in subdomains, path, or query.",
        "limitation": "Legitimate authentication and account management pages also contain words like 'login' or 'account'.",
    },
    "hostname_entropy": {
        "type": "float",
        "description": "Shannon character entropy of the hostname (bits per character, rounded to 4 decimals).",
        "limitation": "Long composite domain names can have moderately elevated character entropy.",
    },
}

FEATURE_NAMES: List[str] = list(FEATURE_DOCUMENTATION.keys())


class URLValidationError(ValueError):
    """Raised when a submitted URL fails lexical validation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedURLInfo:
    """Normalized lexical representation of a validated URL."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    ascii_hostname: str
    registrable_domain: str
    path: str
    query: str
    port: Optional[int]
    has_userinfo: bool
    is_ip: bool
    is_punycode: bool
    url_sha256: str


@dataclass(frozen=True)
class LexicalIndicator:
    """Human-readable indicator explaining a specific URL characteristic."""

    code: str
    title: str
    severity: str  # "info", "low", "medium", "high"
    description: str
    observed_value: str


def calculate_shannon_entropy(text: str) -> float:
    """Compute Shannon character entropy in bits per character."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text.lower())
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return round(entropy, 4)


def _extract_registrable_domain_and_subdomains(ascii_hostname: str, is_ip: bool) -> Tuple[str, int]:
    """Estimate the registrable domain and number of subdomains without network calls."""
    if is_ip or not ascii_hostname:
        return ascii_hostname, 0

    labels = [lbl for lbl in ascii_hostname.split(".") if lbl]
    if len(labels) <= 2:
        return ascii_hostname, 0

    last_two = f"{labels[-2]}.{labels[-1]}"
    if last_two in COMMON_SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
        registrable = f"{labels[-3]}.{last_two}"
        subdomain_count = len(labels) - 3
    else:
        registrable = last_two
        subdomain_count = len(labels) - 2

    return registrable, max(0, subdomain_count)


def validate_and_parse_url(raw_url: Any, max_length: int = 2048) -> ParsedURLInfo:
    """Validate and parse a submitted URL string safely without network access."""
    if not isinstance(raw_url, str):
        raise URLValidationError("INVALID_TYPE", "Submitted URL must be a text string.")

    trimmed = raw_url.strip()
    if not trimmed:
        raise URLValidationError("EMPTY_URL", "Please enter a URL to analyse. Input cannot be empty.")

    if len(trimmed) > max_length:
        raise URLValidationError(
            "URL_TOO_LONG",
            f"Submitted URL length ({len(trimmed)} characters) exceeds the maximum allowed limit of {max_length} characters.",
        )

    if CONTROL_CHAR_RE.search(trimmed):
        raise URLValidationError(
            "MALFORMED_URL",
            "Submitted URL contains unencoded whitespace or control characters.",
        )

    if "://" not in trimmed:
        # Check if someone passed a scheme with single colon like javascript:alert(1) or data:text/html
        if ":" in trimmed.split("/")[0]:
            candidate_scheme = trimmed.split(":", 1)[0].lower()
            if candidate_scheme not in SUPPORTED_SCHEMES:
                raise URLValidationError(
                    "UNSUPPORTED_SCHEME",
                    f"Unsupported URL scheme '{candidate_scheme}'. Only 'http://' and 'https://' URLs are supported.",
                )
        raise URLValidationError(
            "MALFORMED_URL",
            "URL must include an explicit scheme such as 'https://' or 'http://'.",
        )

    try:
        split_result = urlsplit(trimmed)
    except ValueError as exc:
        raise URLValidationError("MALFORMED_URL", f"Malformed URL structure: {exc}") from exc

    scheme = (split_result.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise URLValidationError(
            "UNSUPPORTED_SCHEME",
            f"Unsupported URL scheme '{scheme or 'none'}'. Only 'http' and 'https' are supported.",
        )

    netloc = split_result.netloc
    if not netloc:
        raise URLValidationError("MALFORMED_URL", "URL is missing a valid hostname or domain name.")

    # Extract userinfo if '@' is present in authority section
    has_userinfo = "@" in netloc
    hostport = netloc.rpartition("@")[2] if has_userinfo else netloc
    if not hostport:
        raise URLValidationError("MALFORMED_URL", "URL authority section is missing a destination hostname.")

    # Validate port safely
    try:
        port = split_result.port
    except ValueError as exc:
        raise URLValidationError("MALFORMED_URL", "URL contains an invalid port number.") from exc

    raw_hostname = split_result.hostname
    if not raw_hostname:
        raise URLValidationError("MALFORMED_URL", "URL does not contain a recognizable hostname.")

    raw_hostname = raw_hostname.strip().lower()
    if raw_hostname.startswith(".") or raw_hostname.endswith(".") or ".." in raw_hostname:
        raise URLValidationError("MALFORMED_URL", "Hostname contains empty or leading/trailing dot labels.")

    # Check if hostname is an IPv4 or IPv6 literal
    is_ip = False
    ascii_hostname = raw_hostname
    is_punycode = False

    try:
        ip_obj = ipaddress.ip_address(raw_hostname)
        is_ip = True
        ascii_hostname = str(ip_obj)
    except ValueError:
        # Check if it looks like an invalid IPv4 address (all numeric labels)
        labels = raw_hostname.split(".")
        if len(labels) < 2:
            raise URLValidationError(
                "MALFORMED_URL",
                "Hostname must be a valid domain name with a top-level domain (e.g., example.com) or a valid IP address.",
            )
        if all(lbl.isdigit() for lbl in labels):
            raise URLValidationError("MALFORMED_URL", "Hostname appears to be an out-of-range IPv4 address.")

        ascii_labels: List[str] = []
        for label in labels:
            if not label:
                raise URLValidationError("MALFORMED_URL", "Hostname contains an empty label.")
            has_non_ascii = not label.isascii()
            if has_non_ascii or label.startswith("xn--"):
                is_punycode = True
                try:
                    encoded_label = idna.encode(label).decode("ascii").lower()
                except idna.IDNAError as exc:
                    raise URLValidationError(
                        "MALFORMED_URL",
                        f"Hostname contains an invalid internationalized domain label ('{label}').",
                    ) from exc
                ascii_labels.append(encoded_label)
            else:
                if not HOSTNAME_LABEL_RE.match(label):
                    raise URLValidationError(
                        "MALFORMED_URL",
                        f"Hostname label '{label}' contains invalid characters or invalid hyphen placement.",
                    )
                ascii_labels.append(label)

        # Ensure TLD is not purely numeric
        tld = ascii_labels[-1]
        if tld.isdigit() or len(tld) < 2:
            raise URLValidationError("MALFORMED_URL", "Hostname top-level domain (TLD) is invalid.")

        ascii_hostname = ".".join(ascii_labels)

    registrable_domain, _ = _extract_registrable_domain_and_subdomains(ascii_hostname, is_ip)
    path = split_result.path or "/"
    query = split_result.query or ""

    normalized_host = f"[{ascii_hostname}]" if (is_ip and ":" in ascii_hostname) else ascii_hostname
    port_suffix = f":{port}" if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) else ""
    query_suffix = f"?{query}" if query else ""
    normalized_url = f"{scheme}://{normalized_host}{port_suffix}{path}{query_suffix}"
    url_sha256 = hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()

    return ParsedURLInfo(
        original_url=trimmed,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=raw_hostname,
        ascii_hostname=ascii_hostname,
        registrable_domain=registrable_domain,
        path=path,
        query=query,
        port=port,
        has_userinfo=has_userinfo,
        is_ip=is_ip,
        is_punycode=is_punycode,
        url_sha256=url_sha256,
    )


def extract_lexical_features(parsed: ParsedURLInfo) -> Dict[str, float | int]:
    """Extract the 18 standardized lexical features from a ParsedURLInfo instance."""
    raw = parsed.original_url
    ascii_host = parsed.ascii_hostname
    path = parsed.path if parsed.path != "/" else ""
    query = parsed.query

    _, subdomain_count = _extract_registrable_domain_and_subdomains(ascii_host, parsed.is_ip)

    # Extract subdomain prefix + path + query for keyword inspection so legitimate root domains
    # (e.g. login.gov if registrable) aren't conflated with deceptive prefixes/paths
    subdomain_prefix = ""
    if not parsed.is_ip and ascii_host != parsed.registrable_domain:
        subdomain_prefix = ascii_host[: -(len(parsed.registrable_domain) + 1)]

    inspectable_text = f"{subdomain_prefix}/{path}?{query}".lower()
    suspicious_keyword_count = sum(1 for token in SUSPICIOUS_LEXICAL_TOKENS if token in inspectable_text)

    query_params = parse_qsl(query, keep_blank_values=True) if query else []

    features: Dict[str, float | int] = {
        "url_length": len(raw),
        "hostname_length": len(ascii_host),
        "path_length": len(parsed.path),
        "query_length": len(query),
        "dot_count": raw.count("."),
        "hyphen_count": raw.count("-"),
        "hostname_hyphen_count": ascii_host.count("-"),
        "digit_count": sum(ch.isdigit() for ch in raw),
        "hostname_digit_count": sum(ch.isdigit() for ch in ascii_host),
        "query_param_count": len(query_params),
        "subdomain_count": subdomain_count,
        "is_ip_address": 1 if parsed.is_ip else 0,
        "has_at_symbol": 1 if ("@" in raw or parsed.has_userinfo) else 0,
        "is_https": 1 if parsed.scheme == "https" else 0,
        "has_punycode": 1 if parsed.is_punycode else 0,
        "percent_encoding_count": len(PERCENT_ENCODING_RE.findall(raw)),
        "suspicious_keyword_count": suspicious_keyword_count,
        "hostname_entropy": calculate_shannon_entropy(ascii_host),
    }

    return features


def build_explainable_indicators(
    parsed: ParsedURLInfo, features: Dict[str, float | int]
) -> List[LexicalIndicator]:
    """Generate transparent, human-readable indicators from extracted URL features."""
    indicators: List[LexicalIndicator] = []

    if features["is_ip_address"] == 1:
        indicators.append(
            LexicalIndicator(
                code="IP_ADDRESS_HOSTNAME",
                title="Literal IP Address Hostname",
                severity="high",
                description=(
                    "The destination hostname is a raw IP address rather than a registered domain name. "
                    "While normal for local routers or lab environments, public websites rarely ask users "
                    "to sign in via raw IP addresses."
                ),
                observed_value=parsed.ascii_hostname,
            )
        )

    if features["has_at_symbol"] == 1:
        indicators.append(
            LexicalIndicator(
                code="AT_SYMBOL_IN_URL",
                title="'@' Symbol / Userinfo Pattern Detected",
                severity="high",
                description=(
                    "The URL contains an '@' character. In URL authority sections, browsers ignore everything "
                    "before '@' as a username and connect to the hostname after '@', a technique frequently "
                    "used to disguise the true destination host."
                ),
                observed_value="@ present",
            )
        )

    if features["has_punycode"] == 1:
        indicators.append(
            LexicalIndicator(
                code="PUNYCODE_OR_IDN",
                title="Internationalized / Punycode Domain (IDN)",
                severity="medium",
                description=(
                    "The hostname contains non-ASCII characters or 'xn--' Punycode labels. Internationalized "
                    "domains are legitimate for non-English sites, but look-alike characters (homographs) "
                    "can sometimes be used to mimic well-known brands."
                ),
                observed_value=parsed.ascii_hostname,
            )
        )

    if int(features["subdomain_count"]) >= 3:
        indicators.append(
            LexicalIndicator(
                code="DEEP_SUBDOMAIN_CHAIN",
                title="Multiple Subdomain Levels",
                severity="medium",
                description=(
                    "The hostname has 3 or more subdomain levels before the registrable domain. "
                    "Some phishing URLs prepend brand names as subdomains in front of unrelated domains."
                ),
                observed_value=f"{features['subdomain_count']} subdomains (registrable: {parsed.registrable_domain})",
            )
        )

    if int(features["hostname_hyphen_count"]) >= 2:
        indicators.append(
            LexicalIndicator(
                code="HYPHENATED_HOSTNAME",
                title="Multiple Hyphens in Hostname",
                severity="medium",
                description=(
                    "The hostname contains multiple hyphens. Deceptive domains frequently combine brand names "
                    "and action words with hyphens (e.g., 'brand-secure-verify.example')."
                ),
                observed_value=f"{features['hostname_hyphen_count']} hyphens in {parsed.ascii_hostname}",
            )
        )

    if int(features["suspicious_keyword_count"]) >= 1:
        indicators.append(
            LexicalIndicator(
                code="SENSITIVE_ACTION_KEYWORDS",
                title="Account / Credential Keywords in URL",
                severity="medium" if int(features["suspicious_keyword_count"]) < 3 else "high",
                description=(
                    "The URL subdomain, path, or query contains terms commonly associated with authentication "
                    "or account verification (such as 'login', 'verify', 'secure', 'account', or 'update'). "
                    "Verify that the registrable domain actually belongs to the expected organization."
                ),
                observed_value=f"{features['suspicious_keyword_count']} keyword match(es)",
            )
        )

    if int(features["url_length"]) >= 100:
        indicators.append(
            LexicalIndicator(
                code="EXTENDED_URL_LENGTH",
                title="Long URL String",
                severity="low" if int(features["url_length"]) < 160 else "medium",
                description=(
                    "The total URL length is relatively long. Long URLs can hide redirect targets or "
                    "encoded parameters, though legitimate search and e-commerce links can also be long."
                ),
                observed_value=f"{features['url_length']} characters",
            )
        )

    if int(features["percent_encoding_count"]) >= 3:
        indicators.append(
            LexicalIndicator(
                code="PERCENT_ENCODED_SEQUENCES",
                title="Multiple Percent-Encoded Characters",
                severity="low" if int(features["percent_encoding_count"]) < 6 else "medium",
                description=(
                    "The URL contains multiple '%XX' encoded character sequences, which may encode special "
                    "characters or nested redirect URLs."
                ),
                observed_value=f"{features['percent_encoding_count']} encoded sequences",
            )
        )

    if parsed.port and parsed.port not in (80, 443):
        indicators.append(
            LexicalIndicator(
                code="NON_STANDARD_PORT",
                title="Non-Standard Network Port",
                severity="medium",
                description=(
                    "The URL specifies an explicit port other than standard HTTP (80) or HTTPS (443)."
                ),
                observed_value=f"Port {parsed.port}",
            )
        )

    if parsed.registrable_domain in SHORTENING_HOSTS:
        indicators.append(
            LexicalIndicator(
                code="URL_SHORTENER_SERVICE",
                title="URL Shortening Service",
                severity="medium",
                description=(
                    "The domain belongs to a URL shortening service, which conceals the final destination "
                    "domain from lexical inspection."
                ),
                observed_value=parsed.registrable_domain,
            )
        )

    tld = parsed.ascii_hostname.rsplit(".", 1)[-1] if "." in parsed.ascii_hostname and not parsed.is_ip else ""
    if tld in SUSPICIOUS_TLD_SET:
        indicators.append(
            LexicalIndicator(
                code="HIGH_ABUSE_TLD",
                title="Top-Level Domain Frequently Abused in Bulk Registrations",
                severity="low",
                description=(
                    f"The '.{tld}' top-level domain is sometimes observed in low-cost bulk registrations, "
                    "though legitimate projects also use it."
                ),
                observed_value=f".{tld}",
            )
        )

    # Always include a transparent scheme indicator reminding users about HTTP/HTTPS limitations
    if parsed.scheme == "https":
        indicators.append(
            LexicalIndicator(
                code="SCHEME_HTTPS",
                title="HTTPS Transport Scheme",
                severity="info",
                description=(
                    "The URL uses 'https://'. Note: HTTPS only encrypts traffic in transit and is NOT proof "
                    "that the website owner is trustworthy or legitimate."
                ),
                observed_value="https",
            )
        )
    else:
        indicators.append(
            LexicalIndicator(
                code="SCHEME_HTTP",
                title="Unencrypted HTTP Scheme",
                severity="low",
                description=(
                    "The URL uses unencrypted 'http://'. Sensitive credentials or personal information "
                    "should not be submitted over unencrypted HTTP connections."
                ),
                observed_value="http",
            )
        )

    return indicators
