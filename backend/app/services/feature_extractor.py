"""
PhishGuard Shared Feature Extractor
====================================
Single source of truth for URL feature extraction, used by both
the ML training pipeline and the API inference service.

Design decisions:
- Features are ratio-based where possible to avoid path-length bias
  between legitimate and phishing URL datasets.
- Domain-level features are primary signals.
- Path/query features use ratios (not absolute counts/lengths).
- Returns a fixed-order dictionary of 29 features.
"""

import math
import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qs

import numpy as np
import pandas as pd


# ──────────────────────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────────────────────

BRAND_KEYWORDS = frozenset([
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "chase",
    "wellsfargo", "bankofamerica", "citibank", "usaa", "yahoo",
    "outlook", "office365", "adobe", "docusign", "dhl", "fedex",
    "ups", "irs", "walmart", "ebay", "spotify", "steam", "roblox",
    "coinbase", "binance", "metamask",
])

SUSPICIOUS_TLDS = frozenset([
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
    "info", "online", "site", "website", "space", "tech", "buzz",
    "surf", "click", "link", "win", "bid", "stream", "download",
    "racing", "review", "party", "science", "cricket", "accountant",
    "faith", "loan", "date",
])

SHORTENER_DOMAINS = frozenset([
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "j.mp", "rb.gy", "cutt.ly", "shorturl.at",
])

# ── Static Asset Filter (Product Scope: Page URLs Only) ──
# Decided after seeing mid-tier validation errors: the product input is page
# URLs, so static assets (.ico, .css, etc.) should never enter eval/training.
STATIC_ASSET_EXTENSIONS = frozenset([
    '.ico', '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.woff', '.woff2', '.ttf', '.map', '.json', '.xml',
])


def is_static_asset_url(url: str) -> bool:
    """Return True if the URL points to a static asset, not a page."""
    try:
        path = urlparse(url).path.lower().rstrip("/")
        return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)
    except Exception:
        return False


# ── Learned TLD Phishing Rates (replaces hand-written SUSPICIOUS_TLDS) ──
# The hand-written SUSPICIOUS_TLDS list is kept as a fallback for backward
# compatibility when no learned rates are available.
_tld_phish_rates: Dict[str, float] = {}
_tld_default_rate: float = -1.0  # sentinel: -1 means "use binary fallback"


def set_tld_phish_rates(rates: Dict[str, float], default_rate: float = 0.5) -> None:
    """Set learned per-TLD phishing rates (call during training and model load).

    When set, ``extract_features()`` uses continuous rates instead of the
    hand-written binary ``SUSPICIOUS_TLDS`` set.
    """
    global _tld_phish_rates, _tld_default_rate
    _tld_phish_rates = dict(rates)
    _tld_default_rate = default_rate


def get_tld_phish_rate(tld: str) -> float:
    """Return the phishing rate for a TLD.

    Falls back to binary 0/1 from the hand-written list if no learned
    rates have been set (backward compatibility).
    """
    if _tld_phish_rates:
        return _tld_phish_rates.get(tld, _tld_default_rate)
    return 1.0 if tld in SUSPICIOUS_TLDS else 0.0


# Feature names in canonical order (used everywhere)
FEATURE_NAMES: List[str] = [
    # Scheme (1)
    "is_https",
    # Domain-level (15)
    "domain_length",
    "hostname_length",
    "domain_dot_count",
    "domain_hyphen_count",
    "domain_digit_count",
    "domain_digit_ratio",
    "domain_entropy",
    "subdomain_count",
    "has_ip_address",
    "suspicious_tld",
    "tld_length",
    "has_punycode",
    "brand_in_subdomain",
    "brand_in_domain",
    "brand_impersonation",
    # URL-level ratios (4)
    "has_at_symbol",
    "has_double_slash_redirect",
    "url_special_char_ratio",
    "url_digit_ratio",
    # Shortener (1)
    "is_shortened",
    # Path ratios (5)
    "has_path",
    "path_depth",
    "path_digit_ratio",
    "path_hyphen_ratio",
    "path_has_suspicious_ext",
    # Query/fragment (3)
    "query_param_count",
    "query_length_ratio",
    "has_fragment",
]

# Human-readable explanations for SHAP output
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "is_https": "Uses HTTPS encryption",
    "domain_length": "Length of the registered domain",
    "hostname_length": "Length of the full hostname",
    "domain_dot_count": "Number of dots in hostname",
    "domain_hyphen_count": "Number of hyphens in hostname",
    "domain_digit_count": "Number of digits in hostname",
    "domain_digit_ratio": "Ratio of digits in hostname",
    "domain_entropy": "Character randomness (entropy) of hostname",
    "subdomain_count": "Number of subdomains",
    "has_ip_address": "Uses IP address instead of domain name",
    "suspicious_tld": "TLD phishing rate (smoothed, learned from training data)",
    "tld_length": "Length of the top-level domain",
    "has_punycode": "Uses punycode encoding (possible homoglyph attack)",
    "brand_in_subdomain": "Contains a known brand name in subdomain",
    "brand_in_domain": "Contains a known brand name in domain",
    "brand_impersonation": "Brand in subdomain but NOT in registered domain",
    "has_at_symbol": "URL contains '@' symbol (possible redirect trick)",
    "has_double_slash_redirect": "URL contains extra '//' (redirect trick)",
    "url_special_char_ratio": "Ratio of special characters in URL",
    "url_digit_ratio": "Ratio of digits in URL",
    "is_shortened": "Uses a URL shortening service",
    "has_path": "URL has a path beyond root",
    "path_depth": "Depth of the URL path",
    "path_digit_ratio": "Ratio of digits in the path",
    "path_hyphen_ratio": "Ratio of hyphens in the path",
    "path_has_suspicious_ext": "Path ends with a suspicious file extension",
    "query_param_count": "Number of query parameters",
    "query_length_ratio": "Ratio of query string length to URL length",
    "has_fragment": "URL has a fragment identifier",
}


# ──────────────────────────────────────────────────────────────
#  Helper functions
# ──────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )


def _extract_registered_domain(hostname: str) -> str:
    """Extract the registered domain (eSLD + TLD) from a hostname.

    Simplified version — handles common cases like ``co.uk``
    and preserves IP addresses.
    """
    if _IP_RE.match(hostname):
        return hostname
    parts = hostname.split(".")
    # Handle two-part TLDs like co.uk, com.au
    TWO_PART_TLDS = {"co.uk", "com.au", "co.in", "co.jp", "ac.uk", "org.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _extract_sld(reg_domain: str) -> str:
    """Extract the second-level domain (SLD) without TLD suffix.

    Examples:
        apple.com -> apple
        apple.co.uk -> apple
        apple-dns.net -> apple-dns
        paypal-update.com -> paypal-update
    """
    parts = reg_domain.split(".")
    TWO_PART_TLDS = {"co.uk", "com.au", "co.in", "co.jp", "ac.uk", "org.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _extract_tld(hostname: str) -> str:
    """Extract the TLD from a hostname."""
    parts = hostname.split(".")
    return parts[-1] if parts else ""


def _count_subdomains(hostname: str) -> int:
    """Count the number of subdomain levels, treating www as default web prefix."""
    h = hostname[4:] if hostname.startswith("www.") else hostname
    parts = h.split(".")
    TWO_PART_TLDS = {"co.uk", "com.au", "co.in", "co.jp", "ac.uk", "org.uk"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in TWO_PART_TLDS:
        return max(len(parts) - 3, 0)
    return max(len(parts) - 2, 0)


_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_SUSPICIOUS_EXT_RE = re.compile(
    r"\.(exe|php|cgi|bat|cmd|scr|js|asp|aspx|jsp)$", re.IGNORECASE
)


# ──────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────

def extract_features(url: str) -> Dict[str, float]:
    """Extract features from a single URL.

    Returns a dict with exactly ``len(FEATURE_NAMES)`` keys in
    canonical order.  All values are numeric floats suitable for
    direct model input.

    Features are designed to avoid path-length bias:
    - Domain-level features are primary signals.
    - Path/query features use **ratios**, not absolute lengths.
    - Normalized domain features treat www. invariantly.
    """
    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {name: 0.0 for name in FEATURE_NAMES}

    hostname = (parsed.hostname or "").lower()
    norm_hostname = hostname[4:] if hostname.startswith("www.") else hostname
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = (parsed.scheme or "").lower()

    reg_domain = _extract_registered_domain(hostname)
    tld = _extract_tld(hostname)
    subdomain_part = norm_hostname.replace(reg_domain, "").strip(".")

    # Strip scheme for URL-level ratio features
    url_body = url.split("://", 1)[-1] if "://" in url else url
    url_body_len = max(len(url_body), 1)

    # ── Scheme ──
    f: Dict[str, float] = {}
    f["is_https"] = 1.0 if scheme == "https" else 0.0

    # ── Domain-level (Invariant to www prefix) ──
    f["domain_length"] = float(len(reg_domain))
    f["hostname_length"] = float(len(norm_hostname))
    f["domain_dot_count"] = float(norm_hostname.count("."))
    f["domain_hyphen_count"] = float(norm_hostname.count("-"))
    f["domain_digit_count"] = float(sum(c.isdigit() for c in norm_hostname))
    f["domain_digit_ratio"] = (
        sum(c.isdigit() for c in norm_hostname) / max(len(norm_hostname), 1)
    )
    f["domain_entropy"] = _shannon_entropy(norm_hostname)
    f["subdomain_count"] = float(_count_subdomains(norm_hostname))
    f["has_ip_address"] = 1.0 if _IP_RE.match(hostname) else 0.0
    f["suspicious_tld"] = get_tld_phish_rate(tld)
    f["tld_length"] = float(len(tld))
    f["has_punycode"] = 1.0 if "xn--" in hostname else 0.0

    # Brand detection:
    # A brand on its own official domain (e.g. sld == "apple" for apple.com)
    # is legitimate and MUST NOT be penalized with brand_in_domain = 1.0.
    # brand_in_domain is only triggered when a brand keyword appears inside
    # an unofficial / typosquatted compound domain (e.g. sld == "apple-verify").
    sld = _extract_sld(reg_domain)
    is_official_brand_domain = (sld in BRAND_KEYWORDS)

    brand_sub = any(b in subdomain_part for b in BRAND_KEYWORDS)
    brand_dom = any(b in sld for b in BRAND_KEYWORDS) and not is_official_brand_domain

    f["brand_in_subdomain"] = 1.0 if (brand_sub and not is_official_brand_domain) else 0.0
    f["brand_in_domain"] = 1.0 if brand_dom else 0.0
    f["brand_impersonation"] = 1.0 if (brand_sub and not is_official_brand_domain and not brand_dom) else 0.0

    # ── URL-level (ratio-based) ──
    f["has_at_symbol"] = 1.0 if "@" in url else 0.0
    f["has_double_slash_redirect"] = 1.0 if url.count("//") > 1 else 0.0
    f["url_special_char_ratio"] = (
        sum(1 for c in url_body if not c.isalnum() and c not in "./-_")
        / url_body_len
    )
    f["url_digit_ratio"] = (
        sum(c.isdigit() for c in url_body) / url_body_len
    )

    # ── Shortener ──
    f["is_shortened"] = (
        1.0 if any(s in hostname for s in SHORTENER_DOMAINS) else 0.0
    )

    # ── Path (ratio-based to avoid length bias) ──
    f["has_path"] = 1.0 if path and path != "/" else 0.0
    stripped = path.strip("/")
    f["path_depth"] = float(min(stripped.count("/") + 1, 10)) if stripped else 0.0
    path_len = max(len(path), 1)
    f["path_digit_ratio"] = sum(c.isdigit() for c in path) / path_len
    f["path_hyphen_ratio"] = path.count("-") / path_len
    f["path_has_suspicious_ext"] = (
        1.0 if _SUSPICIOUS_EXT_RE.search(path) else 0.0
    )

    # ── Query / Fragment ──
    try:
        params = parse_qs(query)
        f["query_param_count"] = float(min(len(params), 20))
    except Exception:
        f["query_param_count"] = 0.0
    f["query_length_ratio"] = len(query) / url_body_len
    f["has_fragment"] = 1.0 if parsed.fragment else 0.0

    # Round and return in canonical order
    return {k: round(f[k], 6) for k in FEATURE_NAMES}


def extract_features_batch(urls: List[str]) -> pd.DataFrame:
    """Extract features for a list of URLs.

    Returns a DataFrame with columns in ``FEATURE_NAMES`` order.
    """
    records = [extract_features(u) for u in urls]
    return pd.DataFrame(records, columns=FEATURE_NAMES)


def get_feature_names() -> List[str]:
    """Return the canonical ordered list of feature names."""
    return list(FEATURE_NAMES)


def get_feature_description(name: str) -> str:
    """Return a human-readable description for a feature."""
    return FEATURE_DESCRIPTIONS.get(name, name.replace("_", " ").title())


def extract_domain(url: str) -> str:
    """Extract the registered domain from a URL (for domain-based splitting)."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        return _extract_registered_domain(hostname)
    except Exception:
        return url
