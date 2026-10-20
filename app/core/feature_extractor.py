import math
import re
from urllib.parse import urlparse, parse_qsl
import tldextract

from app.core.validator import is_ip_address, is_private_or_loopback_ip


CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "account", "banking", "update", "confirm", "security", "wallet", "recover",
    "password", "credential", "auth", "validation", "support", "billing",
    "invoice"
]

BRAND_TARGETS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase",
    "wellsfargo", "binance", "metamask", "whatsapp", "instagram", "facebook"
]

SUSPICIOUS_KEYWORDS = CREDENTIAL_KEYWORDS

FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "num_subdomains",
    "has_at_symbol",
    "is_ip_host",
    "is_private_ip",
    "is_https",
    "num_suspicious_keywords",
    "has_suspicious_keyword",
    "num_percent_encoded",
    "has_punycode",
    "url_entropy",
    "host_entropy",
    "num_path_segments",
    "num_query_params",
    "tld_length",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per symbol)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_features_from_url(normalized_url: str) -> dict[str, float | int]:
    """
    Extract comprehensive lexical, host-based, structural, and entropy features
    from an untrusted normalized URL string safely without executing network requests.
    """
    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = parsed.scheme.lower()

    # Domain & subdomain breakdown via tldextract (ignoring standard www)
    ext = tldextract.extract(normalized_url)
    subdomains = [s for s in ext.subdomain.split(".") if s and s.lower() != "www"]
    num_subdomains = len(subdomains)
    tld = ext.suffix or ""

    # Character counts
    url_len = len(normalized_url)
    host_len = len(hostname)
    path_len = len(path)
    query_len = len(query)

    num_dots = normalized_url.count(".")
    num_hyphens = normalized_url.count("-")
    num_digits = sum(c.isdigit() for c in normalized_url)
    digit_ratio = round(num_digits / max(url_len, 1), 4)

    # Specific indicators
    has_at_symbol = 1 if "@" in normalized_url else 0
    is_ip = 1 if is_ip_address(hostname) else 0
    is_priv_ip = 1 if is_private_or_loopback_ip(hostname) else 0
    is_https = 1 if scheme == "https" else 0

    # Suspicious keywords & brand spoofing detection
    url_lower = normalized_url.lower()
    path_and_query = (path + "?" + query).lower()
    subdomain_str = ext.subdomain.lower()
    domain_name = ext.domain.lower()

    # Credential keywords (login, verify, update, etc.)
    cred_matches = sum(1 for kw in CREDENTIAL_KEYWORDS if kw in url_lower)

    # Brand spoofing: brand targeted in subdomain/path or hyphenated domain,
    # but official domain is NOT the brand's own registered domain
    brand_spoofed = 0
    for brand in BRAND_TARGETS:
        if (brand in subdomain_str) or (brand in path_and_query):
            if domain_name != brand:
                brand_spoofed += 1
        elif brand in domain_name and domain_name != brand:
            brand_spoofed += 1

    keyword_matches = cred_matches + (brand_spoofed * 2)
    has_keyword = 1 if keyword_matches > 0 else 0

    # Percent encoding count (%20, %2f, etc.)
    percent_encodings = len(re.findall(r"%[0-9a-fA-F]{2}", normalized_url))

    # Punycode indicator (e.g. xn--...)
    has_punycode = 1 if "xn--" in hostname else 0

    # Shannon Entropies
    url_entropy = calculate_entropy(normalized_url)
    host_entropy = calculate_entropy(hostname)

    # Path & Query structure
    path_segments = [s for s in path.split("/") if s]
    num_path_segments = len(path_segments)

    try:
        query_params = parse_qsl(query, keep_blank_values=True)
        num_query_params = len(query_params)
    except Exception:
        num_query_params = query.count("&") + 1 if query else 0

    features = {
        "url_length": url_len,
        "host_length": host_len,
        "path_length": path_len,
        "query_length": query_len,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "num_subdomains": num_subdomains,
        "has_at_symbol": has_at_symbol,
        "is_ip_host": is_ip,
        "is_private_ip": is_priv_ip,
        "is_https": is_https,
        "num_suspicious_keywords": keyword_matches,
        "has_suspicious_keyword": has_keyword,
        "num_percent_encoded": percent_encodings,
        "has_punycode": has_punycode,
        "url_entropy": url_entropy,
        "host_entropy": host_entropy,
        "num_path_segments": num_path_segments,
        "num_query_params": num_query_params,
        "tld_length": len(tld),
    }
    return features


def features_to_vector(features: dict[str, float | int]) -> list[float]:
    """Convert feature dictionary into ordered vector matching FEATURE_NAMES."""
    return [float(features[name]) for name in FEATURE_NAMES]
