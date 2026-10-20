import ipaddress
import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


ALLOWED_SCHEMES = {"http", "https"}
DISALLOWED_SCHEMES = {
    "javascript", "data", "file", "ftp", "ftps", "gopher", "blob", "vbscript", "about"
}

SENSITIVE_PARAM_PATTERNS = re.compile(
    r"^(pass(word)?|token|auth|key|apikey|api_key|secret|session|jwt|access_token|credential)",
    re.IGNORECASE,
)


class URLValidationError(ValueError):
    """Raised when URL fails validation or security constraints."""
    pass


def normalize_url(raw_url: str) -> str:
    """
    Safely strip and normalize an untrusted URL string without visiting it.
    If scheme is missing, defaults to http for standard RFC parsing.
    """
    if not isinstance(raw_url, str):
        raise URLValidationError("URL input must be a string.")

    cleaned = raw_url.strip()
    # Strip any accidental wrapping quotes or backticks
    if (cleaned.startswith('"') and cleaned.endswith('"')) or (
        cleaned.startswith("'") and cleaned.endswith("'")
    ) or (cleaned.startswith("`") and cleaned.endswith("`")):
        cleaned = cleaned[1:-1].strip()

    if not cleaned:
        raise URLValidationError("URL cannot be empty.")

    if len(cleaned) > 2048:
        raise URLValidationError("URL length exceeds maximum limit of 2048 characters.")

    # Check for explicitly disallowed schemes
    scheme_match = re.match(r"^([a-zA-Z0-9+.-]+):", cleaned)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in DISALLOWED_SCHEMES or scheme not in ALLOWED_SCHEMES:
            raise URLValidationError(
                f"Unsupported scheme '{scheme}'. Only http and https URLs are accepted."
            )
    else:
        # Prepend http:// if user passed a bare domain/URL
        cleaned = "http://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        raise URLValidationError(f"Malformed URL structure: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLValidationError(f"Invalid URL scheme '{scheme}'. Must be http or https.")

    netloc = parsed.netloc.strip()
    if not netloc:
        raise URLValidationError("URL must include a valid hostname/domain.")

    # Separate hostname and port if present
    hostname = parsed.hostname
    if not hostname:
        raise URLValidationError("URL does not contain a recognizable host.")

    # Reconstruct normalized URL
    normalized = urlunparse((
        scheme,
        netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
    return normalized


def redact_sensitive_url(url_str: str) -> str:
    """
    Sanitize sensitive query parameter values (tokens, passwords, keys)
    for safe logging, storage, and UI display without losing structural attributes.
    """
    try:
        parsed = urlparse(url_str)
        if not parsed.query:
            return url_str

        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        redacted_pairs = []
        for key, val in query_pairs:
            if SENSITIVE_PARAM_PATTERNS.match(key):
                redacted_pairs.append((key, "[REDACTED]"))
            else:
                redacted_pairs.append((key, val))

        redacted_query = urlencode(redacted_pairs)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            redacted_query,
            parsed.fragment,
        ))
    except Exception:
        return url_str


def is_ip_address(host: str) -> bool:
    """Check if host string is a valid IPv4 or IPv6 literal."""
    if not host:
        return False
    # Strip brackets for IPv6 literals like [::1]
    clean_host = host.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def is_private_or_loopback_ip(host: str) -> bool:
    """Check if host is localhost or a private/reserved/loopback IP address."""
    clean_host = host.strip("[]").lower()
    if clean_host in {"localhost", "localhost.localdomain", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        ip = ipaddress.ip_address(clean_host)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return False
