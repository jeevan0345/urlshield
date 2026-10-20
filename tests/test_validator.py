import pytest
from app.core.validator import (
    URLValidationError,
    is_ip_address,
    is_private_or_loopback_ip,
    normalize_url,
    redact_sensitive_url,
)


def test_normalize_valid_http_and_https():
    assert normalize_url("https://example.com/login") == "https://example.com/login"
    assert normalize_url("http://example.com") == "http://example.com/"
    assert normalize_url("example.com/docs") == "http://example.com/docs"


def test_normalize_strips_quotes_and_whitespace():
    assert normalize_url('  "https://example.com/path"  ') == "https://example.com/path"
    assert normalize_url(" 'https://example.com/path' ") == "https://example.com/path"
    assert normalize_url(" `https://example.com/path` ") == "https://example.com/path"


def test_reject_disallowed_schemes():
    with pytest.raises(URLValidationError, match="Unsupported scheme"):
        normalize_url("javascript:alert(1)")

    with pytest.raises(URLValidationError, match="Unsupported scheme"):
        normalize_url("data:text/html;base64,PHNjcmlwdD4=")

    with pytest.raises(URLValidationError, match="Unsupported scheme"):
        normalize_url("file:///etc/passwd")

    with pytest.raises(URLValidationError, match="Unsupported scheme"):
        normalize_url("ftp://ftp.example.com/file.txt")


def test_reject_empty_or_too_long():
    with pytest.raises(URLValidationError, match="cannot be empty"):
        normalize_url("")

    with pytest.raises(URLValidationError, match="cannot be empty"):
        normalize_url("   ")

    with pytest.raises(URLValidationError, match="exceeds maximum limit"):
        normalize_url("https://example.com/" + "a" * 2050)


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.5") is True
    assert is_ip_address("127.0.0.1") is True
    assert is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_ip_address("[::1]") is True
    assert is_ip_address("google.com") is False
    assert is_ip_address("192.168.1.com") is False


def test_is_private_or_loopback_ip():
    assert is_private_or_loopback_ip("localhost") is True
    assert is_private_or_loopback_ip("127.0.0.1") is True
    assert is_private_or_loopback_ip("192.168.1.50") is True
    assert is_private_or_loopback_ip("10.20.30.40") is True
    assert is_private_or_loopback_ip("8.8.8.8") is False
    assert is_private_or_loopback_ip("example.com") is False


def test_redact_sensitive_url():
    raw = "https://example.com/auth?token=supersecret123&user=alice&password=mypassword&apikey=key999"
    redacted = redact_sensitive_url(raw)
    assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted
    assert "password=%5BREDACTED%5D" in redacted or "password=[REDACTED]" in redacted
    assert "apikey=%5BREDACTED%5D" in redacted or "apikey=[REDACTED]" in redacted
    assert "supersecret123" not in redacted
    assert "mypassword" not in redacted
    assert "user=alice" in redacted


def test_idn_and_punycode_url():
    url = "https://xn--e1afmkfd.xn--p1ai"
    normalized = normalize_url(url)
    assert "xn--" in normalized
