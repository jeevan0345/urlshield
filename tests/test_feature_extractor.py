import pytest
from app.core.feature_extractor import (
    FEATURE_NAMES,
    calculate_entropy,
    extract_features_from_url,
    features_to_vector,
)


def test_feature_parity_and_count():
    feats = extract_features_from_url("https://example.com/login?token=abc")
    assert len(feats) == len(FEATURE_NAMES)
    vec = features_to_vector(feats)
    assert len(vec) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert name in feats


def test_entropy_calculation():
    # Empty string has zero entropy
    assert calculate_entropy("") == 0.0
    # Homogeneous string has zero entropy
    assert calculate_entropy("aaaaaa") == 0.0
    # Two alternating characters have 1 bit of entropy
    assert round(calculate_entropy("abababab"), 2) == 1.0
    # High entropy random string
    assert calculate_entropy("4f8a9c1e2b7d30f5") > 3.5


def test_lexical_feature_values():
    url = "http://192.168.1.100/secure-login/update.php?id=123"
    feats = extract_features_from_url(url)

    assert feats["is_ip_host"] == 1
    assert feats["is_private_ip"] == 1
    assert feats["is_https"] == 0
    assert feats["num_digits"] >= 10
    assert feats["has_suspicious_keyword"] == 1
    assert feats["num_hyphens"] >= 1


def test_punycode_detection():
    url = "https://xn--appl-43d.com/login"
    feats = extract_features_from_url(url)
    assert feats["has_punycode"] == 1
