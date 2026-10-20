import pytest
from app.core.predictor import URLPredictor


@pytest.fixture
def predictor():
    return URLPredictor()


def test_predictor_initialization(predictor):
    assert predictor.model is not None
    assert "model_version" in predictor.metadata
    assert "features" in predictor.schema


def test_predict_safe_url(predictor):
    res = predictor.predict("https://www.google.com")
    assert res["is_phishing"] is False
    assert res["prediction"] == "legitimate"
    assert res["risk_tier"] == "low"
    assert 0.0 <= res["probability"] <= 1.0
    assert "contributing_factors" in res
    assert len(res["features"]) == 22


def test_predict_phishing_url(predictor):
    res = predictor.predict("http://paypal-verification-account-update.info/login?cmd=_login-run")
    assert res["is_phishing"] is True
    assert res["prediction"] == "phishing"
    assert res["risk_tier"] in {"medium", "high"}
    assert res["probability"] > 0.50
