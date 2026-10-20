import pytest
from app import create_app
from app.config import TestingConfig


@pytest.fixture
def app():
    app = create_app(TestingConfig)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_health_endpoint(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "URLShield | Phishing Intelligence"
    assert data["components"]["database"] == "connected"
    assert data["components"]["model_pipeline"] == "loaded"


def test_scan_api_valid_url(client):
    payload = {"url": "https://www.google.com/search?q=security"}
    res = client.post("/api/v1/scan", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    scan = data["data"]
    assert "id" in scan
    assert scan["is_phishing"] is False
    assert scan["risk_tier"] == "low"
    assert "features" in scan
    assert "contributing_factors" in scan


def test_scan_api_phishing_url(client):
    payload = {"url": "http://paypal-verification-account-update.info/login?cmd=_login-run"}
    res = client.post("/api/v1/scan", json=payload)
    assert res.status_code == 201
    data = res.get_json()
    assert data["success"] is True
    scan = data["data"]
    assert scan["is_phishing"] is True
    assert scan["risk_tier"] in {"medium", "high"}


def test_scan_api_validation_errors(client):
    # Non-json payload
    res = client.post("/api/v1/scan", data="not json")
    assert res.status_code == 400

    # Missing url
    res = client.post("/api/v1/scan", json={})
    assert res.status_code == 400

    # Invalid scheme
    res = client.post("/api/v1/scan", json={"url": "javascript:alert(1)"})
    assert res.status_code == 422
    assert "Unsupported scheme" in res.get_json()["message"]


def test_list_and_get_scans_api(client):
    # Create two scans
    client.post("/api/v1/scan", json={"url": "https://site-a.com"})
    client.post("/api/v1/scan", json={"url": "https://site-b.com"})

    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["pagination"]["total_items"] >= 2

    # Get single scan
    first_id = data["data"]["items"][0]["id"]
    res_single = client.get(f"/api/v1/scans/{first_id}")
    assert res_single.status_code == 200
    assert res_single.get_json()["data"]["id"] == first_id

    # 404 for unknown scan
    res_404 = client.get("/api/v1/scans/non-existent-uuid")
    assert res_404.status_code == 404


def test_delete_scan_api(client):
    res_create = client.post("/api/v1/scan", json={"url": "https://temp-delete.com"})
    scan_id = res_create.get_json()["data"]["id"]

    res_del = client.delete(f"/api/v1/scans/{scan_id}")
    assert res_del.status_code == 200
    assert res_del.get_json()["success"] is True

    # 404 after deletion
    res_del_again = client.delete(f"/api/v1/scans/{scan_id}")
    assert res_del_again.status_code == 404


def test_csv_export_endpoint(client):
    client.post("/api/v1/scan", json={"url": "https://csv-test.com"})
    res = client.get("/api/v1/scans/export/csv")
    assert res.status_code == 200
    assert res.mimetype == "text/csv"
    assert "attachment; filename=urlshield_scans_export.csv" in res.headers["Content-Disposition"]
    assert "csv-test.com" in res.get_data(as_text=True)


def test_model_metrics_endpoint(client):
    res = client.get("/api/v1/model/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "metadata" in data["data"]
    assert "schema" in data["data"]
    assert data["data"]["metadata"]["model_name"] == "URLShield Phishing Detector"
