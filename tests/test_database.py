import pytest
from app.core.database import ScanDatabase


@pytest.fixture
def db():
    return ScanDatabase(":memory:")


def test_save_and_get_scan(db):
    sample = {
        "input_url": "https://example.com/test",
        "normalized_url": "https://example.com/test",
        "redacted_url": "https://example.com/test",
        "is_phishing": False,
        "prediction": "legitimate",
        "probability": 0.05,
        "risk_tier": "low",
        "risk_label": "Safe / Low Risk",
        "features": {"url_length": 25},
        "contributing_factors": [{"factor": "Standard Domain", "severity": "safe", "description": "Clean"}],
    }
    saved = db.save_scan(sample)
    assert "id" in saved

    fetched = db.get_scan(saved["id"])
    assert fetched is not None
    assert fetched["id"] == saved["id"]
    assert fetched["domain"] == "example.com"
    assert fetched["features"]["url_length"] == 25


def test_list_scans_and_pagination(db):
    for i in range(15):
        db.save_scan({
            "input_url": f"https://site{i}.com",
            "normalized_url": f"https://site{i}.com",
            "redacted_url": f"https://site{i}.com",
            "is_phishing": i % 2 == 1,
            "prediction": "phishing" if i % 2 == 1 else "legitimate",
            "probability": 0.8 if i % 2 == 1 else 0.1,
            "risk_tier": "high" if i % 2 == 1 else "low",
            "risk_label": "Phishing" if i % 2 == 1 else "Clean",
            "features": {},
            "contributing_factors": [],
        })

    items, total, pages = db.list_scans(page=1, per_page=10)
    assert total == 15
    assert len(items) == 10
    assert pages == 2

    # Filter by risk tier
    items_high, total_high, _ = db.list_scans(risk_tier="high")
    assert total_high == 7


def test_delete_and_clear(db):
    saved = db.save_scan({
        "input_url": "https://deleteme.com",
        "normalized_url": "https://deleteme.com",
        "redacted_url": "https://deleteme.com",
        "is_phishing": False,
        "prediction": "legitimate",
        "probability": 0.1,
        "risk_tier": "low",
        "risk_label": "Clean",
        "features": {},
        "contributing_factors": [],
    })

    assert db.delete_scan(saved["id"]) is True
    assert db.get_scan(saved["id"]) is None

    # Clear all
    db.save_scan({
        "input_url": "https://remaining.com",
        "normalized_url": "https://remaining.com",
        "redacted_url": "https://remaining.com",
        "is_phishing": False,
        "prediction": "legitimate",
        "probability": 0.1,
        "risk_tier": "low",
        "risk_label": "Clean",
        "features": {},
        "contributing_factors": [],
    })
    cleared = db.clear_all_scans()
    assert cleared == 1
    items, total, _ = db.list_scans()
    assert total == 0


def test_export_csv_and_stats(db):
    db.save_scan({
        "input_url": "https://stats.com",
        "normalized_url": "https://stats.com",
        "redacted_url": "https://stats.com",
        "is_phishing": True,
        "prediction": "phishing",
        "probability": 0.95,
        "risk_tier": "high",
        "risk_label": "Dangerous",
        "features": {},
        "contributing_factors": [],
    })
    stats = db.get_stats()
    assert stats["total_scans"] == 1
    assert stats["phishing_scans"] == 1

    csv_out = db.export_csv()
    assert "Scan ID,Redacted URL" in csv_out
    assert "stats.com" in csv_out
