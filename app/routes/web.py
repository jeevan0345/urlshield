from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify, render_template

from app.core.database import ScanDatabase
from app.core.predictor import get_predictor

web_bp = Blueprint("web", __name__)


def get_db() -> ScanDatabase:
    return current_app.extensions["db"]


@web_bp.route("/")
def dashboard_page():
    """Enterprise overview dashboard."""
    db = get_db()
    stats = db.get_stats()
    recent_scans, _, _ = db.list_scans(page=1, per_page=6)
    predictor = current_app.extensions.get("predictor") or get_predictor()
    metrics = predictor.metadata.get("test_metrics", {})
    return render_template(
        "index.html",
        active_page="dashboard",
        stats=stats,
        recent_scans=recent_scans,
        metrics=metrics,
    )


@web_bp.route("/scan")
def scan_page():
    """Interactive URL scan interface."""
    return render_template("scan.html", active_page="scan")


@web_bp.route("/history")
def history_page():
    """Scan history and audit log."""
    return render_template("history.html", active_page="history")


@web_bp.route("/metrics")
def metrics_page():
    """Model evaluation, ROC/PR curves, confusion matrix, and feature importances."""
    predictor = current_app.extensions.get("predictor") or get_predictor()
    return render_template(
        "metrics.html",
        active_page="metrics",
        metadata=predictor.metadata,
        schema=predictor.schema,
    )


@web_bp.route("/methodology")
def methodology_page():
    """Security principles, SSRF prevention, RFC compliance, and privacy policy."""
    return render_template("methodology.html", active_page="methodology")


@web_bp.route("/health")
def health_check():
    """Health status endpoint for monitoring and container readiness probes."""
    db = get_db()
    db_ok = False
    try:
        conn = db.get_connection()
        db_ok = True
        db.close_connection(conn)
    except Exception:
        db_ok = False

    predictor = current_app.extensions.get("predictor") or get_predictor()
    model_ok = predictor.model is not None

    status_code = 200 if (db_ok and model_ok) else 503
    return jsonify({
        "status": "healthy" if status_code == 200 else "degraded",
        "service": "URLShield | Phishing Intelligence",
        "version": predictor.metadata.get("model_version", "1.0.0"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": "connected" if db_ok else "unavailable",
            "model_pipeline": "loaded" if model_ok else "uninitialized",
        }
    }), status_code
