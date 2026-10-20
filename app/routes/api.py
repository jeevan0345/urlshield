import logging
from flask import Blueprint, current_app, jsonify, request, Response

from app.core.database import ScanDatabase
from app.core.predictor import URLPredictor, get_predictor
from app.core.validator import URLValidationError, normalize_url

logger = logging.getLogger("api")
api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def get_db() -> ScanDatabase:
    """Retrieve database instance from current app context."""
    return current_app.extensions["db"]


@api_bp.route("/scan", methods=["POST"])
def scan_url():
    """Scan and classify an untrusted URL string safely."""
    if not request.is_json:
        return jsonify({
            "success": False,
            "error": "Bad Request",
            "message": "Content-Type must be application/json."
        }), 400

    data = request.get_json(silent=True) or {}
    raw_url = data.get("url")

    if not raw_url or not isinstance(raw_url, str):
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": "Field 'url' is required and must be a non-empty string."
        }), 400

    try:
        predictor = current_app.extensions.get("predictor") or get_predictor()
        result = predictor.predict(raw_url)
    except URLValidationError as ve:
        return jsonify({
            "success": False,
            "error": "Validation Error",
            "message": str(ve)
        }), 422
    except Exception as e:
        logger.error("Prediction error for URL '%s': %s", raw_url[:60], e)
        return jsonify({
            "success": False,
            "error": "Inference Error",
            "message": "Failed to analyze URL."
        }), 500

    # Save to database
    db = get_db()
    saved_record = db.save_scan(result)

    return jsonify({
        "success": True,
        "data": saved_record
    }), 201


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    """Retrieve historical scans with pagination and filters."""
    db = get_db()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    risk_tier = request.args.get("risk_tier", type=str)
    prediction = request.args.get("prediction", type=str)
    search = request.args.get("search", type=str)

    items, total_count, total_pages = db.list_scans(
        page=page,
        per_page=per_page,
        risk_tier=risk_tier,
        prediction=prediction,
        search=search,
    )

    return jsonify({
        "success": True,
        "data": {
            "items": items,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_items": total_count,
                "total_pages": total_pages,
            }
        }
    }), 200


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Retrieve a single scan record by ID."""
    db = get_db()
    record = db.get_scan(scan_id)
    if not record:
        return jsonify({
            "success": False,
            "error": "Not Found",
            "message": f"Scan with ID '{scan_id}' does not exist."
        }), 404

    return jsonify({
        "success": True,
        "data": record
    }), 200


@api_bp.route("/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    """Delete a single scan record."""
    db = get_db()
    deleted = db.delete_scan(scan_id)
    if not deleted:
        return jsonify({
            "success": False,
            "error": "Not Found",
            "message": f"Scan with ID '{scan_id}' not found."
        }), 404

    return jsonify({
        "success": True,
        "message": f"Scan '{scan_id}' successfully removed."
    }), 200


@api_bp.route("/scans", methods=["DELETE"])
def clear_all_scans():
    """Clear all historical scan logs."""
    db = get_db()
    deleted_count = db.clear_all_scans()
    return jsonify({
        "success": True,
        "message": f"Successfully deleted {deleted_count} scan records."
    }), 200


@api_bp.route("/scans/export/csv", methods=["GET"])
def export_scans_csv():
    """Export all scan records as CSV."""
    db = get_db()
    csv_content = db.export_csv()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=urlshield_scans_export.csv"}
    )


@api_bp.route("/model/metrics", methods=["GET"])
def get_model_metrics():
    """Retrieve model card evaluation metrics, confusion matrix, and feature importances."""
    predictor = current_app.extensions.get("predictor") or get_predictor()
    return jsonify({
        "success": True,
        "data": {
            "metadata": predictor.metadata,
            "schema": predictor.schema,
        }
    }), 200


@api_bp.route("/stats", methods=["GET"])
def get_telemetry_stats():
    """Retrieve aggregated telemetry statistics across scans."""
    db = get_db()
    stats = db.get_stats()
    return jsonify({
        "success": True,
        "data": stats
    }), 200
