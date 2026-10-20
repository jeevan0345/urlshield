import csv
import io
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("database")


class ScanDatabase:
    """Storage layer supporting SQLite for local development and PostgreSQL compatibility."""

    def __init__(self, db_uri: str | None = None):
        if not db_uri:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.db_path = str(base_dir / "urlshield.db")
            self.is_sqlite = True
            self.is_memory = False
        elif db_uri.startswith("sqlite:///"):
            clean_path = db_uri.replace("sqlite:///", "")
            if clean_path == ":memory:":
                self.db_path = ":memory:"
                self.is_sqlite = True
                self.is_memory = True
            else:
                self.db_path = clean_path
                self.is_sqlite = True
                self.is_memory = False
        elif db_uri == ":memory:":
            self.db_path = ":memory:"
            self.is_sqlite = True
            self.is_memory = True
        else:
            self.db_path = db_uri
            self.is_sqlite = False
            self.is_memory = False

        self._shared_conn = None
        if self.is_memory:
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row

        self.init_db()

    def get_connection(self):
        """Obtain a database connection with dictionary-like row factory."""
        if self.is_memory and self._shared_conn:
            return self._shared_conn
        if self.is_sqlite:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            return conn
        else:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            return psycopg2.connect(self.db_path, cursor_factory=RealDictCursor)

    def close_connection(self, conn):
        """Safely close connection if not persistent shared in-memory connection."""
        if not self.is_memory and conn is not None:
            conn.close()

    def init_db(self):
        """Create tables and performance indices if they do not exist."""
        table_sql = """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            normalized_url TEXT NOT NULL,
            redacted_url TEXT NOT NULL,
            domain TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            prediction TEXT NOT NULL,
            probability REAL NOT NULL,
            risk_tier TEXT NOT NULL,
            risk_label TEXT NOT NULL,
            features_json TEXT NOT NULL,
            contributing_factors_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
        CREATE INDEX IF NOT EXISTS idx_scans_risk_tier ON scans(risk_tier);
        """
        conn = self.get_connection()
        try:
            if self.is_sqlite:
                conn.executescript(table_sql)
            else:
                with conn.cursor() as cur:
                    cur.execute(table_sql)
            conn.commit()
        finally:
            self.close_connection(conn)

    def save_scan(self, scan_result: dict) -> dict:
        """Persist a completed scan into the database."""
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Extract registered domain or hostname
        try:
            domain = urlparse(scan_result.get("normalized_url", "")).hostname or "unknown"
        except Exception:
            domain = "unknown"

        record = {
            "id": scan_id,
            "url": scan_result.get("input_url", ""),
            "normalized_url": scan_result.get("normalized_url", ""),
            "redacted_url": scan_result.get("redacted_url", ""),
            "domain": domain,
            "is_phishing": 1 if scan_result.get("is_phishing") else 0,
            "prediction": scan_result.get("prediction", "unknown"),
            "probability": float(scan_result.get("probability", 0.0)),
            "risk_tier": scan_result.get("risk_tier", "low"),
            "risk_label": scan_result.get("risk_label", "Safe / Low Risk"),
            "features_json": json.dumps(scan_result.get("features", {})),
            "contributing_factors_json": json.dumps(scan_result.get("contributing_factors", [])),
            "created_at": now,
        }

        query = """
        INSERT INTO scans (
            id, url, normalized_url, redacted_url, domain, is_phishing,
            prediction, probability, risk_tier, risk_label, features_json,
            contributing_factors_json, created_at
        ) VALUES (
            :id, :url, :normalized_url, :redacted_url, :domain, :is_phishing,
            :prediction, :probability, :risk_tier, :risk_label, :features_json,
            :contributing_factors_json, :created_at
        )
        """
        conn = self.get_connection()
        try:
            if self.is_sqlite:
                conn.execute(query, record)
            else:
                with conn.cursor() as cur:
                    cur.execute(query, record)
            conn.commit()
        finally:
            self.close_connection(conn)

        result_copy = dict(scan_result)
        result_copy["id"] = scan_id
        result_copy["created_at"] = now
        return result_copy

    def get_scan(self, scan_id: str) -> dict | None:
        """Retrieve a scan by its UUID."""
        query = "SELECT * FROM scans WHERE id = ?" if self.is_sqlite else "SELECT * FROM scans WHERE id = %s"
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(query, (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_dict(row)
        finally:
            self.close_connection(conn)

    def list_scans(
        self,
        page: int = 1,
        per_page: int = 10,
        risk_tier: str | None = None,
        prediction: str | None = None,
        search: str | None = None,
    ) -> tuple[list[dict], int, int]:
        """
        List scans with filtering, domain search, and pagination.
        Returns: (items, total_count, total_pages)
        """
        page = max(1, page)
        per_page = max(1, min(100, per_page))
        offset = (page - 1) * per_page

        where_clauses = []
        params = []

        if risk_tier and risk_tier.lower() in {"low", "medium", "high"}:
            where_clauses.append("risk_tier = ?")
            params.append(risk_tier.lower())

        if prediction and prediction.lower() in {"phishing", "legitimate"}:
            where_clauses.append("prediction = ?")
            params.append(prediction.lower())

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            where_clauses.append("(LOWER(domain) LIKE ? OR LOWER(redacted_url) LIKE ?)")
            params.extend([term, term])

        where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        count_query = f"SELECT COUNT(*) FROM scans {where_str}"
        select_query = f"""
        SELECT * FROM scans {where_str}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """
        select_params = list(params) + [per_page, offset]

        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(count_query, params)
            total_count = cur.fetchone()[0]

            cur.execute(select_query, select_params)
            rows = cur.fetchall()
            items = [self._row_to_dict(r) for r in rows]

            total_pages = max(1, (total_count + per_page - 1) // per_page)
            return items, total_count, total_pages
        finally:
            self.close_connection(conn)

    def delete_scan(self, scan_id: str) -> bool:
        """Delete an individual scan entry."""
        query = "DELETE FROM scans WHERE id = ?"
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute(query, (scan_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            self.close_connection(conn)

    def clear_all_scans(self) -> int:
        """Clear all historical scans."""
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM scans")
            conn.commit()
            return cur.rowcount
        finally:
            self.close_connection(conn)

    def get_stats(self) -> dict:
        """Compute real telemetry stats across recorded scans."""
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM scans")
            total = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM scans WHERE is_phishing = 1")
            phish_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM scans WHERE is_phishing = 0")
            legit_count = cur.fetchone()[0]

            cur.execute("SELECT AVG(probability) FROM scans")
            avg_prob = cur.fetchone()[0] or 0.0

            cur.execute("SELECT risk_tier, COUNT(*) FROM scans GROUP BY risk_tier")
            risk_dist = {r[0]: r[1] for r in cur.fetchall()}

            return {
                "total_scans": total,
                "phishing_scans": phish_count,
                "legitimate_scans": legit_count,
                "avg_phishing_probability": round(float(avg_prob), 4),
                "risk_distribution": {
                    "low": risk_dist.get("low", 0),
                    "medium": risk_dist.get("medium", 0),
                    "high": risk_dist.get("high", 0),
                }
            }
        finally:
            self.close_connection(conn)

    def export_csv(self) -> str:
        """Export all scan records as CSV string."""
        conn = self.get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, redacted_url, domain, prediction, probability, risk_tier, created_at FROM scans ORDER BY created_at DESC")
            rows = cur.fetchall()

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Scan ID", "Redacted URL", "Domain", "Classification", "Phishing Probability", "Risk Tier", "Timestamp UTC"])
            for r in rows:
                writer.writerow([r["id"], r["redacted_url"], r["domain"], r["prediction"], r["probability"], r["risk_tier"], r["created_at"]])
            return output.getvalue()
        finally:
            self.close_connection(conn)

    def _row_to_dict(self, row) -> dict:
        """Serialize a database row into a structured dictionary."""
        d = dict(row)
        try:
            d["features"] = json.loads(d.get("features_json", "{}"))
        except Exception:
            d["features"] = {}
        try:
            d["contributing_factors"] = json.loads(d.get("contributing_factors_json", "[]"))
        except Exception:
            d["contributing_factors"] = []
        d.pop("features_json", None)
        d.pop("contributing_factors_json", None)
        return d
