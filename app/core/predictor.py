import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np

from app.core.feature_extractor import (
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS,
    extract_features_from_url,
    features_to_vector,
)
from app.core.validator import normalize_url, redact_sensitive_url

logger = logging.getLogger("predictor")


class PredictorError(Exception):
    """Raised when prediction pipeline encounters an unrecoverable state."""
    pass


class URLPredictor:
    """Production ML inference engine for URLShield."""

    _instance = None

    def __init__(
        self,
        model_path: str | Path | None = None,
        metadata_path: str | Path | None = None,
        schema_path: str | Path | None = None,
    ):
        base_dir = Path(__file__).resolve().parent.parent.parent
        self.model_path = Path(model_path or (base_dir / "models" / "phishing_model.joblib"))
        self.metadata_path = Path(metadata_path or (base_dir / "models" / "model_metadata.json"))
        self.schema_path = Path(schema_path or (base_dir / "models" / "feature_schema.json"))

        self.model = None
        self.metadata = {}
        self.schema = {}
        self.load_artifacts()

    def load_artifacts(self):
        """Load joblib model pipeline and JSON metadata."""
        if not self.model_path.exists():
            logger.warning("Model file not found at %s. Predictor in fallback mode.", self.model_path)
            return

        try:
            self.model = joblib.load(self.model_path)
            logger.info("Loaded model pipeline from %s", self.model_path)
        except Exception as e:
            logger.error("Failed to load model pipeline: %s", e)

        if self.metadata_path.exists():
            try:
                with open(self.metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            except Exception as e:
                logger.warning("Could not read metadata: %s", e)

        if self.schema_path.exists():
            try:
                with open(self.schema_path, "r", encoding="utf-8") as f:
                    self.schema = json.load(f)
            except Exception as e:
                logger.warning("Could not read schema: %s", e)

    def explain_features(self, features: dict[str, float | int], raw_url: str) -> list[dict[str, str]]:
        """
        Produce clear, human-understandable explanations of features
        contributing to risk or safety assessment.
        """
        explanations = []

        # IP host check
        if features.get("is_ip_host", 0) == 1:
            explanations.append({
                "factor": "IP Address Hostname",
                "severity": "danger",
                "description": "Host uses a raw numeric IP address instead of a recognized domain name, a classic evasion tactic.",
            })

        # Suspicious keywords
        kw_count = int(features.get("num_suspicious_keywords", 0))
        if kw_count > 0:
            found_kws = [k for k in SUSPICIOUS_KEYWORDS if k in raw_url.lower()]
            explanations.append({
                "factor": f"Suspicious Keywords ({kw_count})",
                "severity": "warning" if kw_count == 1 else "danger",
                "description": f"URL contains credential or finance keywords: {', '.join(found_kws[:4])}.",
            })

        # HTTPS vs HTTP
        if features.get("is_https", 0) == 0:
            explanations.append({
                "factor": "Insecure Scheme (HTTP)",
                "severity": "warning",
                "description": "Connection is unencrypted (HTTP) rather than HTTPS.",
            })

        # Punycode
        if features.get("has_punycode", 0) == 1:
            explanations.append({
                "factor": "Punycode (IDN Homograph)",
                "severity": "danger",
                "description": "Hostname uses Punycode (xn--) which may spoof popular brands using lookalike characters.",
            })

        # Subdomains
        subdomains = int(features.get("num_subdomains", 0))
        if subdomains >= 3:
            explanations.append({
                "factor": f"Deep Subdomain Nesting ({subdomains})",
                "severity": "warning",
                "description": "Multiple subdomains often disguise the true destination authority.",
            })

        # Entropy
        url_ent = float(features.get("url_entropy", 0.0))
        if url_ent > 4.5:
            explanations.append({
                "factor": f"High Character Entropy ({url_ent})",
                "severity": "warning",
                "description": "High randomness in URL characters commonly correlates with algorithmic generation or hex tokens.",
            })

        # URL length
        url_len = int(features.get("url_length", 0))
        if url_len > 90:
            explanations.append({
                "factor": f"Extended URL Length ({url_len} chars)",
                "severity": "warning",
                "description": "Extremely long URLs frequently obfuscate targeted paths and affiliate parameters.",
            })

        # Positive indicators if no critical danger
        if not explanations:
            explanations.append({
                "factor": "Standard Domain & Path",
                "severity": "safe",
                "description": "No IP hostnames, homographs, abnormal entropy, or known evasion keywords detected.",
            })

        return explanations

    def predict(self, raw_url: str) -> dict:
        """
        End-to-end safe prediction:
        1. Normalizes and validates URL safely.
        2. Extracts 22 engineered features.
        3. Generates calibrated probabilities and risk category.
        4. Produces transparent feature explanations and metadata.
        """
        normalized = normalize_url(raw_url)
        redacted = redact_sensitive_url(normalized)
        features = extract_features_from_url(normalized)
        vector = features_to_vector(features)

        if self.model is None:
            raise PredictorError("ML pipeline model is not initialized or trained.")

        X = np.array([vector], dtype=float)
        probas = self.model.predict_proba(X)[0]
        # probas[0] = legit, probas[1] = phishing
        phishing_prob = float(probas[1])
        legit_prob = float(probas[0])

        # Measured Risk Thresholds (Standard calibrated decision boundary 0.50)
        thresholds = self.metadata.get("risk_thresholds", {
            "safe": {"min": 0.0, "max": 0.45, "label": "Low Risk (Legitimate)"},
            "suspicious": {"min": 0.45, "max": 0.75, "label": "Medium Risk (Suspicious)"},
            "phishing": {"min": 0.75, "max": 1.0, "label": "High Risk (Phishing)"},
        })

        is_phishing = phishing_prob >= 0.50

        if phishing_prob < thresholds["safe"]["max"]:
            risk_tier = "low"
            risk_label = "Safe / Low Risk"
            risk_color = "emerald"
        elif phishing_prob < thresholds["suspicious"]["max"]:
            risk_tier = "medium"
            risk_label = "Suspicious / Medium Risk"
            risk_color = "amber"
        else:
            risk_tier = "high"
            risk_label = "Dangerous / High Risk"
            risk_color = "rose"

        explanations = self.explain_features(features, normalized)

        return {
            "input_url": raw_url,
            "normalized_url": normalized,
            "redacted_url": redacted,
            "is_phishing": is_phishing,
            "prediction": "phishing" if is_phishing else "legitimate",
            "probability": round(phishing_prob, 4),
            "phishing_percentage": round(phishing_prob * 100, 1),
            "legitimate_percentage": round(legit_prob * 100, 1),
            "confidence": round(max(phishing_prob, legit_prob), 4),
            "risk_tier": risk_tier,
            "risk_label": risk_label,
            "risk_color": risk_color,
            "features": features,
            "contributing_factors": explanations,
            "model_version": self.metadata.get("model_version", "1.0.0"),
            "model_algorithm": self.metadata.get("chosen_algorithm", "RandomForest"),
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "disclaimer": "Probabilistic assessment based on lexical/structural features. Not a guarantee. Do not interact with unverified links.",
        }


# Singleton getter
_global_predictor = None

def get_predictor() -> URLPredictor:
    global _global_predictor
    if _global_predictor is None:
        _global_predictor = URLPredictor()
    return _global_predictor
