import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class BaseConfig:
    """Base application configuration."""

    SECRET_KEY = os.getenv("SECRET_KEY", "urlshield-dev-secret-key-change-in-prod-7f91a")
    DEBUG = False
    TESTING = False

    # Maximum request size (16 KB) to reject excessive inputs
    MAX_CONTENT_LENGTH = 16 * 1024

    # Database configuration (SQLite local, PostgreSQL deployable)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'urlshield.db'}"
    )

    # Scans retention / storage
    MAX_URL_LENGTH = 2048
    MIN_URL_LENGTH = 3

    # Security & Rate Limiting
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "60 per minute")
    RATELIMIT_SCAN = os.getenv("RATELIMIT_SCAN", "20 per minute")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    CORS_ALLOWED_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",")

    # Model & Feature artifacts
    MODEL_PATH = os.getenv("MODEL_PATH", str(BASE_DIR / "models" / "phishing_model.joblib"))
    METADATA_PATH = os.getenv("METADATA_PATH", str(BASE_DIR / "models" / "model_metadata.json"))
    SCHEMA_PATH = os.getenv("SCHEMA_PATH", str(BASE_DIR / "models" / "feature_schema.json"))

    # Security rule: strictly disabled by default to prevent SSRF and network probing
    ENABLE_OPTIONAL_DNS_LOOKUPS = os.getenv("ENABLE_OPTIONAL_DNS_LOOKUPS", "false").lower() == "true"
    DNS_TIMEOUT_SECONDS = float(os.getenv("DNS_TIMEOUT_SECONDS", "1.5"))

    # Demo Mode flag
    DEMO_MODE_ENABLED = True


class DevelopmentConfig(BaseConfig):
    """Local development configuration."""

    DEBUG = True
    ENV = "development"


class TestingConfig(BaseConfig):
    """Testing configuration."""

    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    RATELIMIT_DEFAULT = "1000 per minute"
    RATELIMIT_SCAN = "1000 per minute"


class ProductionConfig(BaseConfig):
    """Production deployment configuration."""

    DEBUG = False
    ENV = "production"
    # Ensure SECRET_KEY is set in production
    SECRET_KEY = os.getenv("SECRET_KEY", "urlshield-prod-secret-must-be-provided")


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(env_name: str | None = None) -> type[BaseConfig]:
    """Resolve config class from environment name."""
    env = env_name or os.getenv("FLASK_ENV", "development").lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
