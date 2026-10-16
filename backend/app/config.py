from pathlib import Path
from typing import Optional, List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./phishguard.db"

    # ML Model directory
    MODEL_DIR: str = str(Path(__file__).resolve().parent.parent / "ml" / "models")

    # Risk thresholds aligned to PRD: 30 / 60 / 85
    # 0 - 29.9: Safe (Low risk)
    # 30.0 - 59.9: Suspicious (Medium risk)
    # 60.0 - 84.9: Likely Phishing (High risk)
    # 85.0 - 100.0: Phishing (Critical risk, triggers auto-block)
    THRESHOLD_SAFE: float = 30.0
    THRESHOLD_SUSPICIOUS: float = 60.0
    AUTO_BLOCK_THRESHOLD: float = 85.0

    # Threat Intel API Keys (Optional)
    GOOGLE_SAFE_BROWSING_KEY: Optional[str] = None
    PHISHTANK_API_KEY: Optional[str] = None

    # Live Enrichment Network Settings
    ENRICHMENT_TIMEOUT_SECONDS: float = 2.0
    ENRICHMENT_MAX_CONTENT_BYTES: int = 200000  # 200 KB max for page inspection

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173", "*"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
