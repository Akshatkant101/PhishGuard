from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class ScanRecord(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    verdict = Column(String(32), nullable=False, index=True)  # SAFE, SUSPICIOUS, PHISHING
    risk_score = Column(Float, nullable=False)                # 0 - 100
    lexical_risk_score = Column(Float, nullable=True)         # 0 - 100 (ML only)
    confidence = Column(Float, nullable=False)                # 0.0 - 1.0
    latency_ms = Column(Float, nullable=False)                # execution time
    reasons = Column(Text, nullable=False, default="[]")      # JSON array of SHAP reason objects
    enrichment_reasons = Column(Text, nullable=False, default="[]") # JSON array of rule adjustments
    enrichment = Column(Text, nullable=True, default="{}")    # JSON raw enrichment data
    features = Column(Text, nullable=False, default="{}")     # JSON extracted features
    model_version = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)

    def set_reasons(self, data: list):
        self.reasons = json.dumps(data)

    def get_reasons(self) -> list:
        try:
            return json.loads(self.reasons) if self.reasons else []
        except Exception:
            return []

    def set_enrichment_reasons(self, data: list):
        self.enrichment_reasons = json.dumps(data)

    def get_enrichment_reasons(self) -> list:
        try:
            return json.loads(self.enrichment_reasons) if self.enrichment_reasons else []
        except Exception:
            return []

    def set_enrichment(self, data: dict):
        self.enrichment = json.dumps(data)

    def get_enrichment(self) -> dict:
        try:
            return json.loads(self.enrichment) if self.enrichment else {}
        except Exception:
            return {}

    def set_features(self, data: dict):
        self.features = json.dumps(data)

    def get_features(self) -> dict:
        try:
            return json.loads(self.features) if self.features else {}
        except Exception:
            return {}


class BlocklistEntry(Base):
    __tablename__ = "blocklist"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    pattern = Column(String(512), nullable=False, unique=True, index=True)
    entry_type = Column(String(32), nullable=False, default="domain")  # domain or url
    reason = Column(String(512), nullable=True)
    added_by = Column(String(64), nullable=False, default="manual")     # manual or auto-block
    created_at = Column(DateTime, default=utcnow)


class AllowlistEntry(Base):
    __tablename__ = "allowlist"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    pattern = Column(String(512), nullable=False, unique=True, index=True)
    entry_type = Column(String(32), nullable=False, default="domain")  # domain or url
    reason = Column(String(512), nullable=True)
    added_by = Column(String(64), nullable=False, default="manual")
    created_at = Column(DateTime, default=utcnow)
