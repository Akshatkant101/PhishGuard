from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, HttpUrl, field_validator, ConfigDict


# ── Scan Schemas ──

class ScanRequest(BaseModel):
    url: str = Field(..., description="URL to analyze for phishing threats", min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        # Ensure it has a scheme or can be prefixed
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        return v


class ReasonItem(BaseModel):
    feature: str
    description: str
    value: float
    impact: float
    direction: str  # "suspicious" | "benign"


class EnrichmentReason(BaseModel):
    signal: str
    points: float
    description: str
    direction: str  # "suspicious" | "benign"


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    url: str
    domain: str
    verdict: str  # "SAFE" | "SUSPICIOUS" | "PHISHING"
    risk_score: float = Field(..., ge=0.0, le=100.0)
    lexical_risk_score: Optional[float] = None
    confidence: float = Field(..., ge=0.0, le=1.0)
    latency_ms: float
    reasons: List[ReasonItem] = []                    # SHAP ML Feature Attributions Only
    enrichment_reasons: List[EnrichmentReason] = []     # Stage 2 Documented Rule Adjustments
    features: Optional[Dict[str, float]] = None
    enrichment: Optional[Dict[str, Any]] = None
    model_version: Optional[str] = None
    created_at: Optional[datetime] = None


class BatchScanRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=50)


class BatchScanResponse(BaseModel):
    results: List[ScanResponse]
    total: int
    processing_time_ms: float


# ── List / Filter Schemas ──

class ListEntryCreate(BaseModel):
    pattern: str = Field(..., min_length=1, max_length=512, description="Domain or full URL")
    entry_type: str = Field(default="domain", description="'domain' or 'url'")
    reason: Optional[str] = Field(default=None, max_length=512)

    @field_validator("entry_type")
    @classmethod
    def validate_entry_type(cls, v: str) -> str:
        v = v.lower()
        if v not in ("domain", "url"):
            raise ValueError("entry_type must be 'domain' or 'url'")
        return v


class ListEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    pattern: str
    entry_type: str
    reason: Optional[str] = None
    added_by: str
    created_at: datetime


# ── Health & Model Metadata Schemas ──

class HealthResponse(BaseModel):
    status: str
    version: str
    model_loaded: bool
    database_connected: bool


class ModelInfoResponse(BaseModel):
    model_version: Optional[str]
    model_type: Optional[str]
    training_date: Optional[str]
    feature_count: Optional[int]
    optimal_threshold: Optional[float]
    metrics: Optional[Dict[str, Any]]
