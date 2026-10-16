import csv
import io
from typing import Optional, List
from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.db_models import ScanRecord
from app.schemas.schemas import ScanResponse, ReasonItem

router = APIRouter(prefix="/history", tags=["Scan History"])


@router.get("", response_model=List[ScanResponse])
def get_history(
    search: Optional[str] = Query(None, description="Search domain or URL"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: SAFE, SUSPICIOUS, PHISHING"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Retrieve scan history with optional search, verdict filtering, and pagination."""
    query = db.query(ScanRecord)

    if search:
        s = f"%{search.strip().lower()}%"
        query = query.filter((ScanRecord.url.ilike(s)) | (ScanRecord.domain.ilike(s)))

    if verdict:
        query = query.filter(ScanRecord.verdict == verdict.upper())

    query = query.order_by(desc(ScanRecord.created_at))
    records = query.offset(offset).limit(limit).all()

    results = []
    from app.schemas.schemas import EnrichmentReason
    for r in records:
        reasons_data = r.get_reasons()
        reasons = [ReasonItem(**x) for x in reasons_data] if reasons_data else []
        enrich_data = r.get_enrichment_reasons()
        enrichment_reasons = [EnrichmentReason(**x) for x in enrich_data] if enrich_data else []
        results.append(
            ScanResponse(
                id=r.id,
                url=r.url,
                domain=r.domain,
                verdict=r.verdict,
                risk_score=r.risk_score,
                lexical_risk_score=getattr(r, "lexical_risk_score", r.risk_score),
                confidence=r.confidence,
                latency_ms=r.latency_ms,
                reasons=reasons,
                enrichment_reasons=enrichment_reasons,
                enrichment=r.get_enrichment() if hasattr(r, "get_enrichment") else None,
                features=r.get_features(),
                model_version=r.model_version,
                created_at=r.created_at,
            )
        )
    return results


@router.get("/export")
def export_history_csv(
    verdict: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Export scan history as downloadable CSV."""
    query = db.query(ScanRecord)
    if verdict:
        query = query.filter(ScanRecord.verdict == verdict.upper())
    records = query.order_by(desc(ScanRecord.created_at)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "URL", "Domain", "Verdict", "Risk Score", "Confidence", "Latency (ms)", "Timestamp"
    ])

    for r in records:
        writer.writerow([
            r.id,
            r.url,
            r.domain,
            r.verdict,
            r.risk_score,
            r.confidence,
            r.latency_ms,
            r.created_at.isoformat() if r.created_at else "",
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_scan_history.csv"},
    )
