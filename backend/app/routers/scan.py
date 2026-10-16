import time
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.db_models import ScanRecord
from app.schemas.schemas import ScanRequest, ScanResponse, BatchScanRequest, BatchScanResponse, ReasonItem
from app.services.scan_service import scan_service

router = APIRouter(prefix="/scan", tags=["Scanning"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_200_OK)
def scan_url_endpoint(req: ScanRequest, db: Session = Depends(get_db)):
    """Analyze a single URL for phishing indicators, returning risk score, verdict, and explanations."""
    try:
        return scan_service.scan_url(db, req.url)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing URL: {str(e)}",
        )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve full details of a previously performed scan."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan record not found")

    reasons_data = record.get_reasons()
    reasons = [ReasonItem(**r) for r in reasons_data]

    return ScanResponse(
        id=record.id,
        url=record.url,
        domain=record.domain,
        verdict=record.verdict,
        risk_score=record.risk_score,
        confidence=record.confidence,
        latency_ms=record.latency_ms,
        reasons=reasons,
        features=record.get_features(),
        model_version=record.model_version,
        created_at=record.created_at,
    )


@router.post("/batch", response_model=BatchScanResponse)
def scan_batch_endpoint(req: BatchScanRequest, db: Session = Depends(get_db)):
    """Analyze multiple URLs (up to 50) sequentially or in batch."""
    start_time = time.perf_counter()
    results = []
    for raw_url in req.urls:
        try:
            res = scan_service.scan_url(db, raw_url)
            results.append(res)
        except Exception as e:
            # Continue on error for other items
            continue

    total_time = round((time.perf_counter() - start_time) * 1000, 2)
    return BatchScanResponse(
        results=results,
        total=len(results),
        processing_time_ms=total_time,
    )
