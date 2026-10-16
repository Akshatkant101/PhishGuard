from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.config import settings
from app.database import get_db
from app.services.ml_model import ml_service
from app.schemas.schemas import HealthResponse, ModelInfoResponse

router = APIRouter(tags=["Health & Model"])


@router.get("/health", response_model=HealthResponse)
def get_health(db: Session = Depends(get_db)):
    db_ok = False
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    return HealthResponse(
        status="ok" if (db_ok and ml_service.is_loaded) else "degraded",
        version=settings.APP_VERSION,
        model_loaded=ml_service.is_loaded,
        database_connected=db_ok,
    )


@router.get("/model", response_model=ModelInfoResponse)
def get_model_info():
    meta = ml_service.metadata
    return ModelInfoResponse(
        model_version=meta.get("model_version"),
        model_type=meta.get("model_type"),
        training_date=meta.get("training_date"),
        feature_count=meta.get("feature_count"),
        optimal_threshold=meta.get("optimal_threshold"),
        metrics=meta.get("evaluation") or meta.get("best_model_metrics"),
    )
