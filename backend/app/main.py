from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.config import settings
from app.database import engine, Base
from app.models import db_models  # ensure models are registered
from app.routers import (
    health_router,
    scan_router,
    history_router,
    blocklist_router,
    allowlist_router,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB schema
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    logger.info("PhishGuard API started successfully.")
    yield
    logger.info("PhishGuard API shutting down.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Explainable Phishing URL Detection API with SHAP reasons, risk scoring, and policy management.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 routers
app.include_router(health_router, prefix="/v1")
app.include_router(scan_router, prefix="/v1")
app.include_router(history_router, prefix="/v1")
app.include_router(blocklist_router, prefix="/v1")
app.include_router(allowlist_router, prefix="/v1")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
