from app.routers.health import router as health_router
from app.routers.scan import router as scan_router
from app.routers.history import router as history_router
from app.routers.blocklist import router as blocklist_router
from app.routers.allowlist import router as allowlist_router

__all__ = [
    "health_router",
    "scan_router",
    "history_router",
    "blocklist_router",
    "allowlist_router",
]
