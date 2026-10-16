import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.db_models import ScanRecord, BlocklistEntry, AllowlistEntry

# In-memory SQLite DB for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    return TestClient(app)


# ── Health & Model Info Tests ──

def test_health_endpoint(client):
    response = client.get("/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("ok", "degraded")
    assert "version" in data
    assert data["database_connected"] is True


def test_model_info_endpoint(client):
    response = client.get("/v1/model")
    assert response.status_code == 200
    data = response.json()
    assert "model_version" in data
    assert "feature_count" in data


# ── Scan Tests ──

def test_scan_legitimate_url(client):
    payload = {"url": "https://www.google.com/search?q=cybersecurity"}
    response = client.post("/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ("SAFE", "SUSPICIOUS")
    assert 0.0 <= data["risk_score"] <= 100.0
    assert 0.0 <= data["confidence"] <= 1.0
    assert data["latency_ms"] > 0
    assert isinstance(data["reasons"], list)
    assert len(data["reasons"]) > 0
    assert "google.com" in data["domain"]


def test_scan_phishing_url(client):
    payload = {"url": "http://paypal-security-update.account-verification.xyz/login.php"}
    response = client.post("/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "PHISHING"
    assert data["risk_score"] >= 70.0
    assert len(data["reasons"]) > 0
    # Check that reasons explain suspicious traits
    reasons_features = [r["feature"] for r in data["reasons"]]
    assert any(f in reasons_features for f in ("brand_impersonation", "suspicious_tld", "path_has_suspicious_ext", "is_https"))


def test_scan_retrieval_by_id(client):
    # Scan a URL first
    res = client.post("/v1/scan", json={"url": "https://wikipedia.org"})
    scan_id = res.json()["id"]

    # Fetch by ID
    get_res = client.get(f"/v1/scan/{scan_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id
    assert "wikipedia.org" in get_res.json()["url"]


def test_scan_batch(client):
    urls = [
        "https://www.github.com",
        "https://www.python.org",
        "http://secure-update-verify-account.tk/login.exe",
    ]
    response = client.post("/v1/scan/batch", json={"urls": urls})
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 3
    assert len(data["results"]) == 3
    assert data["processing_time_ms"] > 0


# ── Allowlist & Blocklist Policy Tests ──

def test_allowlist_crud_and_override(client):
    # Add to allowlist
    add_res = client.post("/v1/allowlist", json={"pattern": "internal-corp.net", "reason": "Trusted intranet"})
    assert add_res.status_code == 201
    entry_id = add_res.json()["id"]

    # Duplicate check
    dup_res = client.post("/v1/allowlist", json={"pattern": "internal-corp.net"})
    assert dup_res.status_code == 409

    # List allowlist
    list_res = client.get("/v1/allowlist")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # Scan URL matching allowlist
    scan_res = client.post("/v1/scan", json={"url": "http://internal-corp.net/secret/login"})
    assert scan_res.status_code == 200
    assert scan_res.json()["verdict"] == "SAFE"
    assert scan_res.json()["risk_score"] == 0.0

    # Delete allowlist entry
    del_res = client.delete(f"/v1/allowlist/{entry_id}")
    assert del_res.status_code == 204


def test_blocklist_crud_and_override(client):
    # Add to blocklist
    add_res = client.post("/v1/blocklist", json={"pattern": "malicious-phish.biz", "reason": "Known campaign"})
    assert add_res.status_code == 201
    entry_id = add_res.json()["id"]

    # Duplicate check
    dup_res = client.post("/v1/blocklist", json={"pattern": "malicious-phish.biz"})
    assert dup_res.status_code == 409

    # List blocklist
    list_res = client.get("/v1/blocklist")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # Scan URL matching blocklist
    scan_res = client.post("/v1/scan", json={"url": "https://malicious-phish.biz/verify"})
    assert scan_res.status_code == 200
    assert scan_res.json()["verdict"] == "PHISHING"
    assert scan_res.json()["risk_score"] == 100.0

    # Delete blocklist entry
    del_res = client.delete(f"/v1/blocklist/{entry_id}")
    assert del_res.status_code == 204


# ── History Tests ──

def test_history_and_csv_export(client):
    # Perform two scans
    client.post("/v1/scan", json={"url": "https://trusted-site.org"})
    client.post("/v1/scan", json={"url": "http://fake-banking-login.top"})

    # Get history
    hist_res = client.get("/v1/history?limit=10")
    assert hist_res.status_code == 200
    items = hist_res.json()
    assert len(items) >= 2

    # Filter history by search
    search_res = client.get("/v1/history?search=fake-banking")
    assert search_res.status_code == 200
    assert len(search_res.json()) == 1

    # Export CSV
    csv_res = client.get("/v1/history/export")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "fake-banking-login.top" in csv_res.text
