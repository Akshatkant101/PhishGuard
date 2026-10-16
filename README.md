# 🛡️ PhishGuard — Explainable AI Phishing Detection Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-5.0-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![XGBoost](https://img.shields.io/badge/Model-XGBoost%20%2B%20Platt%20Calibrated-orange)](https://xgboost.readthedocs.io/)
[![SHAP](https://img.shields.io/badge/Explainability-TreeSHAP-red)](https://shap.readthedocs.io/)
[![Tests](https://img.shields.io/badge/Tests-88%20Passed-brightgreen)](https://github.com/Akshatkant101/website-detection)

PhishGuard is a high-performance, two-stage phishing URL detection system designed to deliver real-time risk verdicts with mathematical explainability. By combining an invariant lexical ML engine (free from path-length dataset bias) with live infrastructure intelligence (TLS, DNS, RDAP, and content heuristics), PhishGuard provides sub-50ms automated detection without black-box opacity.

---

## 🌟 Key Architecture & Highlights

```
                          ┌─────────────────────────────────────┐
                          │          Incoming Page URL          │
                          └──────────────────┬──────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       ▼                                           ▼
         ┌───────────────────────────┐               ┌───────────────────────────┐
         │  Stage 1: Lexical ML Core │               │ Stage 2: Live Enrichment  │
         │  ──────────────────────── │               │ ───────────────────────── │
         │ • 24 Ratio Invariant Feat │               │ • TLS Cert Validity & Age │
         │ • Platt-Calibrated XGBoost│               │ • DNS Resolver & IP Check │
         │ • Laplace TLD Phish Rates │               │ • RDAP Domain Registration│
         │ • Zero Path-Length Bias   │               │ • Socket-Level SSRF Guard │
         └─────────────┬─────────────┘               └─────────────┬─────────────┘
                       │                                           │
                       └─────────────────────┬─────────────────────┘
                                             ▼
                              ┌─────────────────────────────┐
                              │    Explainability & Math    │
                              │  ─────────────────────────  │
                              │ • Local TreeSHAP Waterfall  │
                              │ • 6-Axis Threat Radar Graph │
                              │ • Final Risk Score (0-100)  │
                              └─────────────────────────────┘
```

### 1. Invariant Lexical ML (Zero Path-Length Bias)
- **Problem Solved:** Traditional phishing models overfit on path length because benchmark phishing feeds typically contain deep paths while legitimate sets skew heavily toward homepages.
- **Solution:** PhishGuard extracts **24 headline-ablated ratio-based features** (digit ratios, special character ratios, hyphen density, token entropy) that evaluate the URL structure without penalizing deep paths.
- **Learned TLD Smoothing:** Hand-curated suspicious TLD lists are replaced with continuous Laplace-smoothed per-TLD phishing rates ($\alpha = 5.0$) learned strictly from the training split, preventing hardcoded regional bias.
- **Probability Calibration:** XGBoost probabilities are calibrated via **Platt Scaling** (3-Fold CV) to ensure predicted probabilities correspond directly to empirical risk percentages.

### 2. Stage 2 Live Threat Intelligence & SSRF Firewall
- **TLS/SSL Certificate Analysis:** Live inspection of certificate chains, trusted CA status, and remaining validity.
- **Domain Age & RDAP:** Queries authoritative RDAP servers to detect newly registered domains (<30 days old).
- **DNS Resolution & Verification:** Validates IP addresses and cross-references them against loopback, link-local, and private RFC 1918 subnets.
- **Hardened Socket-Level SSRF Protection:** Pre-flight DNS resolution validates IP addresses *at the socket connect level* to eliminate TOCTOU (Time-of-Check to Time-of-Use) DNS rebinding and internal network scanning vulnerabilities.

### 3. TreeExplainer Local SHAP & 6-Axis Cyber Threat Radar
- Every scan delivers an instant mathematical attribution vector computed via **TreeSHAP**, ranking exact positive and negative contributors to the risk score.
- Dynamic **6-Axis Threat Radar** visually contextualizes risk across:
  - *Domain Trust*
  - *Brand Impersonation*
  - *Lexical Anomaly*
  - *Host Infrastructure*
  - *Certificate Security*
  - *Path / Query Complexity*

---

## 📊 Live Evaluation & Fresh Test Benchmarks

The model was retrained on a clean dataset of 50,859 verified URLs (with non-page static assets strictly filtered out) and evaluated on an untouched held-out benchmark (**Fresh Test v3: 177 real-world URLs** combining fresh OpenPhish feeds and mid-tier Tranco ranks 10k–500k):

| Metric | PRD Target | Offline Val (Grouped Domain) | Fresh Test $\ge 30$ | Fresh Test $\ge 60$ | Fresh Test $\ge 85$ |
|:---|:---:|:---:|:---:|:---:|:---:|
| **Precision** | $\ge 0.97$ | **0.9891** (PASS) | 0.6154 | 0.6977 | **0.7692** |
| **Recall** | $\ge 0.95$ | **0.9428** | **0.8205** | 0.7692 | 0.7692 |
| **FPR** | $\le 0.01$ | **0.0090** (PASS) | 0.1449 | 0.0942 | **0.0652** |
| **Precision @ 1% Base Rate** | — | — | 0.0541 | 0.0762 | **0.1065** |

> **Threshold Semantics:** Score $\ge$ Threshold counts as Predicted Phishing. Under real-world web traffic (1% phishing base rate), threshold $\ge 85$ delivers the lowest false-alarm operational burden.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.10+, FastAPI, Uvicorn, SQLAlchemy, Pydantic v2
- **Machine Learning:** XGBoost, Scikit-Learn, SHAP, NumPy, Pandas, Joblib
- **Frontend:** React 18, Vite, Lucide Icons, Vanilla Modular CSS
- **Database:** SQLite (persisted locally with indexed scan history)
- **Testing:** Pytest, AsyncIO, Pytest-Mock (88 unit and integration tests)

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** & npm

### 1. Clone the Repository
```bash
git clone https://github.com/Akshatkant101/website-detection.git
cd website-detection
```

### 2. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp ../.env.example .env

# Run FastAPI server (port 8000)
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be live at: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Frontend Setup
```bash
# In a new terminal, navigate to frontend
cd frontend

# Install dependencies
npm install

# Start Vite development server (port 5173)
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🧪 Running the Test Suite

PhishGuard includes an automated test suite with 88 tests covering API routers, feature extraction, SHAP attribution, SSRF firewalling, and ML calibration:

```bash
cd backend
pytest -v
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|:---|:---|:---|
| `POST` | `/api/v1/scan` | Analyzes a single URL; returns risk score, verdict, SHAP reasons, and enrichment signals. |
| `POST` | `/api/v1/scan/batch` | Batch analyzes up to 50 URLs concurrently. |
| `GET` | `/api/v1/history` | Fetches historical scan logs with search and verdict filtering. |
| `GET` | `/api/v1/model/info` | Returns active model metadata, feature weights, and calibration parameters. |
| `GET` | `/api/v1/health` | Healthcheck and active system version. |

### Sample Scan Request
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scan" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://paypal-security-update.account-verification.xyz/login.php"}'
```

### Sample Response
```json
{
  "url": "https://paypal-security-update.account-verification.xyz/login.php",
  "domain": "account-verification.xyz",
  "verdict": "phishing",
  "risk_score": 88.5,
  "confidence": 0.96,
  "latency_ms": 38,
  "reasons": [
    {
      "feature": "brand_in_subdomain",
      "impact": 18.2,
      "direction": "suspicious",
      "description": "Brand keyword 'paypal' found in subdomain"
    },
    {
      "feature": "suspicious_tld",
      "impact": 12.4,
      "direction": "suspicious",
      "description": "High-risk TLD (.xyz) with elevated phishing prevalence"
    }
  ]
}
```

---

## 🔬 Retraining the Model

To retrain the Calibrated XGBoost model on the augmented dataset:
```bash
cd backend
python ml/train.py
```
To run the complete scope-fix pipeline (static-asset filter, midtier validation, and benchmark evaluation):
```bash
cd backend
python ml/run_scope_fix_pipeline.py
```

---

## 🛡️ Security & Privacy Notice
PhishGuard does not execute JavaScript or render untrusted DOM code in a headless browser during scanning. All HTTP requests for Stage 2 enrichment enforce strict timeouts and socket-level IP binding to prevent SSRF against internal services.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
