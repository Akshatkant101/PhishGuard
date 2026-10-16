# PhishGuard: ML-Based Phishing Website Detection & Blocking Platform

**Product Requirements Document (PRD)** | Version 1.0 | Owner: Akshat | Status: Draft

---

## 1. Overview

PhishGuard is a web platform that takes a URL, analyses it with a trained machine learning model plus live threat signals, and returns a **verdict (Legitimate / Suspicious / Phishing)**, a **0-100 risk score**, and a **human-readable explanation** of why. High-risk URLs can be **blocked** through a managed blocklist, a REST API, and a browser extension.

The project goes beyond a notebook-level classifier. It is a complete system: data pipeline, model training and evaluation, explainable inference service, dashboard, and enforcement layer.

## 2. Problem Statement

Phishing is the most common entry point for credential theft and fraud. Users cannot reliably judge a link by eye, and static blocklists lag behind new phishing sites, many of which live for only hours. A system that scores unseen URLs in real time and explains its decision helps users and analysts act before damage occurs.

## 3. Goals and Non-Goals

**Goals**

- G1. Classify a URL as legitimate or phishing with high precision and recall on a held-out test set.
- G2. Return a calibrated risk score and the top reasons behind it (explainability).
- G3. Provide a dashboard for submitting URLs, bulk scans, history, and analytics.
- G4. Enforce decisions: block high-risk URLs via blocklist, API, and browser extension.
- G5. Follow production practices: versioned models, tests, CI, containerised deployment, documented API.

**Non-Goals (v1)**

- Email phishing detection, SMS/QR phishing, mobile app.
- Network-wide or DNS-level blocking at ISP scale.
- Deep-learning page-screenshot models (listed as future scope).

## 4. Users and Personas

| Persona | Need | Key feature |
| --- | --- | --- |
| End user | Quick check before clicking or entering credentials | URL check, risk score, plain-language reasons, extension warning page |
| Security analyst | Triage many suspicious links | Bulk scan, history, filters, override and blocklist management |
| Admin / Org owner | Control policy | Thresholds, allowlist/blocklist, audit log, API keys |

## 5. Scope and Feature Summary

| ID | Requirement | Priority |
| --- | --- | --- |
| F1 | Submit single URL for scan (dashboard + API) | P0 |
| F2 | Verdict + risk score (0-100) + confidence | P0 |
| F3 | Explanation: top contributing features (SHAP), shown as readable reasons | P0 |
| F4 | Scan history with search, filters, export (CSV) | P0 |
| F5 | Blocklist/allowlist management; auto-block above threshold | P0 |
| F6 | Bulk scan via CSV upload with background processing | P1 |
| F7 | Browser extension (Chrome MV3) that checks navigations and shows warning interstitial | P1 |
| F8 | Analytics dashboard: scans over time, verdict split, top risky domains, model stats | P1 |
| F9 | Threat-intel enrichment (PhishTank/OpenPhish lookup, Google Safe Browsing optional) | P1 |
| F10 | User auth, API keys, rate limiting, audit log | P1 |
| F11 | User feedback ("report false positive / missed phish") feeding retraining | P2 |
| F12 | Model versioning, drift monitoring, scheduled retraining | P2 |

## 6. Detailed Functional Requirements

### 6.1 URL Scan Flow

1. User submits URL. System validates and normalises it (scheme, punycode/IDN handling, lowercase host, strip fragments).
2. Checks run in order: allowlist/blocklist hit, cache hit, threat-intel lookup, then ML inference.
3. Feature extraction runs (Section 7.2). Page fetch is optional and sandboxed with timeouts.
4. Model returns phishing probability; the system maps it to a risk score and verdict.
5. Explainer returns top 5 contributing features as human-readable reasons.
6. Result is stored, returned, and if score ≥ block threshold, the URL is added to the blocklist.

### 6.2 Risk Score and Verdict

Risk score = calibrated phishing probability × 100, optionally raised by threat-intel hits.

| Score | Verdict | Default action |
| --- | --- | --- |
| 0-29 | Legitimate (Low risk) | Allow |
| 30-59 | Suspicious (Medium) | Warn user |
| 60-84 | Likely phishing (High) | Warn with interstitial, recommend block |
| 85-100 | Phishing (Critical) | Auto-block |

Thresholds are configurable by admins and tuned from the precision-recall curve, not guessed.

### 6.3 Explainability

Each result shows the top contributing signals with direction and plain language, for example:

- "Domain registered 3 days ago" (+ risk)
- "URL contains '@' and 4 subdomains" (+ risk)
- "Valid HTTPS certificate from long-standing issuer" (- risk)
- "Brand name 'paypal' appears in subdomain, not the registered domain" (+ risk)

Implementation: SHAP values from the tree model mapped through a feature-to-sentence dictionary.

### 6.4 Blocking and Enforcement

A web page cannot block traffic browser-wide, so enforcement is layered:

- **Blocklist service:** database-backed list with source, reason, timestamp, and TTL.
- **Public API:** `POST /v1/scan` and `GET /v1/blocklist` so other tools can consume verdicts.
- **Browser extension (Manifest V3):** intercepts navigation, calls the API, and redirects blocked URLs to a PhishGuard warning page with "Go back" and "Proceed anyway (logged)".
- **Export:** blocklist downloadable as plain text/hosts format for DNS sinkholes like Pi-hole.

### 6.5 Dashboard Screens

1. **Scan:** URL input, result card (verdict badge, risk gauge, reasons, extracted features, WHOIS/TLS details).
2. **History:** table with filters (verdict, date, domain), export.
3. **Bulk scan:** CSV upload, progress bar, downloadable results.
4. **Blocklist/Allowlist:** add/remove, source tags, expiry.
5. **Analytics:** scans per day, verdict distribution, top targeted brands, model metrics.
6. **Settings:** thresholds, API keys, model version.

## 7. Machine Learning Design

### 7.1 Data

| Source | Use |
| --- | --- |
| PhishTank, OpenPhish | Verified phishing URLs (positive class) |
| Tranco top-sites list | Legitimate URLs (negative class) |
| PhiUSIIL / UCI Phishing datasets | Benchmark and feature reference |

Practices: de-duplicate, remove dead links, **split by time or by domain to prevent leakage** (same domain must not appear in both train and test), keep a realistic class ratio for evaluation (phishing is rare in real traffic), and document data provenance.

### 7.2 Feature Groups

- **Lexical (URL string):** length, dot/hyphen/digit counts, special characters, entropy, presence of IP address, '@', suspicious TLD, number of subdomains, brand keywords, punycode.
- **Host-based:** domain age, registrar, DNS records, resolved IP, ASN (WHOIS/DNS lookups).
- **TLS:** certificate age, issuer, validity length, mismatch with domain.
- **Content-based (optional, sandboxed fetch):** form with password field, external form action, favicon mismatch, iframe use, ratio of external links, hidden elements.
- **Reputation:** presence in threat feeds, Tranco rank.

### 7.3 Models and Experiments

| Stage | Models |
| --- | --- |
| Baseline | Logistic Regression, Naive Bayes |
| Main | Random Forest, XGBoost / LightGBM |
| Stretch | Character-level CNN or small transformer on raw URL, ensembled with the tree model |

Compare all models in one table. Use stratified k-fold cross-validation, hyperparameter search (Optuna or GridSearch), probability calibration (Platt or isotonic), and track experiments with MLflow or a simple versioned results log.

### 7.4 Evaluation

| Metric | Target |
| --- | --- |
| Precision (phishing) | ≥ 0.97 |
| Recall (phishing) | ≥ 0.95 |
| F1 | ≥ 0.96 |
| False positive rate | ≤ 1% |
| ROC-AUC / PR-AUC | Reported with curves |
| P95 inference latency (excluding network lookups) | < 200 ms |

Also report confusion matrix, performance on a **time-based holdout** (newer phishing than training), and an error analysis of false positives and negatives. A false positive on a legitimate site is costlier for a blocker than a missed low-risk URL, so thresholds are chosen to keep FPR low.

## 8. System Architecture

```
Browser Extension / Dashboard (React)
            |
       API Gateway (FastAPI)  --  Auth, rate limit
            |
   +--------+---------+------------------+
   |        |         |                  |
Scan Service  Blocklist Service  Threat-Intel Client
   |
Feature Extractor --> ML Inference (XGBoost + SHAP)
   |
Redis (cache, queue)    PostgreSQL (scans, lists, users, audit)
   |
Worker (Celery/RQ): bulk scans, page fetch, retraining jobs
```

## 9. Tech Stack

| Layer | Choice | Reason |
| --- | --- | --- |
| Backend + ML | **Python, FastAPI** | One language for ML and API; async; auto-generated OpenAPI docs |
| ML | scikit-learn, XGBoost/LightGBM, SHAP, pandas | Standard, explainable |
| Frontend | React (or Next.js) + Tailwind + Recharts | Fast dashboard build |
| Database | PostgreSQL | Relational history, audit trail |
| Cache/Queue | Redis + Celery or RQ | Caching and background jobs |
| Extension | Chrome Manifest V3 | Enforcement at browser level |
| DevOps | Docker, docker-compose, GitHub Actions | Reproducible runs, CI |
| Testing | pytest, Playwright (optional) | Quality gates |

Node is a viable alternative for the API, but Python avoids a cross-language bridge to the model, so it is recommended.

## 10. API Specification (v1)

| Endpoint | Description |
| --- | --- |
| `POST /v1/scan` | Body `{url}`. Returns `{verdict, risk_score, confidence, reasons[], features, model_version, scan_id}` |
| `POST /v1/scan/bulk` | Upload list or CSV, returns `job_id` |
| `GET /v1/scan/{id}` | Fetch stored result |
| `GET /v1/history` | Paginated, filterable |
| `GET/POST/DELETE /v1/blocklist` | Manage blocklist |
| `GET/POST/DELETE /v1/allowlist` | Manage allowlist |
| `POST /v1/feedback` | Mark scan as false positive / false negative |
| `GET /v1/health`, `GET /v1/model` | Health and model metadata |

All endpoints authenticated via API key or JWT, rate limited, and documented via OpenAPI/Swagger.

## 11. Data Model (core tables)

- `users(id, email, password_hash, role, created_at)`
- `scans(id, url, normalized_url, domain, verdict, risk_score, confidence, reasons_json, features_json, model_version, created_by, created_at)`
- `blocklist(id, url_or_domain, reason, source, scan_id, expires_at, created_at)`
- `allowlist(id, domain, added_by, created_at)`
- `feedback(id, scan_id, label, comment, created_at)`
- `audit_log(id, actor, action, target, created_at)`
- `models(version, metrics_json, trained_at, active)`

## 12. Non-Functional Requirements

- **Performance:** cached scan < 100 ms; fresh scan with lookups < 3 s at P95.
- **Availability:** graceful degradation; if WHOIS or threat-intel times out, fall back to lexical-only model and flag reduced confidence.
- **Scalability:** stateless API, horizontal scaling via containers, queue for heavy jobs.
- **Reliability:** timeouts and retries on all external calls.
- **Usability:** result understandable by a non-technical user in under 10 seconds.
- **Maintainability:** typed code, linting, modular services, >70% test coverage on core logic.

## 13. Security and Privacy

This product fetches attacker-controlled URLs, so the tool itself must be hardened.

- **SSRF protection:** block requests to private/internal IP ranges and localhost, limit redirects, enforce DNS re-resolution checks.
- **Sandboxed fetching:** strict timeouts, response size cap, no script execution, run in an isolated container.
- Input validation, output escaping (no XSS from scanned page content), CSRF protection.
- Password hashing (bcrypt/argon2), JWT expiry, hashed API keys, rate limiting.
- Privacy: store only URLs and derived features; no page credentials or form contents; configurable retention.
- Clear disclaimer: verdicts are probabilistic, not guarantees.

## 14. Success Metrics

| Type | Metric | Target |
| --- | --- | --- |
| Model | Precision / Recall / FPR | See 7.4 |
| Product | Scan-to-verdict time | < 3 s P95 |
| Product | Reasons judged "understandable" in a 10-person user test | ≥ 80% |
| Quality | Test coverage, CI passing | >70%, green |
| Impact | Detection of phishing URLs newer than training data (time holdout) | ≥ 90% recall |

## 15. Milestones (8-Week Plan)

| Week | Deliverable |
| --- | --- |
| 1 | Requirements finalised, repo, CI, dataset collection and cleaning |
| 2 | Feature extraction pipeline, EDA, baseline models |
| 3 | Main models, tuning, calibration, evaluation report |
| 4 | Explainability (SHAP), inference service, FastAPI endpoints |
| 5 | Dashboard: scan, history, blocklist, auth |
| 6 | Bulk scan, analytics, threat-intel enrichment, caching |
| 7 | Browser extension, enforcement flow, security hardening |
| 8 | Testing, Docker deploy, documentation, demo video, final report |

## 16. Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Dataset bias / leakage inflates accuracy | Misleading results | Domain/time-based splits, time holdout |
| False positives block legitimate sites | Loss of trust | Allowlist, conservative thresholds, user override, feedback loop |
| Concept drift as phishing evolves | Accuracy decay | Drift monitoring, scheduled retraining |
| WHOIS/API rate limits or outages | Missing features | Caching, fallback lexical model |
| Malicious page abuses the fetcher | Security incident | SSRF guards, sandbox, size/time limits |
| Adversarial evasion (look-alike domains) | Missed phishing | Homoglyph/brand-similarity features, retraining on new samples |

## 17. Deliverables

1. Working web app (dashboard + API) and Chrome extension.
2. Trained models with versioned artifacts and an evaluation report.
3. Jupyter notebooks for EDA and experiments.
4. API docs (Swagger), architecture diagram, README with setup in one command (`docker compose up`).
5. Final project report, presentation, and demo video.

## 18. Future Scope

- Visual similarity detection (screenshot + logo matching with CNN) for brand impersonation.
- Email and SMS link scanning, QR code scanning.
- Federated or crowd-sourced threat reporting.
- Active learning from analyst feedback.
- Public blocklist feed.

## 19. Open Questions

- Which threat-intel sources are free and sufficient for the project's rate needs?
- Is page-content fetching in v1, or lexical + host features only?
- Final choice of deployment target (local Docker demo vs cloud free tier)?

## 20. Glossary

**SSRF:** Server-Side Request Forgery. **SHAP:** method that attributes a prediction to input features. **FPR:** false positive rate. **Calibration:** making predicted probabilities match real-world frequencies. **Punycode/IDN:** encoding for non-ASCII domains, often abused in look-alike attacks.
