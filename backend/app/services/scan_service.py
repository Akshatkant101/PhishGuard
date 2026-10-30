import time
import logging
from typing import Optional, List
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.config import settings
from app.models.db_models import ScanRecord, BlocklistEntry, AllowlistEntry
from app.schemas.schemas import ScanResponse, ReasonItem
from app.services.feature_extractor import extract_features, extract_domain
from app.services.ml_model import ml_service
from app.services.explainer import explainer_service
from app.services.enrichment_service import enrichment_service

logger = logging.getLogger(__name__)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


class ScanService:
    @staticmethod
    def is_allowlisted(db: Session, url: str, domain: str) -> Optional[AllowlistEntry]:
        """Check if domain or full URL is in allowlist."""
        return (
            db.query(AllowlistEntry)
            .filter(
                (AllowlistEntry.pattern == domain)
                | (AllowlistEntry.pattern == url)
                | (AllowlistEntry.pattern == domain.replace("www.", ""))
            )
            .first()
        )

    @staticmethod
    def is_blocklisted(db: Session, url: str, domain: str) -> Optional[BlocklistEntry]:
        """Check if domain or full URL is in blocklist."""
        return (
            db.query(BlocklistEntry)
            .filter(
                (BlocklistEntry.pattern == domain)
                | (BlocklistEntry.pattern == url)
                | (BlocklistEntry.pattern == domain.replace("www.", ""))
            )
            .first()
        )

    @staticmethod
    def generate_summary(
        verdict: str,
        risk_score: float,
        reasons: List[ReasonItem],
        enrichment_reasons: List[EnrichmentReason],
        features: Optional[Dict[str, float]] = None,
    ) -> str:
        features = features or {}
        for r in reasons:
            if getattr(r, "feature", "") == "allowlist":
                return "Explicitly trusted: Domain is present in the verified organizational allowlist."
            if getattr(r, "feature", "") == "blocklist":
                return "Critical Risk: Domain is blocked by administrative organizational security policy."
            if getattr(r, "feature", "") == "google_safe_browsing":
                return "Critical Threat: Verified malicious host flagged by Google Safe Browsing threat feeds."

        if verdict == "SAFE":
            if risk_score <= 10.0:
                return "Benign URL: Clean structural lexical profile with established domain authority and valid SSL encryption."
            return f"Low Risk ({risk_score:.0f}/100): Primarily benign, with minor structural anomalies that do not meet threat thresholds."

        suspicious_signals = []
        for er in enrichment_reasons:
            if er.signal == "unresolvable_dns":
                suspicious_signals.append("unresolvable DNS records")
            elif er.signal == "brand_impersonation":
                suspicious_signals.append("potential brand spoofing")
            elif er.signal == "young_domain":
                suspicious_signals.append("recently registered domain (<30 days old)")
            elif er.signal == "invalid_tls":
                suspicious_signals.append("invalid TLS certificate")
            elif er.signal == "short_lived_tls_certificate":
                suspicious_signals.append("short-lived TLS certificate")

        if features.get("has_ip_address", 0) == 1:
            suspicious_signals.append("raw IP host address")
        if features.get("is_https", 1) == 0:
            suspicious_signals.append("unencrypted HTTP connection")
        if features.get("suspicious_tld", 0) > 0.7:
            suspicious_signals.append("high-abuse TLD")
        if features.get("brand_name_in_subdomain", 0) == 1:
            suspicious_signals.append("brand keyword in subdomain")
        if features.get("subdomain_count", 0) >= 3:
            suspicious_signals.append("excessive subdomain nesting")
        if features.get("has_login_keyword", 0) == 1:
            suspicious_signals.append("credential harvesting patterns")

        if not suspicious_signals:
            for r in reasons:
                if getattr(r, "direction", "") == "suspicious" and getattr(r, "impact", 0) > 0.05:
                    suspicious_signals.append(getattr(r, "description", "").lower())

        if verdict == "SUSPICIOUS":
            signal_text = ", ".join(suspicious_signals[:2]) if suspicious_signals else "atypical URL structure and elevated lexical entropy"
            return f"Suspicious ({risk_score:.0f}/100): Flagged due to {signal_text}. Exercise caution before interacting."
        else:
            signal_text = ", ".join(suspicious_signals[:3]) if suspicious_signals else "severe compound lexical and network threat indicators"
            return f"High-Risk Phishing ({risk_score:.0f}/100): Strongly indicative of an attack due to {signal_text}. Do not enter credentials."

    @classmethod
    def scan_url(cls, db: Session, raw_url: str, save_record: bool = True) -> ScanResponse:
        start_time = time.perf_counter()
        url = normalize_url(raw_url)
        domain = extract_domain(url)

        # 1. Allowlist check
        allow_entry = cls.is_allowlisted(db, url, domain)
        if allow_entry:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reasons = [
                ReasonItem(
                    feature="allowlist",
                    description=f"Explicitly trusted by allowlist: {allow_entry.reason or 'Organization policy'}",
                    value=0.0,
                    impact=-5.0,
                    direction="benign",
                )
            ]
            record = ScanRecord(
                url=url,
                domain=domain,
                verdict="SAFE",
                risk_score=0.0,
                lexical_risk_score=0.0,
                confidence=1.0,
                latency_ms=latency_ms,
                model_version=ml_service.metadata.get("model_version", "allowlist-override"),
            )
            record.set_reasons([r.model_dump() for r in reasons])
            record.set_enrichment_reasons([])
            record.set_features({})
            if save_record:
                db.add(record)
                db.commit()
                db.refresh(record)

            return ScanResponse(
                id=record.id,
                url=url,
                domain=domain,
                verdict="SAFE",
                risk_score=0.0,
                lexical_risk_score=0.0,
                confidence=1.0,
                latency_ms=latency_ms,
                reasons=reasons,
                enrichment_reasons=[],
                features={},
                enrichment=None,
                model_version=record.model_version,
                summary="Explicitly trusted: Domain is present in the verified organizational allowlist.",
                created_at=record.created_at,
            )

        # 2. Blocklist check
        block_entry = cls.is_blocklisted(db, url, domain)
        if block_entry:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reasons = [
                ReasonItem(
                    feature="blocklist",
                    description=f"Flagged by blocklist: {block_entry.reason or 'Organization policy'}",
                    value=1.0,
                    impact=5.0,
                    direction="suspicious",
                )
            ]
            record = ScanRecord(
                url=url,
                domain=domain,
                verdict="PHISHING",
                risk_score=100.0,
                lexical_risk_score=100.0,
                confidence=1.0,
                latency_ms=latency_ms,
                model_version=ml_service.metadata.get("model_version", "blocklist-override"),
            )
            record.set_reasons([r.model_dump() for r in reasons])
            record.set_enrichment_reasons([])
            record.set_features({})
            if save_record:
                db.add(record)
                db.commit()
                db.refresh(record)

            return ScanResponse(
                id=record.id,
                url=url,
                domain=domain,
                verdict="PHISHING",
                risk_score=100.0,
                lexical_risk_score=100.0,
                confidence=1.0,
                latency_ms=latency_ms,
                reasons=reasons,
                enrichment_reasons=[],
                features={},
                enrichment=None,
                model_version=record.model_version,
                summary="Critical Risk: Domain is blocked by administrative organizational security policy.",
                created_at=record.created_at,
            )

        # 3. Optional Google Safe Browsing Lookup
        sb_result = enrichment_service.check_safe_browsing(url)
        if sb_result.get("is_threat"):
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            reasons = [
                ReasonItem(
                    feature="google_safe_browsing",
                    description=f"Flagged by Google Safe Browsing Threat Feed ({sb_result.get('threat_type')})",
                    value=1.0,
                    impact=5.0,
                    direction="suspicious",
                )
            ]
            from app.schemas.schemas import EnrichmentReason
            enrichment_reasons = [
                EnrichmentReason(
                    signal="google_safe_browsing",
                    points=60.0,
                    description=f"Flagged by Google Safe Browsing Threat Feed ({sb_result.get('threat_type')})",
                    direction="suspicious",
                )
            ]
            record = ScanRecord(
                url=url,
                domain=domain,
                verdict="PHISHING",
                risk_score=100.0,
                lexical_risk_score=100.0,
                confidence=1.0,
                latency_ms=latency_ms,
                model_version=ml_service.metadata.get("model_version", "safe-browsing-hit"),
            )
            record.set_reasons([r.model_dump() for r in reasons])
            record.set_enrichment_reasons([r.model_dump() for r in enrichment_reasons])
            record.set_features({})
            if save_record:
                db.add(record)
                db.commit()
                db.refresh(record)

            return ScanResponse(
                id=record.id,
                url=url,
                domain=domain,
                verdict="PHISHING",
                risk_score=100.0,
                lexical_risk_score=100.0,
                confidence=1.0,
                latency_ms=latency_ms,
                reasons=reasons,
                enrichment_reasons=enrichment_reasons,
                features={},
                enrichment={"safe_browsing": sb_result},
                model_version=record.model_version,
                summary=f"Critical Threat: Verified malicious host flagged by Google Safe Browsing ({sb_result.get('threat_type')}).",
                created_at=record.created_at,
            )

        # 4. Lexical Feature Extraction (Single source of truth)
        features = extract_features(url)

        # 5. ML Model Prediction
        phish_prob, confidence = ml_service.predict_phishing_probability(features)
        lexical_risk_score = round(phish_prob * 100.0, 1)

        # 6. Pure SHAP Explainability Reasons (Kept strictly ML-only)
        reasons = explainer_service.explain(features, top_k=5)

        # 7. Stage 2 Live Enrichment with Documented Rule Adjustments
        has_ip = bool(features.get("has_ip_address", 0) == 1)
        enrichment_data = enrichment_service.enrich_url(url, domain, has_ip=has_ip)

        # Parse documented rule adjustments
        adjustments_raw = enrichment_data.get("adjustments", [])
        from app.schemas.schemas import EnrichmentReason
        enrichment_reasons = [
            EnrichmentReason(
                signal=a["signal"],
                points=a["points"],
                description=a["description"],
                direction=a["direction"],
            )
            for a in adjustments_raw
        ]

        # Apply rule adjustments to score (clamped to 0.0 - 100.0)
        total_adj = float(enrichment_data.get("total_adjustment_points", 0.0))
        risk_score = round(max(0.0, min(100.0, lexical_risk_score + total_adj)), 1)

        # 8. Verdict Determination Aligned to PRD: 30 / 60 / 85
        if risk_score >= settings.THRESHOLD_SUSPICIOUS:  # >= 60.0
            verdict = "PHISHING"
        elif risk_score >= settings.THRESHOLD_SAFE:        # >= 30.0
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        # 9. Auto-block if threshold exceeded (>= 85.0)
        if risk_score >= settings.AUTO_BLOCK_THRESHOLD and not block_entry:
            try:
                auto_entry = BlocklistEntry(
                    pattern=domain,
                    entry_type="domain",
                    reason=f"Auto-blocked due to severe risk score ({risk_score}/100)",
                    added_by="auto-block",
                )
                db.add(auto_entry)
                db.flush()
                logger.info(f"Auto-blocked high-risk domain: {domain} ({risk_score})")
            except Exception as e:
                db.rollback()
                logger.warning(f"Auto-block duplicate or error for {domain}: {e}")

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        model_version = ml_service.metadata.get("model_version", "v1")

        # 10. Record saving
        record = ScanRecord(
            url=url,
            domain=domain,
            verdict=verdict,
            risk_score=risk_score,
            lexical_risk_score=lexical_risk_score,
            confidence=round(confidence, 3),
            latency_ms=latency_ms,
            model_version=model_version,
        )
        record.set_reasons([r.model_dump() for r in reasons])
        record.set_enrichment_reasons([r.model_dump() for r in enrichment_reasons])
        record.set_enrichment(enrichment_data)
        record.set_features(features)

        if save_record:
            db.add(record)
            db.commit()
            db.refresh(record)

        summary = cls.generate_summary(
            verdict=verdict,
            risk_score=risk_score,
            reasons=reasons,
            enrichment_reasons=enrichment_reasons,
            features=features,
        )

        return ScanResponse(
            id=record.id,
            url=url,
            domain=domain,
            verdict=verdict,
            risk_score=risk_score,
            lexical_risk_score=lexical_risk_score,
            confidence=round(confidence, 3),
            latency_ms=latency_ms,
            reasons=reasons,
            enrichment_reasons=enrichment_reasons,
            features=features,
            enrichment=enrichment_data,
            model_version=model_version,
            summary=summary,
            created_at=record.created_at,
        )


scan_service = ScanService()
