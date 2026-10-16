"""
Investigate False Positives on Real Live Legitimate URLs
========================================================
Extracts SHAP explanations for legitimate URLs that score >= 30,
ranks them by risk score, and analyzes the root cause features.
"""

import json
from pathlib import Path
from app.services.feature_extractor import extract_features, extract_domain
from app.services.ml_model import ml_service
from app.services.explainer import explainer_service

DATA_PATH = Path(__file__).resolve().parent / "data" / "live_eval_val_200.json"
MODEL_LABEL = "Headline Ablated XGBoost (24 Features, Invariant Ratios, Zero Path Bias)"

with open(DATA_PATH, "r", encoding="utf-8") as f:
    items = json.load(f)["urls"]

legit_items = [u for u in items if u["label"] == 0]

print(f"Error Analysis on Validation Split ({len(legit_items)} real legitimate URLs) using {MODEL_LABEL}...")

scored_items = []
for item in legit_items:
    u = item["url"]
    dom = extract_domain(u)
    feats = extract_features(u)
    pred_prob, _ = ml_service.predict_phishing_probability(feats)
    lex_score = round(pred_prob * 100.0, 1)

    scored_items.append({
        "url": u,
        "domain": dom,
        "type": item.get("type", "unknown"),
        "lexical_score": lex_score,
        "features": feats,
    })

# Sort descending by lexical score
scored_items.sort(key=lambda x: x["lexical_score"], reverse=True)

# Filter score >= 30
fp_ge_30 = [x for x in scored_items if x["lexical_score"] >= 30.0]

# Pick top 20 (or all if fewer)
top_20_targets = scored_items[:20]

# Compute SHAP for top 20
top_20 = []
for x in top_20_targets:
    raw_reasons = explainer_service.explain(x["features"], top_k=5)
    reasons = []
    for r in raw_reasons:
        if hasattr(r, "model_dump"):
            reasons.append(r.model_dump())
        elif hasattr(r, "dict"):
            reasons.append(r.dict())
        else:
            reasons.append({
                "feature": getattr(r, "feature", ""),
                "impact": getattr(r, "impact", 0.0),
                "value": getattr(r, "value", None),
                "direction": getattr(r, "direction", "neutral"),
                "description": getattr(r, "description", "")
            })

    top_20.append({
        "url": x["url"],
        "domain": x["domain"],
        "type": x["type"],
        "lexical_score": x["lexical_score"],
        "reasons": reasons,
        "key_features": {
            k: round(v, 4) for k, v in x["features"].items()
            if k in (
                "domain_entropy", "domain_digit_ratio", "domain_length", "domain_hyphen_count",
                "subdomain_count", "is_https", "special_char_ratio", "domain_dot_count",
                "path_hyphen_ratio", "path_digit_ratio", "has_brand_keyword"
            )
        }
    })

out_report = {
    "model_label": MODEL_LABEL,
    "feature_count": 24,
    "split": "Validation Split (Tuning Only - Error Analysis Partition)",
    "total_legit_tested": len(legit_items),
    "count_lexical_ge_30": len(fp_ge_30),
    "fraction_ge_30": round(len(fp_ge_30) / max(len(legit_items), 1), 4),
    "top_20": top_20,
}

REPORT_OUT = Path(__file__).resolve().parent / "data" / "false_positive_analysis.json"
with open(REPORT_OUT, "w", encoding="utf-8") as f:
    json.dump(out_report, f, indent=2)

print(f"\nTotal legit tested: {len(legit_items)}")
print(f"Legit URLs with lexical score >= 30: {len(fp_ge_30)} ({len(fp_ge_30)/len(legit_items)*100:.1f}%)")
print(f"Full report saved to {REPORT_OUT}")
print("\n" + "="*80)
print("TOP 20 LIVE LEGITIMATE URLS BY RISK SCORE (WITH SHAP REASONS)")
print("="*80)

for i, fp in enumerate(top_20, 1):
    print(f"\n#{i:02d} URL: {fp['url']}")
    print(f"    Domain: {fp['domain']} ({fp['type']}) | Score: {fp['lexical_score']}")
    print(f"    Key Feats: {fp['key_features']}")
    print("    Top SHAP Reasons:")
    for r in fp["reasons"][:3]:
        print(f"      - [{r.get('direction', '').upper()}] {r.get('feature')}: val={r.get('value')} (impact: {r.get('impact', 0):+.2f}) -> {r.get('description')}")
