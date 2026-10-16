"""
Live Evaluation Set Benchmarking: Lexical vs. Enriched Stage 2 Pipeline
=======================================================================
Evaluates real-world, same-day live URLs with zero fabricated paths:
- 200 Live Phishing URLs from OpenPhish
- 200 Legitimate URLs from Tranco Top Sites (homepages + live crawled links)

Evaluates:
- Validation Split (200 URLs: 100 phish, 100 legit) - used for tuning weights
- Held-out Test Split (200 URLs: 100 phish, 100 legit) - completely held-out evaluation
- Combined Full Set (400 URLs)

Reports:
- Precision, Recall, FPR, F1, Accuracy side-by-side (Lexical vs Enriched)
- All PRD targets evaluated strictly as PASS or MISS
- List of cases where enrichment changed the verdict
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Dict, Any, List

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix

from app.services.feature_extractor import extract_features, extract_domain
from app.services.ml_model import ml_service
from app.services.enrichment_service import enrichment_service
from app.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
LIVE_DATA_FILE = BASE_DIR / "data" / "live_eval_400.json"
VAL_DATA_FILE = BASE_DIR / "data" / "live_eval_val_200.json"
TEST_DATA_FILE = BASE_DIR / "data" / "live_eval_test_200.json"
FRESH_TEST_DATA_FILE = BASE_DIR / "data" / "live_eval_fresh_test_200.json"
RESULTS_FILE = BASE_DIR / "models" / "live_eval_metrics.json"

MODEL_LABEL = "Headline Ablated XGBoost (24 Features, Invariant Ratios, Zero Path Bias)"

# PRD Targets (Strictly PASS or MISS)
PRD_TARGETS = {
    "precision": 0.97,
    "recall": 0.95,
    "f1": 0.96,
    "fpr": 0.01,
}


def evaluate_dataset(filepath: Path, split_name: str = "full") -> Dict[str, Any]:
    logger.info(f"Loading live evaluation dataset from {filepath} ({split_name}) ...")
    with open(filepath, "r", encoding="utf-8") as f:
        content = json.load(f)
        data = content.get("urls", content)

    logger.info(f"Loaded {len(data)} live evaluation URLs for {split_name}.")

    y_true = []
    y_pred_lex = []
    y_pred_enr = []

    scores_lex = []
    scores_enr = []
    verdicts_lex = []
    verdicts_enr = []

    verdict_changes = []

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def process_item(item):
        url = item["url"]
        domain = item.get("domain") or extract_domain(url)
        label = item["label"]

        # 1. Lexical ML prediction
        feats = extract_features(url)
        phish_prob, conf = ml_service.predict_phishing_probability(feats)
        lex_score = round(phish_prob * 100.0, 1)

        if lex_score >= settings.THRESHOLD_SUSPICIOUS:  # >= 60.0
            lex_verdict = "PHISHING"
            lex_binary = 1
        elif lex_score >= settings.THRESHOLD_SAFE:        # >= 30.0
            lex_verdict = "SUSPICIOUS"
            lex_binary = 0
        else:
            lex_verdict = "SAFE"
            lex_binary = 0

        # 2. Stage 2 Live Enrichment
        has_ip = bool(feats.get("has_ip_address", 0) == 1)
        enr_data = enrichment_service.enrich_url(url, domain, has_ip=has_ip)
        total_adj = float(enr_data.get("total_adjustment_points", 0.0))

        enr_score = round(max(0.0, min(100.0, lex_score + total_adj)), 1)

        if enr_score >= settings.THRESHOLD_SUSPICIOUS:  # >= 60.0
            enr_verdict = "PHISHING"
            enr_binary = 1
        elif enr_score >= settings.THRESHOLD_SAFE:        # >= 30.0
            enr_verdict = "SUSPICIOUS"
            enr_binary = 0
        else:
            enr_verdict = "SAFE"
            enr_binary = 0

        change_info = None
        if lex_verdict != enr_verdict:
            change_info = {
                "url": url,
                "domain": domain,
                "ground_truth": "PHISHING" if label == 1 else "LEGITIMATE",
                "lexical_score": lex_score,
                "lexical_verdict": lex_verdict,
                "total_adjustment": total_adj,
                "enriched_score": enr_score,
                "enriched_verdict": enr_verdict,
                "adjustments": enr_data.get("adjustments", []),
                "outcome": "CORRECTED" if ((label == 1 and enr_verdict == "PHISHING") or (label == 0 and enr_verdict == "SAFE")) else "SHIFTED",
            }

        return {
            "label": label,
            "lex_score": lex_score,
            "lex_binary": lex_binary,
            "lex_verdict": lex_verdict,
            "enr_score": enr_score,
            "enr_binary": enr_binary,
            "enr_verdict": enr_verdict,
            "change_info": change_info,
        }

    start_time = time.time()
    processed_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(process_item, item) for item in data]
        for f in as_completed(futures):
            processed_results.append(f.result())

    total_time = round(time.time() - start_time, 2)
    y_true = np.array([r["label"] for r in processed_results])
    y_pred_lex = np.array([r["lex_binary"] for r in processed_results])
    y_pred_enr = np.array([r["enr_binary"] for r in processed_results])

    verdict_changes = [r["change_info"] for r in processed_results if r["change_info"]]

    # Compute Lexical Metrics
    cm_lex = confusion_matrix(y_true, y_pred_lex)
    tn_l, fp_l, fn_l, tp_l = cm_lex.ravel()
    fpr_lex = round(float(fp_l / (fp_l + tn_l)), 4) if (fp_l + tn_l) > 0 else 0.0
    prec_lex = round(float(precision_score(y_true, y_pred_lex, zero_division=0)), 4)
    rec_lex = round(float(recall_score(y_true, y_pred_lex, zero_division=0)), 4)
    f1_lex = round(float(f1_score(y_true, y_pred_lex, zero_division=0)), 4)
    acc_lex = round(float(accuracy_score(y_true, y_pred_lex)), 4)

    # Compute Enriched Metrics
    cm_enr = confusion_matrix(y_true, y_pred_enr)
    tn_e, fp_e, fn_e, tp_e = cm_enr.ravel()
    fpr_enr = round(float(fp_e / (fp_e + tn_e)), 4) if (fp_e + tn_e) > 0 else 0.0
    prec_enr = round(float(precision_score(y_true, y_pred_enr, zero_division=0)), 4)
    rec_enr = round(float(recall_score(y_true, y_pred_enr, zero_division=0)), 4)
    f1_enr = round(float(f1_score(y_true, y_pred_enr, zero_division=0)), 4)
    acc_enr = round(float(accuracy_score(y_true, y_pred_enr)), 4)

    # Strict PRD Target Checks (PASS or MISS)
    checks = {
        "precision": {"target": ">= 0.97", "lexical": "PASS" if prec_lex >= 0.97 else "MISS", "enriched": "PASS" if prec_enr >= 0.97 else "MISS"},
        "recall": {"target": ">= 0.95", "lexical": "PASS" if rec_lex >= 0.95 else "MISS", "enriched": "PASS" if rec_enr >= 0.95 else "MISS"},
        "f1": {"target": ">= 0.96", "lexical": "PASS" if f1_lex >= 0.96 else "MISS", "enriched": "PASS" if f1_enr >= 0.96 else "MISS"},
        "fpr": {"target": "< 0.02", "lexical": "PASS" if fpr_lex < 0.02 else "MISS", "enriched": "PASS" if fpr_enr < 0.02 else "MISS"},
    }

    results = {
        "split": split_name,
        "evaluation_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(data),
        "phishing_count": int(np.sum(y_true == 1)),
        "legit_count": int(np.sum(y_true == 0)),
        "total_evaluation_time_seconds": total_time,
        "lexical_metrics": {
            "precision": prec_lex,
            "recall": rec_lex,
            "f1": f1_lex,
            "fpr": fpr_lex,
            "accuracy": acc_lex,
            "confusion_matrix": {"tn": int(tn_l), "fp": int(fp_l), "fn": int(fn_l), "tp": int(tp_l)},
        },
        "enriched_metrics": {
            "precision": prec_enr,
            "recall": rec_enr,
            "f1": f1_enr,
            "fpr": fpr_enr,
            "accuracy": acc_enr,
            "confusion_matrix": {"tn": int(tn_e), "fp": int(fp_e), "fn": int(fn_e), "tp": int(tp_e)},
        },
        "prd_compliance": checks,
        "verdict_changes_count": len(verdict_changes),
        "verdict_changes": verdict_changes,
    }

    # Print Table
    print("\n" + "=" * 90)
    print(f" LIVE EVALUATION BENCHMARK: {split_name.upper()} (N = {len(data)})")
    print("=" * 90)
    print(f"Evaluation Time : {total_time}s")
    print(f"Verdict Shifts  : {len(verdict_changes)} cases where enrichment modified the verdict\n")

    print("-" * 90)
    print(f"{'Metric':<22} | {'PRD Target':<12} | {'Lexical ML':<12} | {'PRD':<6} | {'Stage 2 Enr':<12} | {'PRD':<6} | {'Delta':<8}")
    print("-" * 90)
    print(f"{'Precision':<22} | {'>= 0.97':<12} | {prec_lex:<12.4f} | {checks['precision']['lexical']:<6} | {prec_enr:<12.4f} | {checks['precision']['enriched']:<6} | {prec_enr - prec_lex:+.4f}")
    print(f"{'Recall':<22} | {'>= 0.95':<12} | {rec_lex:<12.4f} | {checks['recall']['lexical']:<6} | {rec_enr:<12.4f} | {checks['recall']['enriched']:<6} | {rec_enr - rec_lex:+.4f}")
    print(f"{'F1 Score':<22} | {'>= 0.96':<12} | {f1_lex:<12.4f} | {checks['f1']['lexical']:<6} | {f1_enr:<12.4f} | {checks['f1']['enriched']:<6} | {f1_enr - f1_lex:+.4f}")
    print(f"{'FPR':<22} | {'< 0.02':<12} | {fpr_lex:<12.4f} | {checks['fpr']['lexical']:<6} | {fpr_enr:<12.4f} | {checks['fpr']['enriched']:<6} | {fpr_enr - fpr_lex:+.4f}")
    print(f"{'Accuracy':<22} | {'N/A':<12} | {acc_lex:<12.4f} | {'-':<6} | {acc_enr:<12.4f} | {'-':<6} | {acc_enr - acc_lex:+.4f}")
    print("-" * 90)

    if verdict_changes:
        print(f"\nVERDICT SHIFTS IN {split_name.upper()} ({len(verdict_changes)} cases):")
        print("-" * 90)
        for c in verdict_changes[:6]:
            print(f"URL: {c['url']}")
            print(f"  Truth: {c['ground_truth']} | Outcome: {c['outcome']}")
            print(f"  Lexical: {c['lexical_score']} ({c['lexical_verdict']}) -> Enriched: {c['enriched_score']} ({c['enriched_verdict']}) [Adj: {c['total_adjustment']:+0.1f}]")
            for a in c["adjustments"]:
                print(f"    * [{a['direction'].upper()}] {a['points']:+0.1f} pts: {a['description']}")
            print()

    return results


def run_full_suite():
    # 1. Validation split (Tuning Only - Error Analysis Partition)
    val_res = evaluate_dataset(
        VAL_DATA_FILE,
        split_name="Validation Split (200 URLs - Tuning Only | Error Analysis Partition)"
    )

    # 2. Fresh Untouched Test split (OpenPhish Fresh + Tranco Ranks 10k-500k)
    fresh_test_res = evaluate_dataset(
        FRESH_TEST_DATA_FILE,
        split_name="Fresh Untouched Test Split (200 URLs - OpenPhish Fresh + Tranco 10k-500k)"
    )

    # 3. Previous Test Split (Treated as Used Benchmark)
    old_test_res = evaluate_dataset(
        TEST_DATA_FILE,
        split_name="Previous Held-out Test Split (200 URLs - Used Benchmark)"
    )

    # Save complete metrics suite
    output_suite = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_label": MODEL_LABEL,
        "feature_count": 24,
        "validation_split": val_res,
        "fresh_test_split": fresh_test_res,
        "used_test_split": old_test_res,
    }

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(output_suite, f, indent=2)

    logger.info(f"Complete multi-split evaluation metrics saved to {RESULTS_FILE}.")


if __name__ == "__main__":
    run_full_suite()
