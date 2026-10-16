"""
Retrain & Fresh-Test Evaluation Pipeline
=========================================
1. Augments training data with Tranco mid-tier legit URLs (10k–1M ranks).
2. Builds a mid-tier validation set for error analysis (separate from fresh test).
3. Retrains the Calibrated XGBoost on the augmented data.
4. Runs the fresh test ONCE.
5. Reports Precision, Recall, FPR at thresholds 30, 60, 85 with PASS/MISS vs PRD.
6. Lists offline FPR 0.0151 as MISS.
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    accuracy_score,
)

# Import project modules
from app.services.feature_extractor import (
    extract_features,
    extract_features_batch,
    extract_domain,
    get_feature_names,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
FRESH_TEST_JSON = DATA_DIR / "live_eval_fresh_test_200.json"
MIDTIER_VAL_JSON = DATA_DIR / "midtier_val_100.json"
RESULTS_FILE = MODEL_DIR / "retrain_fresh_test_results.json"

# PRD targets from prd.md Section 7.4
PRD_TARGETS = {
    "precision": {"op": ">=", "val": 0.97},
    "recall": {"op": ">=", "val": 0.95},
    "fpr": {"op": "<=", "val": 0.01},
}


def _prd_check(metric_name: str, value: float) -> str:
    """Return PASS or MISS against PRD targets."""
    t = PRD_TARGETS.get(metric_name)
    if t is None:
        return "-"
    if t["op"] == ">=":
        return "PASS" if value >= t["val"] else "MISS"
    elif t["op"] == "<=":
        return "PASS" if value <= t["val"] else "MISS"
    return "-"


def _compute_metrics_at_threshold(y_true, y_prob, threshold_pct):
    """
    Compute precision, recall, FPR at a given threshold (0–100 score).

    Threshold semantics: score >= threshold => predicted PHISHING (positive).
    This means:
      - threshold 30: anything >= 30 is predicted phishing
      - threshold 60: anything >= 60 is predicted phishing
      - threshold 85: anything >= 85 is predicted phishing
    """
    scores = y_prob * 100.0
    y_pred = (scores >= threshold_pct).astype(int)

    if y_pred.sum() == 0:
        prec = 1.0  # no FPs
        rec = 0.0
    else:
        prec = float(precision_score(y_true, y_pred, zero_division=1))
        rec = float(recall_score(y_true, y_pred, zero_division=0))

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "threshold": threshold_pct,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "fpr": round(fpr, 4),
        "tp": int(tp),
        "fp": int(fp),
        "fn": int(fn),
        "tn": int(tn),
        "prd_precision": _prd_check("precision", prec),
        "prd_recall": _prd_check("recall", rec),
        "prd_fpr": _prd_check("fpr", fpr),
    }


def step1_augment_data():
    """Step 1: Augment training data with mid-tier legit URLs."""
    print("\n" + "=" * 90)
    print("  STEP 1: AUGMENTING TRAINING DATA WITH TRANCO MID-TIER LEGIT URLs")
    print("=" * 90)

    from ml.data.augment_midtier_legit import build_augmented_dataset
    aug_csv, val_json = build_augmented_dataset()
    print(f"\n  Augmented training CSV: {aug_csv}")
    print(f"  Mid-tier validation JSON: {val_json}")
    return aug_csv


def step2_retrain(augmented_csv: str):
    """Step 2: Retrain the model on the augmented dataset."""
    print("\n" + "=" * 90)
    print("  STEP 2: RETRAINING MODEL ON AUGMENTED DATASET")
    print("=" * 90)

    from ml.train import train_pipeline
    metadata = train_pipeline(data_path=Path(augmented_csv), output_dir=MODEL_DIR)
    print(f"\n  Model retrained. Version: {metadata['model_version']}")
    print(f"  Total samples: {metadata['total_samples']}")
    print(f"  Offline validation FPR: {metadata['best_model_metrics']['fpr']}")
    return metadata


def step3_midtier_val_analysis():
    """Step 3: Run mid-tier validation for error analysis (legit-only FPR check)."""
    print("\n" + "=" * 90)
    print("  STEP 3: MID-TIER VALIDATION ERROR ANALYSIS")
    print("=" * 90)

    import joblib
    model = joblib.load(MODEL_DIR / "model.joblib")
    with open(MODEL_DIR / "model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)
    feature_names = meta.get("feature_names", get_feature_names())

    with open(MIDTIER_VAL_JSON, "r", encoding="utf-8") as f:
        val_data = json.load(f)

    val_items = val_data["urls"]
    print(f"  Loaded {len(val_items)} mid-tier validation URLs (all legitimate)")

    urls = [item["url"] for item in val_items]
    X_df = extract_features_batch(urls)
    X = X_df[feature_names].to_numpy(dtype=np.float32)
    probs = model.predict_proba(X)[:, 1]
    scores = probs * 100.0

    for thresh in [30, 60, 85]:
        fp_count = int((scores >= thresh).sum())
        fpr = fp_count / len(scores) if len(scores) > 0 else 0.0
        print(f"  Threshold {thresh} (>= {thresh} = predicted phishing): "
              f"{fp_count}/{len(scores)} false positives, FPR = {fpr:.4f}")

    # Top-10 highest scoring for error analysis
    idx_sorted = np.argsort(-scores)
    print(f"\n  Top-10 highest-scoring mid-tier legit URLs (for error analysis):")
    for rank, idx in enumerate(idx_sorted[:10], 1):
        item = val_items[idx]
        print(f"    [{rank:2d}] Score: {scores[idx]:5.1f} | {item['url'][:80]} | {item.get('type','?')}")

    return {
        "total_urls": len(val_items),
        "scores": scores.tolist(),
    }


def step4_fresh_test():
    """Step 4: Run the fresh test ONCE. Report at thresholds 30, 60, 85."""
    print("\n" + "=" * 90)
    print("  STEP 4: FRESH TEST (SINGLE RUN — UNTOUCHED BENCHMARK)")
    print("=" * 90)

    import joblib
    model = joblib.load(MODEL_DIR / "model.joblib")
    with open(MODEL_DIR / "model_metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)
    feature_names = meta.get("feature_names", get_feature_names())

    with open(FRESH_TEST_JSON, "r", encoding="utf-8") as f:
        fresh_data = json.load(f)

    items = fresh_data["urls"]
    y_true = np.array([item["label"] for item in items], dtype=int)
    urls = [item["url"] for item in items]

    n_phish = int((y_true == 1).sum())
    n_legit = int((y_true == 0).sum())
    print(f"  Fresh test set: {len(items)} URLs ({n_phish} phishing, {n_legit} legitimate)")

    X_df = extract_features_batch(urls)
    X = X_df[feature_names].to_numpy(dtype=np.float32)

    t0 = time.perf_counter()
    probs = model.predict_proba(X)[:, 1]
    inference_time = time.perf_counter() - t0

    print(f"  Inference time: {inference_time:.3f}s ({inference_time/len(items)*1000:.1f} ms/URL)\n")

    # Compute metrics at all three thresholds
    thresholds = [30, 60, 85]
    results = {}
    for thresh in thresholds:
        m = _compute_metrics_at_threshold(y_true, probs, thresh)
        results[f"threshold_{thresh}"] = m

    # =============================================
    # Table 1: Multi-Threshold Fresh Test Results
    # =============================================
    print("  " + "=" * 100)
    print("  FRESH TEST RESULTS: Predicted Phishing = score >= threshold")
    print("  " + "=" * 100)
    print(f"  {'Threshold':<12} | {'Precision':<12} | {'PRD':<6} | {'Recall':<12} | {'PRD':<6} | "
          f"{'FPR':<12} | {'PRD':<6} | {'TP':<5} | {'FP':<5} | {'FN':<5} | {'TN':<5}")
    print("  " + "-" * 100)

    for thresh in thresholds:
        m = results[f"threshold_{thresh}"]
        print(f"  >= {thresh:<8} | {m['precision']:<12.4f} | {m['prd_precision']:<6} | "
              f"{m['recall']:<12.4f} | {m['prd_recall']:<6} | "
              f"{m['fpr']:<12.4f} | {m['prd_fpr']:<6} | "
              f"{m['tp']:<5} | {m['fp']:<5} | {m['fn']:<5} | {m['tn']:<5}")
    print("  " + "=" * 100)

    print(f"\n  NOTE: 'Predicted Phishing' means the model's risk score >= threshold.")
    print(f"        PRD targets: Precision >= 0.97, Recall >= 0.95, FPR <= 0.01 (1%)")

    return results, probs, y_true


def step5_offline_fpr_note(offline_fpr: float = 0.0151):
    """Step 5: Report offline FPR as MISS per user request."""
    print("\n" + "=" * 90)
    print("  OFFLINE VALIDATION FPR COMPLIANCE")
    print("=" * 90)

    status = _prd_check("fpr", offline_fpr)
    print(f"  Previous Offline Validation FPR: {offline_fpr:.4f}")
    print(f"  PRD Target: FPR <= 0.01")
    print(f"  Status: {status}")
    print("=" * 90)


def run_full_pipeline():
    """Execute the complete retrain + fresh test pipeline."""
    print("\n" + "#" * 90)
    print("  PHISHGUARD RETRAIN & FRESH TEST PIPELINE")
    print("  Goal: Reduce FPR on mid-tier sites via training data augmentation")
    print("#" * 90)

    t_start = time.perf_counter()

    # Step 1: Augment data
    augmented_csv = step1_augment_data()

    # Step 2: Retrain
    train_meta = step2_retrain(augmented_csv)

    # Step 3: Mid-tier validation error analysis
    val_analysis = step3_midtier_val_analysis()

    # Step 4: Fresh test (single run)
    fresh_results, probs, y_true = step4_fresh_test()

    # Step 5: Offline FPR note
    # Report the retrained model's offline validation FPR
    retrained_offline_fpr = train_meta.get("best_model_metrics", {}).get("fpr", 0.0)
    previous_offline_fpr = 0.0151

    step5_offline_fpr_note(previous_offline_fpr)

    # =============================================
    # Final Summary Report
    # =============================================
    print("\n" + "#" * 90)
    print("  FINAL SUMMARY REPORT")
    print("#" * 90)

    print("\n  Table: Offline Validation FPR (Predicted Phishing = probability >= 0.50)")
    print("  " + "-" * 60)
    print(f"  {'Metric':<30} | {'Value':<12} | {'PRD (<=0.01)':<12}")
    print("  " + "-" * 60)
    print(f"  {'Previous Offline FPR':<30} | {previous_offline_fpr:<12.4f} | {'MISS':<12}")
    print(f"  {'Retrained Offline FPR':<30} | {retrained_offline_fpr:<12.4f} | "
          f"{_prd_check('fpr', retrained_offline_fpr):<12}")
    print("  " + "-" * 60)

    print("\n  Table: Fresh Test Multi-Threshold (Predicted Phishing = score >= threshold)")
    print("  " + "-" * 95)
    print(f"  {'Threshold':<12} | {'Precision':<10} | {'PRD':<6} | {'Recall':<10} | {'PRD':<6} | "
          f"{'FPR':<10} | {'PRD':<6}")
    print("  " + "-" * 95)
    for thresh in [30, 60, 85]:
        m = fresh_results[f"threshold_{thresh}"]
        print(f"  >= {thresh:<8} | {m['precision']:<10.4f} | {m['prd_precision']:<6} | "
              f"{m['recall']:<10.4f} | {m['prd_recall']:<6} | "
              f"{m['fpr']:<10.4f} | {m['prd_fpr']:<6}")
    print("  " + "-" * 95)

    total_time = time.perf_counter() - t_start
    print(f"\n  Total pipeline time: {total_time:.1f}s")

    # Save results
    output = {
        "pipeline_run_at": datetime.now(timezone.utc).isoformat(),
        "total_pipeline_time_s": round(total_time, 1),
        "training_metadata": {
            "model_version": train_meta.get("model_version"),
            "total_samples": train_meta.get("total_samples"),
            "train_samples": train_meta.get("train_samples"),
            "test_samples": train_meta.get("test_samples"),
            "feature_count": train_meta.get("feature_count"),
        },
        "offline_fpr": {
            "previous": {"fpr": previous_offline_fpr, "prd": "MISS"},
            "retrained": {"fpr": retrained_offline_fpr, "prd": _prd_check("fpr", retrained_offline_fpr)},
        },
        "fresh_test_multi_threshold": fresh_results,
        "midtier_val_analysis": {
            "total_urls": val_analysis["total_urls"],
        },
    }

    with open(RESULTS_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\n  Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    run_full_pipeline()
