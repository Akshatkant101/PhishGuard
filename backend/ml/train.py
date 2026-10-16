"""
PhishGuard Model Training Pipeline
==================================
Trains and validates:
1. Logistic Regression (Baseline)
2. Random Forest
3. XGBoost (Main Model) with Platt Probability Calibration

Methodology:
- Grouped Domain Split: Ensures zero domain leakage between training,
  validation, and test partitions.
- Real dataset: 50,000+ verified PhiUSIIL URLs.
- No tuning on the held-out test partition.
- Learned per-TLD phishing rates (Laplace-smoothed, from training split only)
  replace the hand-written SUSPICIOUS_TLDS binary feature.
- Saves calibrated XGBoost as primary production inference model
  and uncalibrated XGBoost for SHAP TreeExplainer.
"""

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import time
from urllib.parse import urlparse
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

from app.services.feature_extractor import (
    extract_domain,
    extract_features_batch,
    get_feature_names,
    set_tld_phish_rates,
)

warnings.filterwarnings("ignore")

DATA_PATH = Path(__file__).resolve().parent / "data" / "phiusiil_50k.csv"
OUTPUT_DIR = Path(__file__).resolve().parent / "models"


def compute_tld_phish_rates(urls: list, labels, alpha: float = 5.0):
    """Compute smoothed per-TLD phishing rates from training data.

    Uses Laplace smoothing: rate = (phish_count + α) / (total + 2α).
    Unseen TLDs at inference time fall back to the global phishing rate.

    Returns:
        (rates_dict, global_rate)
    """
    tld_total: Counter = Counter()
    tld_phish: Counter = Counter()

    for url, label in zip(urls, labels):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            hostname = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        parts = hostname.split(".")
        tld = parts[-1] if parts else ""
        if tld:
            tld_total[tld] += 1
            if int(label) == 1:
                tld_phish[tld] += 1

    total_urls = sum(tld_total.values())
    total_phish = sum(tld_phish.values())
    global_rate = total_phish / max(total_urls, 1)

    rates = {}
    for tld, count in tld_total.items():
        p = tld_phish.get(tld, 0)
        rates[tld] = round((p + alpha) / (count + 2 * alpha), 6)

    return rates, round(global_rate, 6)


def train_pipeline(data_path: Path | None = None, output_dir: Path | None = None, ablated: bool = True):
    data_path = Path(data_path or DATA_PATH)
    output_dir = Path(output_dir or OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_label = "Headline Ablated 24-Feature (Zero Path Bias)" if ablated else "Full 29-Feature"
    print("=" * 80)
    print(f"  PHISHGUARD ML TRAINING PIPELINE [{model_label.upper()}]")
    print("=" * 80)

    # 1. Load Dataset
    print(f"\n[1/7] Loading dataset from {data_path} ...")
    df = pd.read_csv(data_path)
    urls = df["url"].tolist()
    labels = df["label"].to_numpy(dtype=int)
    domains = np.array([extract_domain(u) for u in urls])

    n_phish = int((labels == 1).sum())
    n_legit = int((labels == 0).sum())
    print(f"Loaded {len(df):,} URLs: {n_phish:,} Phishing, {n_legit:,} Legitimate")
    print(f"Unique registered domains: {len(np.unique(domains)):,}")

    # 2. Domain-Based Split (Train 80% / Test 20%) - ZERO Domain Leakage
    #    Split BEFORE feature extraction so TLD rates come from training only.
    print("\n[2/7] Performing Grouped Domain Split (Train 80% / Test 20%) ...")
    gss_test = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss_test.split(np.arange(len(labels)), labels, groups=domains))

    train_domains = set(domains[train_idx])
    test_domains = set(domains[test_idx])
    overlap = len(train_domains.intersection(test_domains))
    print(f"Train samples: {len(train_idx):,} ({len(train_domains):,} domains)")
    print(f"Test samples:  {len(test_idx):,} ({len(test_domains):,} domains)")
    print(f"Domain Leakage Check: {overlap} overlapping domains (VERIFIED: ZERO LEAKAGE)")
    assert overlap == 0, "Error: Domain leakage detected!"

    # Split train further into train_fit (80%) and val_calib (20%) via domain split
    gss_val = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    fit_sub_idx, calib_sub_idx = next(gss_val.split(train_idx, labels[train_idx], groups=domains[train_idx]))

    fit_idx = train_idx[fit_sub_idx]
    calib_idx = train_idx[calib_sub_idx]

    print(f"  - Model Fitting partition:    {len(fit_idx):,} samples")
    print(f"  - Calibration/Val partition:  {len(calib_idx):,} samples")
    print(f"  - Untouched Test partition:   {len(test_idx):,} samples")

    # 3. Compute Per-TLD Phishing Rates (from training split ONLY)
    print("\n[3/7] Computing smoothed per-TLD phishing rates from training data ...")
    train_urls_for_tld = [urls[i] for i in train_idx]
    tld_rates, tld_default = compute_tld_phish_rates(train_urls_for_tld, labels[train_idx])
    set_tld_phish_rates(tld_rates, tld_default)
    print(f"Learned rates for {len(tld_rates)} TLDs (smoothing alpha=5, global prior: {tld_default:.4f})")
    top5 = sorted(tld_rates.items(), key=lambda x: -x[1])[:5]
    bot5 = sorted(tld_rates.items(), key=lambda x: x[1])[:5]
    print(f"  Highest phish-rate TLDs: {[(t, round(r,3)) for t,r in top5]}")
    print(f"  Lowest  phish-rate TLDs: {[(t, round(r,3)) for t,r in bot5]}")

    # 4. Extract Features (with learned TLD rates active)
    all_feature_names = get_feature_names()
    path_features = [
        "has_path", "path_depth", "path_digit_ratio", "path_hyphen_ratio", "path_has_suspicious_ext"
    ]
    if ablated:
        feature_names = [f for f in all_feature_names if f not in path_features]
        print(f"\n[4/7] Extracting {len(feature_names)} Headline Ablated ratio-based features (excluding 5 path features) ...")
    else:
        feature_names = all_feature_names
        print(f"\n[4/7] Extracting {len(feature_names)} full ratio-based features ...")

    t0_feat = time.perf_counter()
    X_df = extract_features_batch(urls)
    X_matrix = X_df[feature_names].to_numpy(dtype=np.float32)
    print(f"Extracted features for {len(X_df):,} URLs in {time.perf_counter() - t0_feat:.2f}s")

    X_train, y_train = X_matrix[train_idx], labels[train_idx]
    X_fit, y_fit = X_matrix[fit_idx], labels[fit_idx]
    X_calib, y_calib = X_matrix[calib_idx], labels[calib_idx]
    X_test, y_test = X_matrix[test_idx], labels[test_idx]

    # Save test partition untouched
    test_split_data = {
        "urls": [urls[i] for i in test_idx],
        "labels": labels[test_idx].tolist(),
        "domains": domains[test_idx].tolist(),
    }
    with open(output_dir / "test_split.json", "w", encoding="utf-8") as f:
        json.dump(test_split_data, f)

    # 5. Train Models
    print("\n[5/7] Training Candidate Classifiers on Fitting partition ...")
    scaler = StandardScaler().fit(X_fit)
    X_fit_scaled = scaler.transform(X_fit)
    X_calib_scaled = scaler.transform(X_calib)

    # Model 1: Logistic Regression
    t0 = time.perf_counter()
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_fit_scaled, y_fit)
    lr_time = time.perf_counter() - t0

    # Model 2: Random Forest
    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=-1)
    rf.fit(X_fit, y_fit)
    rf_time = time.perf_counter() - t0

    # Model 3: XGBoost (Main Model)
    t0 = time.perf_counter()
    xgb_clf = xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    xgb_clf.fit(X_fit, y_fit)
    xgb_time = time.perf_counter() - t0

    # 6. Probability Calibration for XGBoost
    print("\n[6/7] Applying Platt Probability Calibration (3-Fold CV) on Train partition ...")
    calibrated_xgb = CalibratedClassifierCV(estimator=xgb.XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    ), method="sigmoid", cv=3)
    t0_cal = time.perf_counter()
    calibrated_xgb.fit(X_train, y_train)
    cal_time = time.perf_counter() - t0_cal

    # Evaluate on Validation split (Side-by-Side comparison)
    models_eval = {
        "Logistic Regression": (lr, X_calib_scaled, lr_time),
        "Random Forest": (rf, X_calib, rf_time),
        "XGBoost (Raw)": (xgb_clf, X_calib, xgb_time),
        "XGBoost (Calibrated)": (calibrated_xgb, X_calib, cal_time),
    }

    val_metrics = {}
    print("\n" + "=" * 90)
    print(f"{'Model':<25} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'ROC-AUC':<10} | {'FPR':<10} | {'Time (s)':<8}")
    print("-" * 90)

    for name, (m, X_in, t_sec) in models_eval.items():
        y_prob = m.predict_proba(X_in)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_calib, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        prec = precision_score(y_calib, y_pred, zero_division=0)
        rec = recall_score(y_calib, y_pred, zero_division=0)
        f1 = f1_score(y_calib, y_pred, zero_division=0)
        auc = roc_auc_score(y_calib, y_prob)

        val_metrics[name] = {
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "fpr": round(float(fpr), 4),
            "train_time_s": round(t_sec, 3),
        }
        print(f"{name:<25} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {auc:<10.4f} | {fpr:<10.4f} | {t_sec:<8.2f}")
    print("=" * 90)

    # 7. Save Model Artifacts
    print("\n[7/7] Saving trained model artifacts ...")
    model_version = f"v{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    # Main inference model (calibrated XGBoost)
    joblib.dump(calibrated_xgb, output_dir / "model.joblib")
    # Base XGBoost model for SHAP TreeExplainer
    joblib.dump(xgb_clf, output_dir / "xgb_base.joblib")
    # Other models
    joblib.dump(rf, output_dir / "rf_model.joblib")
    joblib.dump(lr, output_dir / "lr_model.joblib")
    joblib.dump(scaler, output_dir / "scaler.joblib")

    # Save learned TLD phishing rates
    tld_rates_data = {
        "rates": tld_rates,
        "default_rate": tld_default,
        "alpha": 5.0,
        "n_tlds": len(tld_rates),
    }
    with open(output_dir / "tld_phish_rates.json", "w", encoding="utf-8") as f:
        json.dump(tld_rates_data, f, indent=2)
    print(f"  - tld_phish_rates.json  (Learned rates for {len(tld_rates)} TLDs)")

    p_len = df[df["label"] == 1]["url"].str.len().mean()
    l_len = df[df["label"] == 0]["url"].str.len().mean()

    metadata = {
        "model_version": model_version,
        "model_type": f"XGBoost + Platt Calibration ({model_label})",
        "main_model": f"XGBoost + Platt Calibration ({model_label})",
        "base_model": "XGBoost",
        "training_date": datetime.now(timezone.utc).isoformat(),
        "dataset": str(data_path),
        "total_samples": len(df),
        "train_samples": len(train_idx),
        "test_samples": len(test_idx),
        "train_domains": len(train_domains),
        "test_domains": len(test_domains),
        "domain_leakage": 0,
        "feature_count": len(feature_names),
        "feature_names": feature_names,
        "tld_rate_feature": "suspicious_tld (continuous, Laplace-smoothed from training data)",
        "all_model_metrics": val_metrics,
        "validation_metrics": val_metrics,
        "best_model_metrics": val_metrics.get("XGBoost (Calibrated)", val_metrics.get("XGBoost (Raw)")),
        "class_distribution": {
            "total": len(df),
            "train_legit": int((y_train == 0).sum()),
            "train_phish": int((y_train == 1).sum()),
            "test_legit": int((y_test == 0).sum()),
            "test_phish": int((y_test == 1).sum()),
        },
        "bias_check": {
            "avg_url_length_legit": round(float(l_len), 1),
            "avg_url_length_phish": round(float(p_len), 1),
            "delta": round(float(abs(l_len - p_len)), 1),
        },
        "uses_scaled_features": False,
    }

    with open(output_dir / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Artifacts successfully saved to {output_dir}:")
    print("  - model.joblib      (Calibrated XGBoost)")
    print("  - xgb_base.joblib   (Base XGBoost for SHAP TreeExplainer)")
    print("  - test_split.json   (Untouched held-out test set)")
    print("  - model_metadata.json")
    print("\nTraining completed successfully.")
    return metadata


def train(data_path: Path | str | None = None, output_dir: Path | str | None = None):
    """Alias for train_pipeline."""
    return train_pipeline(data_path, output_dir)


if __name__ == "__main__":
    train_pipeline()
