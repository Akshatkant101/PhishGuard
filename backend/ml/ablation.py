"""
PhishGuard Ablation Study: Path Feature Ablation & Bias Impact
============================================================
Evaluates:
1. Full Model (29 features): Domain + Lexical + Query + Path features.
2. Ablated Model (24 features): No path features (excludes has_path, path_depth,
   path_digit_ratio, path_hyphen_ratio, path_has_suspicious_ext).
   Tests if domain-level signals alone suffice for robust phishing detection.
3. Raw Unbalanced Benchmark: Raw PhiUSIIL where legitimate URLs lacked paths,
   quantifying the spurious shortcut learned if path bias is uncorrected.
"""

from pathlib import Path
import time
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    accuracy_score,
)
from sklearn.model_selection import GroupShuffleSplit
import xgboost as xgb
from sklearn.calibration import CalibratedClassifierCV

from app.services.feature_extractor import (
    extract_domain,
    extract_features_batch,
    get_feature_names,
)

DATA_PATH = Path(__file__).resolve().parent / "data" / "phiusiil_50k.csv"
RAW_PATH = Path(__file__).resolve().parent / "data" / "phiusiil_raw.csv"

PATH_FEATURE_NAMES = [
    "has_path",
    "path_depth",
    "path_digit_ratio",
    "path_hyphen_ratio",
    "path_has_suspicious_ext",
]


def run_ablation_study():
    print("=" * 95)
    print("  PHISHGUARD ABLATION STUDY: PATH FEATURES & BIAS IMPACT ANALYSIS")
    print("=" * 95)

    # 1. Load Balanced 50k Dataset
    print("\n[1/3] Loading 50,000 URL balanced benchmark ...")
    df_balanced = pd.read_csv(DATA_PATH)
    urls = df_balanced["url"].tolist()
    labels = df_balanced["label"].to_numpy(dtype=int)
    domains = np.array([extract_domain(u) for u in urls])

    X_full_df = extract_features_batch(urls)
    all_features = get_feature_names()
    no_path_features = [f for f in all_features if f not in PATH_FEATURE_NAMES]

    # Domain-based split
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(X_full_df, labels, groups=domains))

    y_train = labels[train_idx]
    y_test = labels[test_idx]

    # Experiment 1: Full 29 Features
    print("\n[2/3] Experiment 1: Full 29 Features (Domain + Lexical + Path)")
    X_train_full = X_full_df.iloc[train_idx][all_features].to_numpy()
    X_test_full = X_full_df.iloc[test_idx][all_features].to_numpy()

    xgb_full = CalibratedClassifierCV(
        estimator=xgb.XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1
        ),
        method="sigmoid", cv=3
    )
    t0 = time.perf_counter()
    xgb_full.fit(X_train_full, y_train)
    t_full = time.perf_counter() - t0
    prob_full = xgb_full.predict_proba(X_test_full)[:, 1]
    pred_full = (prob_full >= 0.5).astype(int)

    # Experiment 2: Ablated Model (24 Features, NO Path Features)
    print("\n      Experiment 2: Ablated (24 Features: Zero Path Features)")
    X_train_no_path = X_full_df.iloc[train_idx][no_path_features].to_numpy()
    X_test_no_path = X_full_df.iloc[test_idx][no_path_features].to_numpy()

    xgb_no_path = CalibratedClassifierCV(
        estimator=xgb.XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1
        ),
        method="sigmoid", cv=3
    )
    t0 = time.perf_counter()
    xgb_no_path.fit(X_train_no_path, y_train)
    t_no_path = time.perf_counter() - t0
    prob_no_path = xgb_no_path.predict_proba(X_test_no_path)[:, 1]
    pred_no_path = (prob_no_path >= 0.5).astype(int)

    # Experiment 3: Raw PhiUSIIL without synthetic path balancing
    print("\n[3/3] Experiment 3: Raw PhiUSIIL without synthetic path balancing")
    df_raw = pd.read_csv(RAW_PATH, usecols=["URL", "label"])
    phish_raw = df_raw[df_raw["label"] == 0].sample(n=25000, random_state=42).copy()
    legit_raw = df_raw[df_raw["label"] == 1].sample(n=25000, random_state=42).copy()
    phish_raw["label"] = 1
    legit_raw["label"] = 0
    df_raw_50k = pd.concat([phish_raw, legit_raw]).sample(frac=1.0, random_state=42).reset_index(drop=True)

    raw_urls = df_raw_50k["URL"].tolist()
    raw_labels = df_raw_50k["label"].to_numpy(dtype=int)
    raw_domains = np.array([extract_domain(u) for u in raw_urls])

    X_raw_df = extract_features_batch(raw_urls)
    gss_raw = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    raw_tr_idx, raw_te_idx = next(gss_raw.split(X_raw_df, raw_labels, groups=raw_domains))

    X_raw_train = X_raw_df.iloc[raw_tr_idx][all_features].to_numpy()
    y_raw_train = raw_labels[raw_tr_idx]
    X_raw_test = X_raw_df.iloc[raw_te_idx][all_features].to_numpy()
    y_raw_test = raw_labels[raw_te_idx]

    xgb_raw_bias = CalibratedClassifierCV(
        estimator=xgb.XGBClassifier(
            n_estimators=150, max_depth=6, learning_rate=0.1,
            eval_metric="logloss", random_state=42, n_jobs=-1
        ),
        method="sigmoid", cv=3
    )
    t0 = time.perf_counter()
    xgb_raw_bias.fit(X_raw_train, y_raw_train)
    t_raw = time.perf_counter() - t0
    prob_raw = xgb_raw_bias.predict_proba(X_raw_test)[:, 1]
    pred_raw = (prob_raw >= 0.5).astype(int)

    # Compile Side-by-Side Results
    results = [
        ("Full Model (29 Feats)", y_test, prob_full, pred_full, t_full, 29),
        ("Ablated (No Path Feats, 24 Feats)", y_test, prob_no_path, pred_no_path, t_no_path, 24),
        ("Raw PhiUSIIL (Path-Biased)", y_raw_test, prob_raw, pred_raw, t_raw, 29),
    ]

    print("\n" + "=" * 105)
    print(f"{'Configuration':<35} | {'Feats':<5} | {'Precision':<10} | {'Recall':<10} | {'F1':<10} | {'ROC-AUC':<10} | {'FPR':<10}")
    print("-" * 105)

    ablation_summary = {}
    for name, y_true, y_prob, y_p, t_dur, n_f in results:
        tn, fp, fn, tp = confusion_matrix(y_true, y_p).ravel()
        prec = precision_score(y_true, y_p, zero_division=0)
        rec = recall_score(y_true, y_p, zero_division=0)
        f1 = f1_score(y_true, y_p, zero_division=0)
        auc_val = roc_auc_score(y_true, y_prob)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        ablation_summary[name] = {
            "feature_count": n_f,
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(auc_val), 4),
            "fpr": round(float(fpr), 4),
            "fit_time_s": round(t_dur, 2),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }
        print(f"{name:<35} | {n_f:<5} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {auc_val:<10.4f} | {fpr:<10.4f}")

    print("=" * 105)

    # Save to JSON
    out_file = Path(__file__).resolve().parent / "models" / "ablation_metrics.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(ablation_summary, f, indent=2)

    print(f"\nAblation metrics saved to {out_file}")
    return ablation_summary


if __name__ == "__main__":
    run_ablation_study()
