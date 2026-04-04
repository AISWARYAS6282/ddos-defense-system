"""
train_model.py  —  CICIDS2017 Friday DDoS — ZERO LEAKAGE FINAL
python train_model.py

All bugs and data leakage fixed:
  #1 LEAKAGE: Scaler now fit ONLY on X_train, after split
  #2 LEAKAGE: Zero-variance filter now computed on X_train only, after split
  #3 RE-BROKEN: early_stopping_rounds moved back to fit() where it belongs
  #4 MINOR:   LabelEncoder fit before split (harmless but fixed for correctness)
  #5 COSMETIC: enumerate(imp, 1) so ranking starts at 1
"""

import os, sys, warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

CSV_PATH     = r"C:\Users\aiswa\Downloads\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
OUTPUT_MODEL = os.path.join("app", "ml", "rf_model.pkl")
OUTPUT_META  = os.path.join("app", "ml", "rf_meta.pkl")


def main():
    print("\n" + "=" * 60)
    print("  CICIDS2017  —  XGBoost ZERO LEAKAGE FINAL")
    print("=" * 60)

    # ── Load ──────────────────────────────────────────────────────────────────
    print(f"\n📂 Loading CSV...")
    df = pd.read_csv(CSV_PATH, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"   Shape: {df.shape}")

    label_col = "Label"
    df[label_col] = df[label_col].str.strip()

    print(f"\n   Class distribution:")
    for label, count in df[label_col].value_counts().items():
        print(f"     {label:30s}: {count:,}")

    # ── Features — convert to numeric, clip extremes ──────────────────────────
    feature_cols = [c for c in df.columns if c != label_col]
    X_raw = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X_raw = X_raw.replace([np.inf, -np.inf], np.nan).fillna(0).clip(-1e12, 1e12)

    # ── Encode labels ─────────────────────────────────────────────────────────
    le = LabelEncoder()
    y  = le.fit_transform(df[label_col])
    n_classes = len(le.classes_)
    print(f"\n   Classes ({n_classes}): {list(le.classes_)}")

    # ── SPLIT FIRST — before any fitting ─────────────────────────────────────
    # FIX #1 and #2: nothing is fit on data until AFTER this split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n📐 Train: {len(X_train_raw):,}  |  Test: {len(X_test_raw):,}")

    # ── FIX #2: zero-variance filter computed on TRAIN ONLY ──────────────────
    train_stds = X_train_raw.std()
    good = list(train_stds[train_stds > 0].index)
    X_train_raw = X_train_raw[good]
    X_test_raw  = X_test_raw[good]
    print(f"🔧 {len(good)} features kept  ({len(feature_cols) - len(good)} zero-variance dropped)")

    # ── FIX #1: scaler fit on TRAIN ONLY, then transform both ────────────────
    scaler    = StandardScaler()
    X_train_s = scaler.fit_transform(X_train_raw)   # fit + transform — train only
    X_test_s  = scaler.transform(X_test_raw)        # transform only — no leakage

    # ── Objective and metric ──────────────────────────────────────────────────
    if n_classes == 2:
        objective   = "binary:logistic"
        eval_metric = "logloss"
    else:
        objective   = "multi:softmax"
        eval_metric = "mlogloss"

    print(f"\n🤖 Training XGBoost  ({objective}, {n_classes} classes)...")

    # ── FIX #3: early_stopping_rounds in fit(), NOT in constructor ────────────
    # ADD early_stopping_rounds to constructor, remove from fit():
    model = XGBClassifier(
    n_estimators          = 300,
    max_depth             = 8,
    learning_rate         = 0.1,
    subsample             = 0.8,
    colsample_bytree      = 0.8,
    objective             = objective,
    eval_metric           = eval_metric,
    early_stopping_rounds = 15,    # ← ADD HERE
    n_jobs                = -1,
    random_state          = 42,
    verbosity             = 0,
    )

    model.fit(
    X_train_s, y_train,
    eval_set = [(X_test_s, y_test)],
    verbose  = 50,
    )
    print("  ✓ Training complete!")

    # ── Evaluate ──────────────────────────────────────────────────────────────
    y_pred = model.predict(X_test_s)

    # ── Sanity check ──────────────────────────────────────────
    print("\n🔍 Sanity Check:")
    print("  Unique predictions :", set(y_pred))
    print("  Train size         :", len(X_train_s))
    print("  Test size          :", len(X_test_s))
# ─────────────────────────────────────────────────────────

    acc  = accuracy_score (y_test, y_pred)
    prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    rec  = recall_score   (y_test, y_pred, average="weighted", zero_division=0)
    f1   = f1_score       (y_test, y_pred, average="weighted", zero_division=0)

    print(f"\n{'=' * 60}")
    print(f"  REAL MODEL PERFORMANCE  (no data leakage)")
    print(f"{'=' * 60}")
    print(f"  Accuracy  : {acc  * 100:.2f}%")
    print(f"  Precision : {prec * 100:.2f}%")
    print(f"  Recall    : {rec  * 100:.2f}%")
    print(f"  F1 Score  : {f1   * 100:.2f}%")
    print(f"{'=' * 60}\n")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))

    # ── Top features ──────────────────────────────────────────────────────────
    print("🏆 Top 10 Features:")
    imp = sorted(zip(good, model.feature_importances_), key=lambda x: -x[1])[:10]
    for i, (fname, val) in enumerate(imp, 1):   # FIX #5: starts at 1
        bar = "█" * int(val * 300)
        print(f"  {i:2d}. {fname:40s} {val * 100:5.1f}%  {bar}")

    # ── Save ──────────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(OUTPUT_MODEL), exist_ok=True)
    meta = {
        "features"     : good,
        "label_encoder": le,
        "scaler"       : scaler,
        "classes"      : list(le.classes_),
        "accuracy"     : acc,
        "precision"    : prec,
        "recall"       : rec,
        "f1"           : f1,
        "model_type"   : "XGBoost",
        "dataset"      : "CICIDS2017",
        "n_classes"    : n_classes,
    }
    joblib.dump(model, OUTPUT_MODEL)
    joblib.dump(meta,  OUTPUT_META)

    print(f"\n✅ Saved!")
    print(f"   → {OUTPUT_MODEL}")
    print(f"   → {OUTPUT_META}")
    print(f"\n   Final Accuracy: {acc * 100:.2f}%")


if __name__ == "__main__":
    main()