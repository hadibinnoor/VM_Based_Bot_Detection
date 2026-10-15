"""
Train RandomForest from a persisted CSV dataset.

Run:
    python3 train_model.py

Expected input:
    ml/data/synthetic_bot_dataset.csv

Outputs:
    ml/rf_model.pkl
    ml/train_metrics.json
"""

from __future__ import annotations

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import cross_val_score, train_test_split

# Ensure sibling features.py is importable when this script is invoked
# from a different working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURE_NAMES  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "rf_model.pkl")
METRICS_PATH = os.path.join(HERE, "train_metrics.json")
DATASET_PATH = os.path.join(HERE, "data", "synthetic_bot_dataset.csv")
# ─── Training ─────────────────────────────────────────────────────────────────


def load_training_dataframe() -> pd.DataFrame:
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}. Persist the CSV first."
        )
    df = pd.read_csv(DATASET_PATH)
    required = set(FEATURE_NAMES + ["label"])
    missing = sorted(required.difference(df.columns))
    if missing:
        raise ValueError(f"dataset missing required columns: {missing}")
    return df


def split_dataset(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    X = df[FEATURE_NAMES].values.astype(np.float64)
    y = df["label"].values.astype(int)

    # If generator includes a synthetic timeline bucket, use it as an
    # out-of-time holdout to reduce optimistic leakage from random shuffling.
    if "time_bucket" in df.columns:
        test_mask = df["time_bucket"] >= 80
        if test_mask.sum() > 200 and (~test_mask).sum() > 1000:
            X_train, y_train = X[~test_mask], y[~test_mask]
            X_test, y_test = X[test_mask], y[test_mask]
            return X_train, X_test, y_train, y_test

    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


def train() -> None:
    df = load_training_dataframe()
    X_train, X_test, y_train, y_test = split_dataset(df)
    X = df[FEATURE_NAMES].values.astype(np.float64)
    y = df["label"].values.astype(int)

    model = RandomForestClassifier(
        n_estimators=450,
        max_depth=12,
        min_samples_split=8,
        min_samples_leaf=4,
        max_features="sqrt",
        class_weight="balanced",
        bootstrap=True,
        oob_score=True,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    bar = "=" * 60
    print(bar)
    print("TRAINING COMPLETE")
    print(bar)
    print(f"OOB score : {model.oob_score_:.4f}")
    print(f"AUC-ROC   : {roc_auc_score(y_test, y_prob):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=["Human", "Bot"]))
    print("Confusion matrix:")
    print(confusion_matrix(y_test, y_pred))
    print()
    print("Top 10 feature importances:")
    importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_),
        key=lambda x: x[1],
        reverse=True,
    )
    for name, imp in importances[:10]:
        bar_str = "#" * int(imp * 200)
        print(f"  {name:<25s} {imp:.4f}  {bar_str}")

    print()
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="roc_auc", n_jobs=-1)
    print(f"5-fold CV AUC: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f}")

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved: {MODEL_PATH}")

    metrics = {
        "dataset_path": DATASET_PATH,
        "n_rows": int(len(df)),
        "n_train": int(len(y_train)),
        "n_test": int(len(y_test)),
        "oob_score": float(model.oob_score_),
        "auc_roc": float(roc_auc_score(y_test, y_prob)),
        "cv_auc_mean": float(cv_scores.mean()),
        "cv_auc_std": float(cv_scores.std()),
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved: {METRICS_PATH}")


if __name__ == "__main__":
    train()
