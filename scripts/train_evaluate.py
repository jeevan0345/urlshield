"""
Model Training and Rigorous Evaluation Pipeline for URLShield.
Trains Logistic Regression and Random Forest baselines with Group-aware CV on domains.
Evaluates Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix, and Calibration.
Saves winning pipeline with joblib, model metadata, and feature schema.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    brier_score_loss,
)
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.core.feature_extractor import FEATURE_NAMES, extract_features_from_url, features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_evaluate")

DATA_DIR = PROJECT_ROOT / "data" / "processed"
MODELS_DIR = PROJECT_ROOT / "models"


def load_and_extract_features(csv_path: Path):
    """Load URLs from CSV and compute feature matrices."""
    logger.info("Loading %s and extracting features...", csv_path)
    df = pd.read_csv(csv_path)

    feature_rows = []
    valid_indices = []
    for idx, row in df.iterrows():
        try:
            feats = extract_features_from_url(str(row["url"]))
            feature_rows.append(features_to_vector(feats))
            valid_indices.append(idx)
        except Exception as e:
            logger.warning("Feature extraction failed for row %d: %s", idx, e)

    df_valid = df.iloc[valid_indices].reset_index(drop=True)
    X = np.array(feature_rows, dtype=float)
    y = df_valid["label"].to_numpy(dtype=int)
    groups = df_valid["domain"].to_numpy()
    urls = df_valid["url"].to_list()
    return X, y, groups, urls, df_valid


def evaluate_cv(pipeline, X, y, groups, n_splits=5):
    """Run GroupKFold cross-validation on domains to prevent leakage."""
    gkf = GroupKFold(n_splits=n_splits)
    metrics = {
        "accuracy": [],
        "precision": [],
        "recall": [],
        "f1": [],
        "roc_auc": [],
        "pr_auc": [],
    }

    for fold, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups=groups)):
        X_train_f, X_val_f = X[train_idx], X[val_idx]
        y_train_f, y_val_f = y[train_idx], y[val_idx]

        pipeline.fit(X_train_f, y_train_f)
        y_pred = pipeline.predict(X_val_f)
        y_proba = pipeline.predict_proba(X_val_f)[:, 1]

        metrics["accuracy"].append(accuracy_score(y_val_f, y_pred))
        metrics["precision"].append(precision_score(y_val_f, y_pred, zero_division=0))
        metrics["recall"].append(recall_score(y_val_f, y_pred, zero_division=0))
        metrics["f1"].append(f1_score(y_val_f, y_pred, zero_division=0))
        metrics["roc_auc"].append(roc_auc_score(y_val_f, y_proba))
        metrics["pr_auc"].append(average_precision_score(y_val_f, y_proba))

    return {k: round(float(np.mean(v)), 4) for k, v in metrics.items()}


def train_and_evaluate():
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    train_path = DATA_DIR / "train.csv"
    test_path = DATA_DIR / "test.csv"

    if not train_path.exists() or not test_path.exists():
        logger.error("Train/test datasets missing. Run scripts/prepare_dataset.py first.")
        sys.exit(1)

    X_train, y_train, groups_train, urls_train, df_train = load_and_extract_features(train_path)
    X_test, y_test, groups_test, urls_test, df_test = load_and_extract_features(test_path)

    logger.info("Training set: %d samples (%d features), Test set: %d samples",
                X_train.shape[0], X_train.shape[1], X_test.shape[0])

    # 1. Baseline: Logistic Regression Pipeline
    lr_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=42, C=1.0))
    ])

    # 2. Baseline: Random Forest Pipeline
    rf_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            max_depth=14,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        ))
    ])

    logger.info("Running 5-Fold Group CV for Logistic Regression...")
    lr_cv = evaluate_cv(lr_pipeline, X_train, y_train, groups_train, n_splits=5)
    logger.info("Logistic Regression CV: %s", lr_cv)

    logger.info("Running 5-Fold Group CV for Random Forest...")
    rf_cv = evaluate_cv(rf_pipeline, X_train, y_train, groups_train, n_splits=5)
    logger.info("Random Forest CV: %s", rf_cv)

    # Model Selection: compare validation F1 and ROC-AUC
    models_comparison = {
        "LogisticRegression": lr_cv,
        "RandomForest": rf_cv,
    }

    if rf_cv["f1"] >= lr_cv["f1"]:
        chosen_name = "RandomForest"
        base_pipeline = rf_pipeline
    else:
        chosen_name = "LogisticRegression"
        base_pipeline = lr_pipeline

    logger.info("Chosen model architecture: %s (Validation F1: %.4f vs %.4f)",
                chosen_name, rf_cv["f1"], lr_cv["f1"])

    # Fit chosen base pipeline on full training set
    base_pipeline.fit(X_train, y_train)

    # Probability Calibration
    calibrated_clf = CalibratedClassifierCV(
        estimator=base_pipeline,
        method="sigmoid",
        cv="prefit"
    )
    calibrated_clf.fit(X_train, y_train)

    # Single Final Evaluation on Held-Out Test Set
    logger.info("Evaluating chosen calibrated pipeline on held-out test data...")
    test_preds = calibrated_clf.predict(X_test)
    test_probas = calibrated_clf.predict_proba(X_test)[:, 1]

    test_acc = accuracy_score(y_test, test_preds)
    test_prec = precision_score(y_test, test_preds, zero_division=0)
    test_rec = recall_score(y_test, test_preds, zero_division=0)
    test_f1 = f1_score(y_test, test_preds, zero_division=0)
    test_roc_auc = roc_auc_score(y_test, test_probas)
    test_pr_auc = average_precision_score(y_test, test_probas)
    test_brier = brier_score_loss(y_test, test_probas)
    cm = confusion_matrix(y_test, test_preds)

    # False Positives and False Negatives examples
    fps = []
    fns = []
    for u, actual, pred, p in zip(urls_test, y_test, test_preds, test_probas):
        if actual == 0 and pred == 1:
            fps.append({"url": u, "prob": round(float(p), 4)})
        elif actual == 1 and pred == 0:
            fns.append({"url": u, "prob": round(float(p), 4)})

    # Feature Importance analysis
    feature_importances = {}
    if chosen_name == "RandomForest":
        importances = base_pipeline.named_steps["classifier"].feature_importances_
        for name, imp in zip(FEATURE_NAMES, importances):
            feature_importances[name] = round(float(imp), 4)
    else:
        coefs = base_pipeline.named_steps["classifier"].coef_[0]
        for name, coef in zip(FEATURE_NAMES, coefs):
            feature_importances[name] = round(float(coef), 4)

    # Sort feature importances descending
    sorted_importances = dict(sorted(feature_importances.items(), key=lambda x: abs(x[1]), reverse=True))

    test_metrics = {
        "accuracy": round(float(test_acc), 4),
        "precision": round(float(test_prec), 4),
        "recall": round(float(test_rec), 4),
        "f1": round(float(test_f1), 4),
        "roc_auc": round(float(test_roc_auc), 4),
        "pr_auc": round(float(test_pr_auc), 4),
        "brier_score": round(float(test_brier), 4),
        "confusion_matrix": {
            "true_negatives": int(cm[0, 0]),
            "false_positives": int(cm[0, 1]),
            "false_negatives": int(cm[1, 0]),
            "true_positives": int(cm[1, 1]),
        },
        "sample_counts": {
            "test_total": len(y_test),
            "test_legitimate": int(np.sum(y_test == 0)),
            "test_phishing": int(np.sum(y_test == 1)),
        },
        "false_positive_examples": fps[:5],
        "false_negative_examples": fns[:5],
    }

    logger.info("=== HELD-OUT TEST EVALUATION METRICS ===")
    logger.info("Accuracy:  %.4f", test_metrics["accuracy"])
    logger.info("Precision: %.4f", test_metrics["precision"])
    logger.info("Recall:    %.4f", test_metrics["recall"])
    logger.info("F1 Score:  %.4f", test_metrics["f1"])
    logger.info("ROC-AUC:   %.4f", test_metrics["roc_auc"])
    logger.info("PR-AUC:    %.4f", test_metrics["pr_auc"])
    logger.info("Confusion Matrix: TN=%d, FP=%d, FN=%d, TP=%d",
                cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 1])

    # Save fitted calibrated model
    model_save_path = MODELS_DIR / "phishing_model.joblib"
    joblib.dump(calibrated_clf, model_save_path)
    logger.info("Saved fitted calibrated pipeline to %s", model_save_path)

    # Save feature schema
    feature_stats = {}
    for i, col in enumerate(FEATURE_NAMES):
        vals = X_train[:, i]
        feature_stats[col] = {
            "index": i,
            "mean": round(float(np.mean(vals)), 4),
            "std": round(float(np.std(vals)), 4),
            "min": round(float(np.min(vals)), 4),
            "max": round(float(np.max(vals)), 4),
        }

    schema = {
        "features": FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES),
        "feature_statistics": feature_stats,
    }
    with open(MODELS_DIR / "feature_schema.json", "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    # Save full model metadata
    model_metadata = {
        "model_name": "URLShield Phishing Detector",
        "model_version": "1.0.0",
        "chosen_algorithm": chosen_name,
        "calibration": "Platt Sigmoid Calibration (CalibratedClassifierCV)",
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
        "cross_validation": {
            "strategy": "5-Fold GroupKFold on registered domains",
            "models_comparison": models_comparison,
        },
        "test_metrics": test_metrics,
        "feature_importances": sorted_importances,
        "risk_thresholds": {
            "safe": {"min": 0.0, "max": 0.35, "label": "Low Risk (Legitimate)"},
            "suspicious": {"min": 0.35, "max": 0.70, "label": "Medium Risk (Suspicious)"},
            "phishing": {"min": 0.70, "max": 1.0, "label": "High Risk (Phishing)"},
        },
        "provenance": {
            "dataset_sources": "Tranco Top Sites + URLhaus / OpenPhish Feeds",
            "leakage_mitigation": "Domain grouping partition across folds",
        }
    }
    with open(MODELS_DIR / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(model_metadata, f, indent=2)

    logger.info("Saved model metadata to %s", MODELS_DIR / "model_metadata.json")
    print("\nTraining and evaluation finished successfully!")


if __name__ == "__main__":
    train_and_evaluate()
