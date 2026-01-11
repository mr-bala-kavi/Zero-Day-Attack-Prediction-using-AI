#!/usr/bin/env python3
"""
Evaluation script for vulnerability detection models.

Usage:
    python scripts/evaluate.py --model data/models/baseline_model.joblib --data test_data.csv
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    precision_recall_curve,
    roc_curve,
)

from src.utils.logger import setup_logger
from src.data.dataset import SyntheticVulnerabilityDataset


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate vulnerability detection models")
    parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Path to trained model",
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="Path to test data CSV (if not provided, uses synthetic data)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="evaluation_results.json",
        help="Output file for evaluation results",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification threshold",
    )
    return parser.parse_args()


def load_model(model_path: str):
    """Load a trained model from disk."""
    logger = setup_logger("evaluate")
    model_path = Path(model_path)

    if model_path.suffix == ".joblib":
        from src.models.baseline import BaselineModel
        model = BaselineModel()
        model.load(str(model_path))
        logger.info(f"Loaded baseline model from {model_path}")
        return model

    elif model_path.is_dir():
        if (model_path / "encoder").exists():
            from src.models.codebert_model import CodeBERTModel
            model = CodeBERTModel()
            model.load(str(model_path))
            logger.info(f"Loaded CodeBERT model from {model_path}")
            return model
        elif (model_path / "ensemble_config.json").exists():
            from src.models.ensemble import EnsembleModel
            model = EnsembleModel()
            model.load(str(model_path))
            logger.info(f"Loaded ensemble model from {model_path}")
            return model

    raise ValueError(f"Could not determine model type from path: {model_path}")


def evaluate_model(model, codes, labels, threshold=0.5):
    """Compute comprehensive evaluation metrics."""
    # Get predictions
    proba = model.predict_proba(codes)
    if len(proba.shape) == 1:
        proba_positive = proba
    else:
        proba_positive = proba[:, 1]

    predictions = (proba_positive > threshold).astype(int)

    # Basic metrics
    metrics = {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
    }

    # ROC-AUC (if both classes present)
    if len(np.unique(labels)) > 1:
        metrics["roc_auc"] = float(roc_auc_score(labels, proba_positive))

        # Compute ROC curve points
        fpr, tpr, roc_thresholds = roc_curve(labels, proba_positive)
        metrics["roc_curve"] = {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
        }

        # Compute PR curve points
        precision_curve, recall_curve, pr_thresholds = precision_recall_curve(labels, proba_positive)
        metrics["pr_curve"] = {
            "precision": precision_curve.tolist(),
            "recall": recall_curve.tolist(),
        }

    # Confusion matrix
    cm = confusion_matrix(labels, predictions)
    metrics["confusion_matrix"] = cm.tolist()

    # Per-class metrics
    report = classification_report(labels, predictions, output_dict=True, zero_division=0)
    metrics["classification_report"] = report

    # Threshold analysis
    thresholds = np.arange(0.1, 1.0, 0.1)
    threshold_metrics = []
    for t in thresholds:
        t_pred = (proba_positive > t).astype(int)
        threshold_metrics.append({
            "threshold": float(t),
            "precision": float(precision_score(labels, t_pred, zero_division=0)),
            "recall": float(recall_score(labels, t_pred, zero_division=0)),
            "f1": float(f1_score(labels, t_pred, zero_division=0)),
        })
    metrics["threshold_analysis"] = threshold_metrics

    return metrics


def print_report(metrics):
    """Print a formatted evaluation report."""
    print("\n" + "=" * 60)
    print("EVALUATION REPORT")
    print("=" * 60)

    print(f"\nOverall Metrics:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    if "roc_auc" in metrics:
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")

    print(f"\nConfusion Matrix:")
    cm = np.array(metrics["confusion_matrix"])
    print(f"  TN: {cm[0, 0]:5d}  FP: {cm[0, 1]:5d}")
    print(f"  FN: {cm[1, 0]:5d}  TP: {cm[1, 1]:5d}")

    print(f"\nThreshold Analysis:")
    print(f"  {'Threshold':>10} {'Precision':>10} {'Recall':>10} {'F1':>10}")
    print("  " + "-" * 42)
    for t in metrics["threshold_analysis"]:
        print(f"  {t['threshold']:>10.2f} {t['precision']:>10.4f} {t['recall']:>10.4f} {t['f1']:>10.4f}")

    print("\n" + "=" * 60)


def main():
    args = parse_args()
    logger = setup_logger("evaluate", level="INFO")

    logger.info("Loading model...")
    model = load_model(args.model)

    logger.info("Loading test data...")
    if args.data and Path(args.data).exists():
        df = pd.read_csv(args.data)
    else:
        logger.info("Generating synthetic test data...")
        generator = SyntheticVulnerabilityDataset()
        df = generator.generate_full_dataset(samples_per_type=100)

    codes = df["code"].tolist()
    labels = df["vulnerable"].values

    logger.info(f"Evaluating on {len(codes)} samples...")
    metrics = evaluate_model(model, codes, labels, threshold=args.threshold)

    # Print report
    print_report(metrics)

    # Save results
    with open(args.output, "w") as f:
        # Convert numpy arrays to lists for JSON serialization
        json.dump(metrics, f, indent=2)
    logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
