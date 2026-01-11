#!/usr/bin/env python3
"""
Training script for vulnerability detection models.

Usage:
    python scripts/train.py --model baseline
    python scripts/train.py --model codebert
    python scripts/train.py --model ensemble
"""

import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import numpy as np
import pandas as pd

from src.utils.config import get_config
from src.utils.logger import setup_logger
from src.data.dataset import SyntheticVulnerabilityDataset, VulnerabilityDataset, create_dataloaders
from src.models.baseline import BaselineModel
from src.models.ensemble import EnsembleModel


def parse_args():
    parser = argparse.ArgumentParser(description="Train vulnerability detection models")
    parser.add_argument(
        "--model",
        type=str,
        choices=["baseline", "codebert", "ensemble"],
        default="baseline",
        help="Model type to train",
    )
    parser.add_argument(
        "--data",
        type=str,
        default=None,
        help="Path to training data CSV (if not provided, uses synthetic data)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/models",
        help="Output directory for trained model",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=500,
        help="Number of synthetic samples per vulnerability type",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=10,
        help="Number of training epochs (for deep learning models)",
    )
    return parser.parse_args()


def load_or_generate_data(data_path: str, samples_per_type: int):
    """Load data from CSV or generate synthetic data."""
    logger = setup_logger("train")

    if data_path and Path(data_path).exists():
        logger.info(f"Loading data from {data_path}")
        df = pd.read_csv(data_path)
    else:
        logger.info(f"Generating synthetic dataset with {samples_per_type} samples per type")
        generator = SyntheticVulnerabilityDataset()
        df = generator.generate_full_dataset(samples_per_type)

    logger.info(f"Dataset size: {len(df)} samples")
    logger.info(f"Vulnerable: {df['vulnerable'].sum()}, Safe: {(~df['vulnerable'].astype(bool)).sum()}")

    return df


def train_baseline(df: pd.DataFrame, output_dir: str):
    """Train baseline Random Forest model."""
    logger = setup_logger("train")
    logger.info("Training baseline model...")

    # Prepare data
    codes = df["code"].tolist()
    labels = df["vulnerable"].values

    # Train model
    model = BaselineModel(model_type="random_forest")
    model.fit(codes, labels)

    # Evaluate on training data (for sanity check)
    metrics = model.evaluate(codes, labels)
    logger.info(f"Training metrics: {metrics}")

    # Save model
    output_path = Path(output_dir) / "baseline_model.joblib"
    model.save(str(output_path))
    logger.info(f"Model saved to {output_path}")

    # Log feature importance
    importance = model.get_feature_importance()
    top_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
    logger.info("Top 10 important features:")
    for name, imp in top_features:
        logger.info(f"  {name}: {imp:.4f}")

    return model, metrics


def train_codebert(df: pd.DataFrame, output_dir: str, epochs: int):
    """Train CodeBERT model."""
    logger = setup_logger("train")
    logger.info("Training CodeBERT model...")

    try:
        from src.models.codebert_model import CodeBERTModel

        # Initialize model (this will load the tokenizer)
        model = CodeBERTModel()
        model._load_model()

        # Create dataset and dataloaders
        dataset = VulnerabilityDataset(
            df,
            code_column="code",
            label_column="vulnerable",
            tokenizer=model.tokenizer,
            max_length=model.max_length,
        )

        train_loader, val_loader, test_loader = create_dataloaders(
            dataset,
            batch_size=model.batch_size,
        )

        # Train
        history = model.fit(train_loader, val_loader, epochs=epochs)

        # Evaluate on test set
        codes = df["code"].tolist()
        labels = df["vulnerable"].values
        metrics = model.evaluate(codes, labels)
        logger.info(f"Test metrics: {metrics}")

        # Save model
        output_path = Path(output_dir) / "codebert_model"
        model.save(str(output_path))
        logger.info(f"Model saved to {output_path}")

        return model, metrics

    except ImportError as e:
        logger.error(f"Could not train CodeBERT: {e}")
        logger.error("Make sure transformers is installed: pip install transformers")
        return None, {}


def train_ensemble(df: pd.DataFrame, output_dir: str):
    """Train ensemble model."""
    logger = setup_logger("train")
    logger.info("Training ensemble model...")

    # Prepare data
    codes = df["code"].tolist()
    labels = df["vulnerable"].values

    # Create ensemble (patterns only for now, as CodeBERT requires more setup)
    model = EnsembleModel(
        use_baseline=True,
        use_codebert=False,  # Set to True if transformers is available
        use_patterns=True,
    )

    # Train
    model.fit(codes, labels)

    # Evaluate
    metrics = model.evaluate(codes, labels)
    logger.info(f"Ensemble metrics: {metrics}")

    # Save
    output_path = Path(output_dir) / "ensemble_model"
    model.save(str(output_path))
    logger.info(f"Model saved to {output_path}")

    return model, metrics


def main():
    args = parse_args()
    logger = setup_logger("train", level="INFO")

    logger.info("=" * 60)
    logger.info("Zero-Day Vulnerability Prediction - Training")
    logger.info("=" * 60)

    # Load or generate data
    df = load_or_generate_data(args.data, args.samples)

    # Create output directory
    Path(args.output).mkdir(parents=True, exist_ok=True)

    # Train selected model
    if args.model == "baseline":
        model, metrics = train_baseline(df, args.output)
    elif args.model == "codebert":
        model, metrics = train_codebert(df, args.output, args.epochs)
    elif args.model == "ensemble":
        model, metrics = train_ensemble(df, args.output)

    logger.info("=" * 60)
    logger.info("Training Complete!")
    logger.info(f"Final Metrics: {metrics}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
