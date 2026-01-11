"""
Ensemble model combining multiple vulnerability detection approaches.

Combines predictions from baseline ML, CodeBERT, and pattern-based
detection for improved accuracy.
"""

from typing import Any, Dict, List, Optional, Union

import numpy as np

from ..utils.config import get_config
from ..utils.logger import get_logger
from .baseline import BaselineModel
from ..features.pattern_detector import PatternDetector


class EnsembleModel:
    """
    Ensemble model for vulnerability detection.

    Combines multiple models and detection strategies:
    1. Baseline ML model (Random Forest on features)
    2. CodeBERT model (transformer on code)
    3. Pattern-based detection (rule matching)
    """

    def __init__(
        self,
        use_baseline: bool = True,
        use_codebert: bool = True,
        use_patterns: bool = True,
        weights: Optional[Dict[str, float]] = None,
    ):
        """
        Initialize the ensemble model.

        Args:
            use_baseline: Include baseline ML model
            use_codebert: Include CodeBERT model
            use_patterns: Include pattern-based detection
            weights: Custom weights for each model
        """
        self.config = get_config()
        self.logger = get_logger("ensemble_model")

        self.use_baseline = use_baseline
        self.use_codebert = use_codebert
        self.use_patterns = use_patterns

        # Default weights
        self.weights = weights or {
            "baseline": 0.4,
            "codebert": 0.4,
            "patterns": 0.2,
        }

        # Models
        self.baseline_model = None
        self.codebert_model = None
        self.pattern_detector = PatternDetector()

        self._init_models()

    def _init_models(self) -> None:
        """Initialize component models."""
        if self.use_baseline:
            self.baseline_model = BaselineModel()
            self.logger.info("Baseline model initialized")

        if self.use_codebert:
            try:
                from .codebert_model import CodeBERTModel
                self.codebert_model = CodeBERTModel()
                self.logger.info("CodeBERT model initialized")
            except ImportError:
                self.logger.warning("CodeBERT not available, disabling")
                self.use_codebert = False
                self.weights["codebert"] = 0

        # Normalize weights
        total_weight = sum(
            w for k, w in self.weights.items()
            if (k == "baseline" and self.use_baseline) or
               (k == "codebert" and self.use_codebert) or
               (k == "patterns" and self.use_patterns)
        )
        if total_weight > 0:
            for k in self.weights:
                self.weights[k] /= total_weight

    def fit(
        self,
        codes: List[str],
        labels: np.ndarray,
        language: str = "auto",
    ) -> "EnsembleModel":
        """
        Train all component models.

        Args:
            codes: List of code strings
            labels: Binary labels
            language: Programming language

        Returns:
            self
        """
        if self.use_baseline:
            self.logger.info("Training baseline model...")
            self.baseline_model.fit(codes, labels, language)

        if self.use_codebert:
            self.logger.info("Training CodeBERT model...")
            # For CodeBERT, we need to create a proper dataset and dataloader
            from ..data.dataset import VulnerabilityDataset, create_dataloaders
            import pandas as pd

            df = pd.DataFrame({"code": codes, "vulnerable": labels})
            dataset = VulnerabilityDataset(
                df,
                code_column="code",
                label_column="vulnerable",
                tokenizer=self.codebert_model.tokenizer if self.codebert_model else None,
            )
            train_loader, val_loader, _ = create_dataloaders(dataset)
            self.codebert_model.fit(train_loader, val_loader)

        self.logger.info("Ensemble training complete")
        return self

    def predict(
        self,
        codes: Union[str, List[str]],
        language: str = "auto",
        threshold: float = 0.5,
    ) -> np.ndarray:
        """
        Predict vulnerability labels.

        Args:
            codes: Single code string or list of code strings
            language: Programming language
            threshold: Classification threshold

        Returns:
            Array of predictions
        """
        proba = self.predict_proba(codes, language)
        return (proba[:, 1] > threshold).astype(int)

    def predict_proba(
        self,
        codes: Union[str, List[str]],
        language: str = "auto",
    ) -> np.ndarray:
        """
        Predict vulnerability probabilities.

        Args:
            codes: Single code string or list of code strings
            language: Programming language

        Returns:
            Array of probabilities (n_samples, 2)
        """
        if isinstance(codes, str):
            codes = [codes]

        n_samples = len(codes)
        ensemble_proba = np.zeros((n_samples, 2))

        # Baseline model predictions
        if self.use_baseline and self.baseline_model:
            try:
                baseline_proba = self.baseline_model.predict_proba(codes, language)
                ensemble_proba += self.weights["baseline"] * baseline_proba
            except Exception as e:
                self.logger.warning(f"Baseline prediction failed: {e}")

        # CodeBERT predictions
        if self.use_codebert and self.codebert_model:
            try:
                codebert_proba = self.codebert_model.predict_proba(codes)
                ensemble_proba += self.weights["codebert"] * codebert_proba
            except Exception as e:
                self.logger.warning(f"CodeBERT prediction failed: {e}")

        # Pattern-based predictions
        if self.use_patterns:
            pattern_proba = np.zeros((n_samples, 2))
            for i, code in enumerate(codes):
                matches = self.pattern_detector.detect(code, language)
                score = self.pattern_detector.get_vulnerability_score(matches)
                pattern_proba[i, 1] = score
                pattern_proba[i, 0] = 1 - score
            ensemble_proba += self.weights["patterns"] * pattern_proba

        # Normalize probabilities
        row_sums = ensemble_proba.sum(axis=1, keepdims=True)
        ensemble_proba = np.divide(
            ensemble_proba,
            row_sums,
            where=row_sums != 0,
            out=np.full_like(ensemble_proba, 0.5),
        )

        return ensemble_proba

    def analyze_code(
        self,
        code: str,
        language: str = "auto",
    ) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a code sample.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            Comprehensive analysis dictionary
        """
        result = {
            "vulnerable": False,
            "confidence": 0.0,
            "vulnerability_probability": 0.0,
            "model_predictions": {},
            "pattern_matches": [],
            "recommendations": [],
        }

        # Ensemble prediction
        proba = self.predict_proba(code, language)[0]
        result["vulnerable"] = bool(proba[1] > 0.5)
        result["vulnerability_probability"] = float(proba[1])
        result["confidence"] = float(proba[1] if result["vulnerable"] else proba[0])

        # Individual model predictions
        if self.use_baseline and self.baseline_model:
            try:
                baseline_proba = self.baseline_model.predict_proba(code, language)[0]
                result["model_predictions"]["baseline"] = {
                    "vulnerable": bool(baseline_proba[1] > 0.5),
                    "probability": float(baseline_proba[1]),
                }
            except Exception as e:
                self.logger.warning(f"Baseline analysis failed: {e}")

        if self.use_codebert and self.codebert_model:
            try:
                codebert_proba = self.codebert_model.predict_proba(code)[0]
                result["model_predictions"]["codebert"] = {
                    "vulnerable": bool(codebert_proba[1] > 0.5),
                    "probability": float(codebert_proba[1]),
                }
            except Exception as e:
                self.logger.warning(f"CodeBERT analysis failed: {e}")

        # Pattern matches
        matches = self.pattern_detector.detect(code, language)
        result["pattern_matches"] = [
            {
                "name": m.pattern_name,
                "type": m.vulnerability_type,
                "severity": m.severity,
                "line": m.line_number,
                "code": m.code_snippet,
                "cwe": m.cwe_id,
                "description": m.description,
                "fix": m.fix_suggestion,
            }
            for m in matches
        ]

        # Generate recommendations
        if result["vulnerable"]:
            result["recommendations"].append(
                "Code review recommended - potential vulnerability detected"
            )
            for match in matches:
                if match.fix_suggestion:
                    result["recommendations"].append(
                        f"Line {match.line_number}: {match.fix_suggestion}"
                    )

        return result

    def evaluate(
        self,
        codes: List[str],
        labels: np.ndarray,
        language: str = "auto",
    ) -> Dict[str, float]:
        """
        Evaluate the ensemble on test data.

        Args:
            codes: List of code strings
            labels: True labels
            language: Programming language

        Returns:
            Dictionary of evaluation metrics
        """
        predictions = self.predict(codes, language)
        proba = self.predict_proba(codes, language)[:, 1]

        from sklearn.metrics import (
            accuracy_score,
            precision_score,
            recall_score,
            f1_score,
            roc_auc_score,
        )

        metrics = {
            "accuracy": accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "roc_auc": roc_auc_score(labels, proba) if len(np.unique(labels)) > 1 else 0.5,
        }

        self.logger.info(f"Ensemble evaluation: {metrics}")
        return metrics

    def save(self, path: str) -> None:
        """Save all component models."""
        from pathlib import Path
        import json

        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        # Save config
        config = {
            "use_baseline": self.use_baseline,
            "use_codebert": self.use_codebert,
            "use_patterns": self.use_patterns,
            "weights": self.weights,
        }
        with open(path / "ensemble_config.json", "w") as f:
            json.dump(config, f)

        # Save component models
        if self.use_baseline and self.baseline_model:
            self.baseline_model.save(path / "baseline.joblib")

        if self.use_codebert and self.codebert_model:
            self.codebert_model.save(path / "codebert")

        self.logger.info(f"Ensemble saved to {path}")

    def load(self, path: str) -> "EnsembleModel":
        """Load all component models."""
        from pathlib import Path
        import json

        path = Path(path)

        # Load config
        with open(path / "ensemble_config.json", "r") as f:
            config = json.load(f)

        self.use_baseline = config["use_baseline"]
        self.use_codebert = config["use_codebert"]
        self.use_patterns = config["use_patterns"]
        self.weights = config["weights"]

        # Load component models
        if self.use_baseline and (path / "baseline.joblib").exists():
            self.baseline_model = BaselineModel()
            self.baseline_model.load(path / "baseline.joblib")

        if self.use_codebert and (path / "codebert").exists():
            from .codebert_model import CodeBERTModel
            self.codebert_model = CodeBERTModel()
            self.codebert_model.load(path / "codebert")

        self.logger.info(f"Ensemble loaded from {path}")
        return self
