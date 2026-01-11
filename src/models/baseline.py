"""
Baseline machine learning model for vulnerability detection.

Uses traditional ML algorithms (Random Forest, XGBoost) on
hand-crafted features extracted from source code.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)

from ..utils.config import get_config
from ..utils.logger import get_logger
from ..features.code_features import CodeFeatureExtractor
from ..features.ast_features import ASTFeatureExtractor
from ..features.pattern_detector import PatternDetector


class BaselineModel:
    """
    Baseline vulnerability detection model using Random Forest.

    This model extracts hand-crafted features from source code and
    uses traditional machine learning for classification.
    """

    def __init__(self, model_type: str = "random_forest"):
        """
        Initialize the baseline model.

        Args:
            model_type: Type of model ("random_forest" or "gradient_boosting")
        """
        self.config = get_config()
        self.logger = get_logger("baseline_model")

        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names: List[str] = []

        # Feature extractors
        self.code_extractor = CodeFeatureExtractor()
        self.ast_extractor = ASTFeatureExtractor()
        self.pattern_detector = PatternDetector()

        self._init_model()

    def _init_model(self) -> None:
        """Initialize the underlying ML model."""
        model_config = self.config.get("models.baseline", {})

        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=model_config.get("n_estimators", 200),
                max_depth=model_config.get("max_depth", 20),
                min_samples_split=model_config.get("min_samples_split", 5),
                min_samples_leaf=model_config.get("min_samples_leaf", 2),
                class_weight=model_config.get("class_weight", "balanced"),
                random_state=model_config.get("random_state", 42),
                n_jobs=-1,
            )
        elif self.model_type == "gradient_boosting":
            self.model = GradientBoostingClassifier(
                n_estimators=model_config.get("n_estimators", 200),
                max_depth=model_config.get("max_depth", 10),
                learning_rate=0.1,
                random_state=model_config.get("random_state", 42),
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")

        self.logger.info(f"Initialized {self.model_type} model")

    def extract_features(
        self,
        code: str,
        language: str = "auto"
    ) -> Dict[str, float]:
        """
        Extract all features from a code sample.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            Dictionary of feature names to values
        """
        features = {}

        # Code complexity features
        code_features = self.code_extractor.extract_features(code, language)
        features.update({f"code_{k}": v for k, v in code_features.items()})

        # AST-based features
        ast_features = self.ast_extractor.extract_features(code, language)
        features.update({f"ast_{k}": v for k, v in ast_features.items()})

        # Pattern-based features
        matches = self.pattern_detector.detect(code, language)
        pattern_features = self.pattern_detector.to_features(matches)
        features.update({f"pattern_{k}": v for k, v in pattern_features.items()})

        return features

    def prepare_features(
        self,
        codes: List[str],
        language: str = "auto"
    ) -> np.ndarray:
        """
        Extract and prepare features for a batch of code samples.

        Args:
            codes: List of source code strings
            language: Programming language

        Returns:
            NumPy array of features (n_samples, n_features)
        """
        all_features = []

        for code in codes:
            features = self.extract_features(code, language)
            all_features.append(features)

        # Get consistent feature names
        if not self.feature_names:
            self.feature_names = sorted(all_features[0].keys())

        # Convert to array
        X = np.array([
            [f.get(name, 0) for name in self.feature_names]
            for f in all_features
        ], dtype=np.float32)

        return X

    def fit(
        self,
        X: Union[np.ndarray, List[str]],
        y: np.ndarray,
        language: str = "auto"
    ) -> "BaselineModel":
        """
        Train the model on labeled data.

        Args:
            X: Feature array or list of code strings
            y: Binary labels (0 = safe, 1 = vulnerable)
            language: Programming language (if X is code strings)

        Returns:
            self
        """
        # Extract features if given code strings
        if isinstance(X, list) and isinstance(X[0], str):
            self.logger.info("Extracting features from code samples...")
            X = self.prepare_features(X, language)

        # Scale features
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.logger.info(f"Training {self.model_type} on {len(y)} samples...")
        self.model.fit(X_scaled, y)

        # Log training metrics
        train_pred = self.model.predict(X_scaled)
        train_acc = accuracy_score(y, train_pred)
        self.logger.info(f"Training accuracy: {train_acc:.4f}")

        return self

    def predict(
        self,
        X: Union[np.ndarray, List[str], str],
        language: str = "auto"
    ) -> np.ndarray:
        """
        Predict vulnerability labels for code samples.

        Args:
            X: Feature array, list of code strings, or single code string
            language: Programming language

        Returns:
            Array of predictions (0 = safe, 1 = vulnerable)
        """
        # Handle single code string
        if isinstance(X, str):
            X = [X]

        # Extract features if given code strings
        if isinstance(X, list) and isinstance(X[0], str):
            X = self.prepare_features(X, language)

        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def predict_proba(
        self,
        X: Union[np.ndarray, List[str], str],
        language: str = "auto"
    ) -> np.ndarray:
        """
        Predict vulnerability probabilities for code samples.

        Args:
            X: Feature array, list of code strings, or single code string
            language: Programming language

        Returns:
            Array of probabilities (n_samples, 2)
        """
        if isinstance(X, str):
            X = [X]

        if isinstance(X, list) and isinstance(X[0], str):
            X = self.prepare_features(X, language)

        X_scaled = self.scaler.transform(X)
        return self.model.predict_proba(X_scaled)

    def evaluate(
        self,
        X: Union[np.ndarray, List[str]],
        y: np.ndarray,
        language: str = "auto"
    ) -> Dict[str, float]:
        """
        Evaluate the model on test data.

        Args:
            X: Feature array or list of code strings
            y: True labels
            language: Programming language

        Returns:
            Dictionary of evaluation metrics
        """
        if isinstance(X, list) and isinstance(X[0], str):
            X = self.prepare_features(X, language)

        X_scaled = self.scaler.transform(X)

        y_pred = self.model.predict(X_scaled)
        y_proba = self.model.predict_proba(X_scaled)[:, 1]

        metrics = {
            "accuracy": accuracy_score(y, y_pred),
            "precision": precision_score(y, y_pred, zero_division=0),
            "recall": recall_score(y, y_pred, zero_division=0),
            "f1": f1_score(y, y_pred, zero_division=0),
            "roc_auc": roc_auc_score(y, y_proba) if len(np.unique(y)) > 1 else 0.5,
        }

        self.logger.info(f"Evaluation metrics: {metrics}")
        return metrics

    def get_feature_importance(self) -> Dict[str, float]:
        """
        Get feature importance scores.

        Returns:
            Dictionary of feature names to importance scores
        """
        if hasattr(self.model, "feature_importances_"):
            importance = self.model.feature_importances_
            return dict(zip(self.feature_names, importance))
        return {}

    def save(self, path: str) -> None:
        """
        Save the model to disk.

        Args:
            path: Path to save the model
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "model_type": self.model_type,
        }

        joblib.dump(model_data, path)
        self.logger.info(f"Model saved to {path}")

    def load(self, path: str) -> "BaselineModel":
        """
        Load a model from disk.

        Args:
            path: Path to the saved model

        Returns:
            self
        """
        model_data = joblib.load(path)

        self.model = model_data["model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.model_type = model_data["model_type"]

        self.logger.info(f"Model loaded from {path}")
        return self

    def analyze_code(
        self,
        code: str,
        language: str = "auto"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a code sample.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            Dictionary with prediction, confidence, features, and patterns
        """
        # Get prediction
        proba = self.predict_proba(code, language)[0]
        prediction = int(proba[1] > 0.5)
        confidence = float(proba[prediction])

        # Get features
        features = self.extract_features(code, language)

        # Get pattern matches
        matches = self.pattern_detector.detect(code, language)

        return {
            "vulnerable": bool(prediction),
            "confidence": confidence,
            "vulnerability_probability": float(proba[1]),
            "features": features,
            "pattern_matches": [
                {
                    "name": m.pattern_name,
                    "type": m.vulnerability_type,
                    "severity": m.severity,
                    "line": m.line_number,
                    "cwe": m.cwe_id,
                    "description": m.description,
                    "fix": m.fix_suggestion,
                }
                for m in matches
            ],
            "feature_importance": self.get_feature_importance(),
        }
