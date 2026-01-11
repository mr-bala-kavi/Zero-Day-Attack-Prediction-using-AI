"""
CodeBERT-based model for vulnerability detection.

Uses pre-trained CodeBERT/GraphCodeBERT for code understanding
and fine-tunes for vulnerability classification.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from tqdm import tqdm

from ..utils.config import get_config
from ..utils.logger import get_logger


class CodeBERTClassifier(nn.Module):
    """
    Neural network classifier on top of CodeBERT embeddings.
    """

    def __init__(
        self,
        hidden_size: int = 768,
        num_labels: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(hidden_size, 256),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(256, num_labels),
        )

    def forward(self, pooled_output: torch.Tensor) -> torch.Tensor:
        return self.classifier(pooled_output)


class CodeBERTModel:
    """
    CodeBERT-based vulnerability detection model.

    Fine-tunes CodeBERT on labeled vulnerability data for
    binary classification.
    """

    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        device: Optional[str] = None,
    ):
        """
        Initialize the CodeBERT model.

        Args:
            model_name: HuggingFace model name/path
            device: Device to use (cuda/cpu/auto)
        """
        self.config = get_config()
        self.logger = get_logger("codebert_model")

        self.model_name = model_name
        self.device = self._get_device(device)

        # Model components (lazy loaded)
        self.tokenizer = None
        self.encoder = None
        self.classifier = None

        # Training config
        model_config = self.config.get("models.codebert", {})
        self.max_length = model_config.get("max_length", 512)
        self.batch_size = model_config.get("batch_size", 16)
        self.learning_rate = model_config.get("learning_rate", 2e-5)
        self.epochs = model_config.get("epochs", 10)
        self.warmup_ratio = model_config.get("warmup_ratio", 0.1)

    def _get_device(self, device: Optional[str]) -> torch.device:
        """Determine the device to use."""
        if device == "auto" or device is None:
            if torch.cuda.is_available():
                return torch.device("cuda")
            elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                return torch.device("mps")
            else:
                return torch.device("cpu")
        return torch.device(device)

    def _load_model(self) -> None:
        """Load the pre-trained model and tokenizer."""
        if self.tokenizer is not None:
            return

        try:
            from transformers import AutoTokenizer, AutoModel

            self.logger.info(f"Loading {self.model_name}...")

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.encoder = AutoModel.from_pretrained(self.model_name)
            self.encoder.to(self.device)

            # Initialize classifier
            hidden_size = self.encoder.config.hidden_size
            self.classifier = CodeBERTClassifier(hidden_size=hidden_size)
            self.classifier.to(self.device)

            self.logger.info(f"Model loaded on {self.device}")

        except ImportError:
            raise ImportError(
                "transformers library required. Install with: pip install transformers"
            )

    def tokenize(
        self,
        codes: Union[str, List[str]],
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenize code samples.

        Args:
            codes: Single code string or list of code strings

        Returns:
            Dictionary of tokenized inputs
        """
        self._load_model()

        if isinstance(codes, str):
            codes = [codes]

        encoding = self.tokenizer(
            codes,
            truncation=True,
            padding=True,
            max_length=self.max_length,
            return_tensors="pt",
        )

        return {k: v.to(self.device) for k, v in encoding.items()}

    def encode(self, codes: Union[str, List[str]]) -> torch.Tensor:
        """
        Encode code samples to embeddings.

        Args:
            codes: Single code string or list of code strings

        Returns:
            Tensor of embeddings (batch_size, hidden_size)
        """
        self._load_model()

        inputs = self.tokenize(codes)

        with torch.no_grad():
            outputs = self.encoder(**inputs)
            # Use [CLS] token embedding or mean pooling
            embeddings = outputs.last_hidden_state[:, 0, :]

        return embeddings

    def fit(
        self,
        train_loader: DataLoader,
        val_loader: Optional[DataLoader] = None,
        epochs: Optional[int] = None,
    ) -> Dict[str, List[float]]:
        """
        Fine-tune the model on labeled data.

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            epochs: Number of training epochs

        Returns:
            Dictionary of training history
        """
        self._load_model()

        epochs = epochs or self.epochs

        # Optimizer
        optimizer = torch.optim.AdamW(
            list(self.encoder.parameters()) + list(self.classifier.parameters()),
            lr=self.learning_rate,
            weight_decay=0.01,
        )

        # Learning rate scheduler
        total_steps = len(train_loader) * epochs
        warmup_steps = int(total_steps * self.warmup_ratio)

        def lr_lambda(step):
            if step < warmup_steps:
                return step / warmup_steps
            return max(0.0, (total_steps - step) / (total_steps - warmup_steps))

        scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)

        # Loss function
        criterion = nn.CrossEntropyLoss()

        # Training history
        history = {"train_loss": [], "val_loss": [], "val_f1": []}

        # Training loop
        best_val_f1 = 0.0
        patience_counter = 0
        patience = self.config.get("training.early_stopping_patience", 5)

        for epoch in range(epochs):
            self.encoder.train()
            self.classifier.train()

            train_loss = 0.0
            train_steps = 0

            progress = tqdm(train_loader, desc=f"Epoch {epoch + 1}/{epochs}")
            for batch in progress:
                # Get inputs
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["label"].to(self.device)

                # Forward pass
                outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
                pooled = outputs.last_hidden_state[:, 0, :]
                logits = self.classifier(pooled)

                loss = criterion(logits, labels)

                # Backward pass
                optimizer.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(
                    list(self.encoder.parameters()) + list(self.classifier.parameters()),
                    max_norm=1.0,
                )
                optimizer.step()
                scheduler.step()

                train_loss += loss.item()
                train_steps += 1
                progress.set_postfix({"loss": loss.item()})

            avg_train_loss = train_loss / train_steps
            history["train_loss"].append(avg_train_loss)

            # Validation
            if val_loader is not None:
                val_metrics = self._evaluate(val_loader, criterion)
                history["val_loss"].append(val_metrics["loss"])
                history["val_f1"].append(val_metrics["f1"])

                self.logger.info(
                    f"Epoch {epoch + 1}: train_loss={avg_train_loss:.4f}, "
                    f"val_loss={val_metrics['loss']:.4f}, val_f1={val_metrics['f1']:.4f}"
                )

                # Early stopping
                if val_metrics["f1"] > best_val_f1:
                    best_val_f1 = val_metrics["f1"]
                    patience_counter = 0
                else:
                    patience_counter += 1
                    if patience_counter >= patience:
                        self.logger.info(f"Early stopping at epoch {epoch + 1}")
                        break
            else:
                self.logger.info(f"Epoch {epoch + 1}: train_loss={avg_train_loss:.4f}")

        return history

    def _evaluate(
        self,
        data_loader: DataLoader,
        criterion: nn.Module,
    ) -> Dict[str, float]:
        """Evaluate the model on a data loader."""
        self.encoder.eval()
        self.classifier.eval()

        total_loss = 0.0
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in data_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["label"].to(self.device)

                outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
                pooled = outputs.last_hidden_state[:, 0, :]
                logits = self.classifier(pooled)

                loss = criterion(logits, labels)
                total_loss += loss.item()

                preds = torch.argmax(logits, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)

        from sklearn.metrics import precision_score, recall_score, f1_score

        return {
            "loss": total_loss / len(data_loader),
            "precision": precision_score(all_labels, all_preds, zero_division=0),
            "recall": recall_score(all_labels, all_preds, zero_division=0),
            "f1": f1_score(all_labels, all_preds, zero_division=0),
        }

    def predict(self, codes: Union[str, List[str]]) -> np.ndarray:
        """
        Predict vulnerability labels.

        Args:
            codes: Single code string or list of code strings

        Returns:
            Array of predictions (0 = safe, 1 = vulnerable)
        """
        proba = self.predict_proba(codes)
        return np.argmax(proba, axis=1)

    def predict_proba(self, codes: Union[str, List[str]]) -> np.ndarray:
        """
        Predict vulnerability probabilities.

        Args:
            codes: Single code string or list of code strings

        Returns:
            Array of probabilities (n_samples, 2)
        """
        self._load_model()

        if isinstance(codes, str):
            codes = [codes]

        self.encoder.eval()
        self.classifier.eval()

        all_proba = []

        # Process in batches
        for i in range(0, len(codes), self.batch_size):
            batch_codes = codes[i:i + self.batch_size]
            inputs = self.tokenize(batch_codes)

            with torch.no_grad():
                outputs = self.encoder(**inputs)
                pooled = outputs.last_hidden_state[:, 0, :]
                logits = self.classifier(pooled)
                proba = torch.softmax(logits, dim=1)
                all_proba.append(proba.cpu().numpy())

        return np.vstack(all_proba)

    def evaluate(
        self,
        codes: List[str],
        labels: np.ndarray,
    ) -> Dict[str, float]:
        """
        Evaluate the model on test data.

        Args:
            codes: List of code strings
            labels: True labels

        Returns:
            Dictionary of evaluation metrics
        """
        predictions = self.predict(codes)
        proba = self.predict_proba(codes)[:, 1]

        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

        metrics = {
            "accuracy": accuracy_score(labels, predictions),
            "precision": precision_score(labels, predictions, zero_division=0),
            "recall": recall_score(labels, predictions, zero_division=0),
            "f1": f1_score(labels, predictions, zero_division=0),
            "roc_auc": roc_auc_score(labels, proba) if len(np.unique(labels)) > 1 else 0.5,
        }

        self.logger.info(f"Evaluation metrics: {metrics}")
        return metrics

    def save(self, path: str) -> None:
        """
        Save the model to disk.

        Args:
            path: Directory path to save the model
        """
        self._load_model()

        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)

        # Save encoder
        self.encoder.save_pretrained(path / "encoder")
        self.tokenizer.save_pretrained(path / "encoder")

        # Save classifier
        torch.save(self.classifier.state_dict(), path / "classifier.pt")

        # Save config
        import json
        config = {
            "model_name": self.model_name,
            "max_length": self.max_length,
        }
        with open(path / "config.json", "w") as f:
            json.dump(config, f)

        self.logger.info(f"Model saved to {path}")

    def load(self, path: str) -> "CodeBERTModel":
        """
        Load a model from disk.

        Args:
            path: Directory path to the saved model

        Returns:
            self
        """
        from transformers import AutoTokenizer, AutoModel
        import json

        path = Path(path)

        # Load config
        with open(path / "config.json", "r") as f:
            config = json.load(f)

        self.model_name = config["model_name"]
        self.max_length = config["max_length"]

        # Load encoder
        self.tokenizer = AutoTokenizer.from_pretrained(path / "encoder")
        self.encoder = AutoModel.from_pretrained(path / "encoder")
        self.encoder.to(self.device)

        # Load classifier
        hidden_size = self.encoder.config.hidden_size
        self.classifier = CodeBERTClassifier(hidden_size=hidden_size)
        self.classifier.load_state_dict(torch.load(path / "classifier.pt", map_location=self.device))
        self.classifier.to(self.device)

        self.logger.info(f"Model loaded from {path}")
        return self

    def analyze_code(self, code: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a code sample.

        Args:
            code: Source code string

        Returns:
            Dictionary with prediction, confidence, and attention analysis
        """
        self._load_model()

        proba = self.predict_proba(code)[0]
        prediction = int(proba[1] > 0.5)
        confidence = float(proba[prediction])

        return {
            "vulnerable": bool(prediction),
            "confidence": confidence,
            "vulnerability_probability": float(proba[1]),
            "model": "codebert",
        }
