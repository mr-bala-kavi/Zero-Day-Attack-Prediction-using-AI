"""
Dataset classes for vulnerability prediction.

Provides PyTorch-compatible datasets for training vulnerability detection models.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
import torch
from torch.utils.data import DataLoader, Dataset, WeightedRandomSampler
from sklearn.model_selection import train_test_split

from ..utils.config import get_config
from ..utils.logger import get_logger


class VulnerabilityDataset(Dataset):
    """
    Dataset for code vulnerability prediction.

    Supports both feature-based models (Random Forest) and
    text-based models (CodeBERT).
    """

    def __init__(
        self,
        data: Union[pd.DataFrame, List[Dict]],
        code_column: str = "code",
        label_column: str = "vulnerable",
        feature_columns: Optional[List[str]] = None,
        tokenizer=None,
        max_length: int = 512,
    ):
        """
        Initialize the vulnerability dataset.

        Args:
            data: DataFrame or list of dictionaries containing the data
            code_column: Name of the column containing source code
            label_column: Name of the column containing labels (0/1)
            feature_columns: List of feature column names for ML models
            tokenizer: HuggingFace tokenizer for transformer models
            max_length: Maximum sequence length for tokenization
        """
        self.logger = get_logger("dataset")

        if isinstance(data, list):
            data = pd.DataFrame(data)

        self.data = data.reset_index(drop=True)
        self.code_column = code_column
        self.label_column = label_column
        self.feature_columns = feature_columns
        self.tokenizer = tokenizer
        self.max_length = max_length

        # Validate columns
        if code_column not in self.data.columns:
            raise ValueError(f"Code column '{code_column}' not found in data")
        if label_column not in self.data.columns:
            raise ValueError(f"Label column '{label_column}' not found in data")

        self.logger.info(
            f"Dataset initialized with {len(self.data)} samples, "
            f"{self.data[label_column].sum()} vulnerable"
        )

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a single sample.

        Returns:
            Dictionary containing 'input', 'features', and 'label' tensors
        """
        row = self.data.iloc[idx]
        label = torch.tensor(row[self.label_column], dtype=torch.long)

        result = {"label": label}

        # Add tokenized input for transformer models
        if self.tokenizer is not None:
            code = str(row[self.code_column])
            encoding = self.tokenizer(
                code,
                truncation=True,
                padding="max_length",
                max_length=self.max_length,
                return_tensors="pt",
            )
            result["input_ids"] = encoding["input_ids"].squeeze(0)
            result["attention_mask"] = encoding["attention_mask"].squeeze(0)

        # Add numerical features for ML models
        if self.feature_columns:
            features = row[self.feature_columns].values.astype(np.float32)
            result["features"] = torch.tensor(features, dtype=torch.float32)

        # Add raw code for reference
        result["code"] = row[self.code_column]

        return result

    def get_labels(self) -> np.ndarray:
        """Get all labels as numpy array."""
        return self.data[self.label_column].values

    def get_features(self) -> Optional[np.ndarray]:
        """Get all features as numpy array."""
        if self.feature_columns:
            return self.data[self.feature_columns].values.astype(np.float32)
        return None

    def get_class_weights(self) -> torch.Tensor:
        """
        Calculate class weights for handling imbalanced data.

        Returns:
            Tensor with weights for each class
        """
        labels = self.get_labels()
        class_counts = np.bincount(labels)
        total = len(labels)
        weights = total / (len(class_counts) * class_counts)
        return torch.tensor(weights, dtype=torch.float32)

    def get_sample_weights(self) -> torch.Tensor:
        """
        Calculate sample weights for WeightedRandomSampler.

        Returns:
            Tensor with weight for each sample
        """
        class_weights = self.get_class_weights()
        labels = self.get_labels()
        return class_weights[labels]


def create_dataloaders(
    dataset: VulnerabilityDataset,
    batch_size: int = 32,
    test_size: float = 0.2,
    val_size: float = 0.1,
    use_weighted_sampling: bool = True,
    random_state: int = 42,
) -> Tuple[DataLoader, DataLoader, DataLoader]:
    """
    Create train, validation, and test dataloaders with stratified splits.

    Args:
        dataset: VulnerabilityDataset instance
        batch_size: Batch size for dataloaders
        test_size: Fraction for test set
        val_size: Fraction for validation set (from training data)
        use_weighted_sampling: Use weighted sampling for imbalanced data
        random_state: Random seed for reproducibility

    Returns:
        Tuple of (train_loader, val_loader, test_loader)
    """
    config = get_config()
    logger = get_logger("dataset")

    # Get indices for stratified split
    indices = np.arange(len(dataset))
    labels = dataset.get_labels()

    # First split: train+val and test
    train_val_idx, test_idx = train_test_split(
        indices,
        test_size=test_size,
        stratify=labels,
        random_state=random_state,
    )

    # Second split: train and val
    train_idx, val_idx = train_test_split(
        train_val_idx,
        test_size=val_size / (1 - test_size),
        stratify=labels[train_val_idx],
        random_state=random_state,
    )

    logger.info(
        f"Split sizes - Train: {len(train_idx)}, Val: {len(val_idx)}, Test: {len(test_idx)}"
    )

    # Create subsets
    train_dataset = torch.utils.data.Subset(dataset, train_idx)
    val_dataset = torch.utils.data.Subset(dataset, val_idx)
    test_dataset = torch.utils.data.Subset(dataset, test_idx)

    # Create sampler for training data if using weighted sampling
    train_sampler = None
    shuffle_train = True
    if use_weighted_sampling:
        sample_weights = dataset.get_sample_weights()[train_idx]
        train_sampler = WeightedRandomSampler(
            weights=sample_weights,
            num_samples=len(train_idx),
            replacement=True,
        )
        shuffle_train = False

    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=shuffle_train,
        sampler=train_sampler,
        num_workers=0,
        pin_memory=torch.cuda.is_available(),
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
        pin_memory=torch.cuda.is_available(),
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=0,
        pin_memory=torch.cuda.is_available(),
    )

    return train_loader, val_loader, test_loader


class SyntheticVulnerabilityDataset:
    """
    Generator for synthetic vulnerability training data.

    Creates labeled code samples with known vulnerability patterns
    for initial model training and testing.
    """

    def __init__(self):
        self.logger = get_logger("synthetic_dataset")

    def generate_buffer_overflow_samples(self, n_samples: int = 100) -> List[Dict]:
        """Generate C code samples with buffer overflow vulnerabilities."""
        samples = []

        # Vulnerable patterns
        vulnerable_patterns = [
            ('strcpy(dest, src);', 'char dest[10];\n    strcpy(dest, user_input);'),
            ('gets(buffer);', 'char buffer[100];\n    gets(buffer);'),
            ('sprintf(buf, fmt, data);', 'char buf[50];\n    sprintf(buf, "%s", long_string);'),
            ('memcpy without bounds', 'memcpy(dest, src, strlen(src));'),
        ]

        # Safe patterns
        safe_patterns = [
            ('strncpy with bounds', 'strncpy(dest, src, sizeof(dest) - 1);\n    dest[sizeof(dest) - 1] = \'\\0\';'),
            ('fgets with limit', 'fgets(buffer, sizeof(buffer), stdin);'),
            ('snprintf with size', 'snprintf(buf, sizeof(buf), "%s", string);'),
            ('memcpy with check', 'if (len <= sizeof(dest)) memcpy(dest, src, len);'),
        ]

        for i in range(n_samples):
            if i % 2 == 0:
                pattern = vulnerable_patterns[i % len(vulnerable_patterns)]
                samples.append({
                    "code": self._wrap_c_function(pattern[1]),
                    "vulnerable": 1,
                    "vulnerability_type": "buffer_overflow",
                    "description": pattern[0],
                })
            else:
                pattern = safe_patterns[i % len(safe_patterns)]
                samples.append({
                    "code": self._wrap_c_function(pattern[1]),
                    "vulnerable": 0,
                    "vulnerability_type": None,
                    "description": pattern[0],
                })

        return samples

    def generate_sql_injection_samples(self, n_samples: int = 100) -> List[Dict]:
        """Generate code samples with SQL injection vulnerabilities."""
        samples = []

        # Vulnerable patterns
        vulnerable_patterns = [
            "query = \"SELECT * FROM users WHERE id = \" + user_id",
            "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            "query = \"DELETE FROM users WHERE id = %s\" % user_input",
            "sql = \"INSERT INTO logs VALUES ('\" + data + \"')\"",
        ]

        # Safe patterns
        safe_patterns = [
            "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))",
            "cursor.execute(\"SELECT * FROM users WHERE name = %s\", [name])",
            "query = text(\"SELECT * FROM users WHERE id = :id\").bindparams(id=user_id)",
            "session.query(User).filter(User.id == user_id).first()",
        ]

        for i in range(n_samples):
            if i % 2 == 0:
                pattern = vulnerable_patterns[i % len(vulnerable_patterns)]
                samples.append({
                    "code": self._wrap_python_function(pattern),
                    "vulnerable": 1,
                    "vulnerability_type": "sql_injection",
                    "description": "SQL injection via string concatenation",
                })
            else:
                pattern = safe_patterns[i % len(safe_patterns)]
                samples.append({
                    "code": self._wrap_python_function(pattern),
                    "vulnerable": 0,
                    "vulnerability_type": None,
                    "description": "Parameterized query",
                })

        return samples

    def generate_xss_samples(self, n_samples: int = 100) -> List[Dict]:
        """Generate code samples with XSS vulnerabilities."""
        samples = []

        # Vulnerable patterns
        vulnerable_patterns = [
            "element.innerHTML = userInput;",
            "document.write(userData);",
            "$(\"#output\").html(response);",
            "eval(userCode);",
        ]

        # Safe patterns
        safe_patterns = [
            "element.textContent = userInput;",
            "const escaped = DOMPurify.sanitize(userData);",
            "$(\"#output\").text(response);",
            "element.innerText = sanitize(userInput);",
        ]

        for i in range(n_samples):
            if i % 2 == 0:
                pattern = vulnerable_patterns[i % len(vulnerable_patterns)]
                samples.append({
                    "code": self._wrap_js_function(pattern),
                    "vulnerable": 1,
                    "vulnerability_type": "xss",
                    "description": "Cross-site scripting vulnerability",
                })
            else:
                pattern = safe_patterns[i % len(safe_patterns)]
                samples.append({
                    "code": self._wrap_js_function(pattern),
                    "vulnerable": 0,
                    "vulnerability_type": None,
                    "description": "Safe DOM manipulation",
                })

        return samples

    def generate_full_dataset(self, samples_per_type: int = 100) -> pd.DataFrame:
        """
        Generate a complete synthetic dataset with multiple vulnerability types.

        Args:
            samples_per_type: Number of samples to generate per vulnerability type

        Returns:
            DataFrame with all generated samples
        """
        all_samples = []
        all_samples.extend(self.generate_buffer_overflow_samples(samples_per_type))
        all_samples.extend(self.generate_sql_injection_samples(samples_per_type))
        all_samples.extend(self.generate_xss_samples(samples_per_type))

        df = pd.DataFrame(all_samples)
        self.logger.info(
            f"Generated {len(df)} synthetic samples: "
            f"{df['vulnerable'].sum()} vulnerable, "
            f"{(~df['vulnerable'].astype(bool)).sum()} safe"
        )
        return df

    def _wrap_c_function(self, code: str) -> str:
        return f"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *user_input) {{
    {code}
}}"""

    def _wrap_python_function(self, code: str) -> str:
        return f"""import sqlite3

def query_database(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    {code}
    return cursor.fetchall()"""

    def _wrap_js_function(self, code: str) -> str:
        return f"""function handleUserInput(userInput) {{
    const element = document.getElementById('output');
    {code}
}}"""
