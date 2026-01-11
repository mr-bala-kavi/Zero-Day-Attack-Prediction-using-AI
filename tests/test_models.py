"""Tests for ML models."""

import pytest
import sys
import tempfile
from pathlib import Path

import numpy as np

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.data.dataset import SyntheticVulnerabilityDataset
from src.models.baseline import BaselineModel


class TestBaselineModel:
    """Tests for BaselineModel."""

    def setup_method(self):
        self.model = BaselineModel(model_type="random_forest")

        # Generate small synthetic dataset
        generator = SyntheticVulnerabilityDataset()
        self.df = generator.generate_full_dataset(samples_per_type=20)
        self.codes = self.df["code"].tolist()
        self.labels = self.df["vulnerable"].values

    def test_extract_features(self):
        code = """
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
}
        """
        features = self.model.extract_features(code, "c")

        assert isinstance(features, dict)
        assert len(features) > 0
        assert all(isinstance(v, (int, float)) for v in features.values())

    def test_fit(self):
        self.model.fit(self.codes, self.labels)

        # Model should be trained
        assert self.model.model is not None
        assert len(self.model.feature_names) > 0

    def test_predict(self):
        self.model.fit(self.codes, self.labels)

        predictions = self.model.predict(self.codes)

        assert len(predictions) == len(self.codes)
        assert all(p in [0, 1] for p in predictions)

    def test_predict_proba(self):
        self.model.fit(self.codes, self.labels)

        proba = self.model.predict_proba(self.codes)

        assert proba.shape == (len(self.codes), 2)
        assert np.allclose(proba.sum(axis=1), 1.0)

    def test_predict_single_sample(self):
        self.model.fit(self.codes, self.labels)

        code = "gets(buffer);"
        prediction = self.model.predict(code)
        proba = self.model.predict_proba(code)

        assert len(prediction) == 1
        assert proba.shape == (1, 2)

    def test_evaluate(self):
        self.model.fit(self.codes, self.labels)
        metrics = self.model.evaluate(self.codes, self.labels)

        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1" in metrics
        assert all(0 <= v <= 1 for v in metrics.values())

    def test_save_load(self):
        self.model.fit(self.codes, self.labels)

        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "model.joblib"
            self.model.save(str(model_path))

            # Load model
            loaded_model = BaselineModel()
            loaded_model.load(str(model_path))

            # Predictions should match
            original_pred = self.model.predict(self.codes)
            loaded_pred = loaded_model.predict(self.codes)

            np.testing.assert_array_equal(original_pred, loaded_pred)

    def test_feature_importance(self):
        self.model.fit(self.codes, self.labels)
        importance = self.model.get_feature_importance()

        assert isinstance(importance, dict)
        assert len(importance) > 0
        assert all(isinstance(v, float) for v in importance.values())

    def test_analyze_code(self):
        self.model.fit(self.codes, self.labels)

        code = """
void vulnerable(char *input) {
    gets(input);
    strcpy(buffer, input);
}
        """
        result = self.model.analyze_code(code, "c")

        assert "vulnerable" in result
        assert "confidence" in result
        assert "vulnerability_probability" in result
        assert "features" in result
        assert "pattern_matches" in result


class TestSyntheticDataset:
    """Tests for SyntheticVulnerabilityDataset."""

    def setup_method(self):
        self.generator = SyntheticVulnerabilityDataset()

    def test_generate_buffer_overflow_samples(self):
        samples = self.generator.generate_buffer_overflow_samples(n_samples=10)

        assert len(samples) == 10
        assert all("code" in s for s in samples)
        assert all("vulnerable" in s for s in samples)

        # Should have mix of vulnerable and safe
        vulnerable_count = sum(s["vulnerable"] for s in samples)
        assert 0 < vulnerable_count < 10

    def test_generate_sql_injection_samples(self):
        samples = self.generator.generate_sql_injection_samples(n_samples=10)

        assert len(samples) == 10
        vulnerable_count = sum(s["vulnerable"] for s in samples)
        assert 0 < vulnerable_count < 10

    def test_generate_xss_samples(self):
        samples = self.generator.generate_xss_samples(n_samples=10)

        assert len(samples) == 10
        vulnerable_count = sum(s["vulnerable"] for s in samples)
        assert 0 < vulnerable_count < 10

    def test_generate_full_dataset(self):
        df = self.generator.generate_full_dataset(samples_per_type=10)

        assert len(df) == 30  # 10 per type * 3 types
        assert "code" in df.columns
        assert "vulnerable" in df.columns
        assert "vulnerability_type" in df.columns


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
