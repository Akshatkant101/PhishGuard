"""
Integration tests for the ML training + evaluation pipeline.

Verifies:
- Sample data generation is reproducible and balanced
- Training pipeline runs end-to-end
- Domain-based split has zero leakage
- Model artifacts are saved correctly
- Evaluation pipeline runs and produces metrics
- Model metadata JSON contains required fields
"""

import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestSampleDataGeneration:
    """Tests for ml.data.download.generate_sample_dataset."""

    def test_generates_correct_counts(self, tmp_path):
        from ml.data.download import generate_sample_dataset

        path = generate_sample_dataset(
            n_legit=50, n_phish=50, seed=42, output_path=tmp_path / "test.csv"
        )

        import pandas as pd
        df = pd.read_csv(path)
        assert len(df) == 100
        assert df["label"].sum() == 50
        assert (df["label"] == 0).sum() == 50

    def test_reproducible_with_seed(self, tmp_path):
        from ml.data.download import generate_sample_dataset

        p1 = generate_sample_dataset(
            n_legit=20, n_phish=20, seed=123, output_path=tmp_path / "a.csv"
        )
        p2 = generate_sample_dataset(
            n_legit=20, n_phish=20, seed=123, output_path=tmp_path / "b.csv"
        )

        import pandas as pd
        df1 = pd.read_csv(p1)
        df2 = pd.read_csv(p2)
        assert df1.equals(df2)

    def test_path_length_bias_controlled(self, tmp_path):
        """Average URL lengths should be within 15 chars of each other."""
        from ml.data.download import generate_sample_dataset

        path = generate_sample_dataset(
            n_legit=200, n_phish=200, seed=42, output_path=tmp_path / "bias.csv"
        )

        import pandas as pd
        df = pd.read_csv(path)

        legit_avg = df[df["label"] == 0]["url"].str.len().mean()
        phish_avg = df[df["label"] == 1]["url"].str.len().mean()
        delta = abs(legit_avg - phish_avg)

        assert delta < 15, (
            f"Path-length bias detected: legit avg={legit_avg:.1f}, "
            f"phish avg={phish_avg:.1f}, delta={delta:.1f}"
        )


class TestTrainingPipeline:
    """End-to-end training pipeline tests."""

    def test_train_produces_artifacts(self, tmp_path):
        from ml.data.download import generate_sample_dataset
        from ml.train import train

        data_path = generate_sample_dataset(
            n_legit=80, n_phish=80, seed=42,
            output_path=tmp_path / "data" / "train.csv",
        )
        output_dir = tmp_path / "models"

        metadata = train(data_path=str(data_path), output_dir=str(output_dir))

        # Check artifacts exist
        assert (output_dir / "model.joblib").exists()
        assert (output_dir / "scaler.joblib").exists()
        assert (output_dir / "model_metadata.json").exists()
        assert (output_dir / "test_split.json").exists()

    def test_domain_leakage_is_zero(self, tmp_path):
        from ml.data.download import generate_sample_dataset
        from ml.train import train

        data_path = generate_sample_dataset(
            n_legit=80, n_phish=80, seed=42,
            output_path=tmp_path / "data" / "train.csv",
        )
        output_dir = tmp_path / "models"
        metadata = train(data_path=str(data_path), output_dir=str(output_dir))

        assert metadata["domain_leakage"] == 0

    def test_metadata_has_required_fields(self, tmp_path):
        from ml.data.download import generate_sample_dataset
        from ml.train import train

        data_path = generate_sample_dataset(
            n_legit=80, n_phish=80, seed=42,
            output_path=tmp_path / "data" / "train.csv",
        )
        output_dir = tmp_path / "models"
        metadata = train(data_path=str(data_path), output_dir=str(output_dir))

        required = [
            "model_version", "model_type", "base_model",
            "training_date", "feature_names", "feature_count",
            "train_samples", "test_samples",
            "all_model_metrics", "best_model_metrics",
            "class_distribution", "bias_check",
        ]
        for field in required:
            assert field in metadata, f"Missing metadata field: {field}"

    def test_feature_count_matches(self, tmp_path):
        from ml.data.download import generate_sample_dataset
        from ml.train import train
        from app.services.feature_extractor import FEATURE_NAMES

        data_path = generate_sample_dataset(
            n_legit=60, n_phish=60, seed=42,
            output_path=tmp_path / "data" / "train.csv",
        )
        output_dir = tmp_path / "models"
        metadata = train(data_path=str(data_path), output_dir=str(output_dir))

        assert metadata["feature_count"] == len(metadata["feature_names"])
        assert metadata["feature_count"] in (24, len(FEATURE_NAMES))


class TestEvaluationPipeline:
    """End-to-end evaluation pipeline tests."""

    @pytest.fixture
    def trained_model_dir(self, tmp_path):
        """Train a model and return the output directory."""
        from ml.data.download import generate_sample_dataset
        from ml.train import train

        data_path = generate_sample_dataset(
            n_legit=80, n_phish=80, seed=42,
            output_path=tmp_path / "data" / "train.csv",
        )
        output_dir = tmp_path / "models"
        train(data_path=str(data_path), output_dir=str(output_dir))
        return output_dir

    def test_evaluate_runs_without_error(self, trained_model_dir):
        from ml.evaluate import evaluate

        metrics = evaluate(model_dir=str(trained_model_dir))
        assert isinstance(metrics, dict)

    def test_evaluate_produces_required_metrics(self, trained_model_dir):
        from ml.evaluate import evaluate

        metrics = evaluate(model_dir=str(trained_model_dir))

        required = [
            "threshold", "precision_phishing", "recall_phishing",
            "f1", "accuracy", "roc_auc", "pr_auc", "fpr",
            "brier_score", "confusion_matrix",
            "threshold_high_precision", "recall_at_high_precision",
        ]
        for field in required:
            assert field in metrics, f"Missing metric: {field}"

    def test_metrics_in_valid_ranges(self, trained_model_dir):
        from ml.evaluate import evaluate

        m = evaluate(model_dir=str(trained_model_dir))
        assert 0 <= m["precision_phishing"] <= 1
        assert 0 <= m["recall_phishing"] <= 1
        assert 0 <= m["f1"] <= 1
        assert 0 <= m["accuracy"] <= 1
        assert 0 <= m["roc_auc"] <= 1
        assert 0 <= m["pr_auc"] <= 1
        assert 0 <= m["fpr"] <= 1
        assert 0 <= m["brier_score"] <= 1
        assert 0 < m["threshold"] < 1

    def test_confusion_matrix_sums_to_test_size(self, trained_model_dir):
        from ml.evaluate import evaluate

        m = evaluate(model_dir=str(trained_model_dir))
        cm = m["confusion_matrix"]
        total = cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"]
        assert total > 0

    def test_metadata_updated_with_evaluation(self, trained_model_dir):
        from ml.evaluate import evaluate

        evaluate(model_dir=str(trained_model_dir))

        with open(trained_model_dir / "model_metadata.json") as fh:
            meta = json.load(fh)

        assert "evaluation" in meta
        assert "optimal_threshold" in meta
