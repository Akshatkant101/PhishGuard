from pathlib import Path
import json
import logging
from typing import Any, Dict, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from app.config import settings

logger = logging.getLogger(__name__)


class ModelService:
    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir or settings.MODEL_DIR)
        self.model = None
        self.scaler = None
        self.metadata: Dict[str, Any] = {}
        self.feature_names: list[str] = []
        self.optimal_threshold: float = 0.5
        self.load()

    def load(self):
        """Load model, scaler, and metadata."""
        try:
            model_path = self.model_dir / "model.joblib"
            scaler_path = self.model_dir / "scaler.joblib"
            meta_path = self.model_dir / "model_metadata.json"

            if model_path.exists():
                self.model = joblib.load(model_path)
                logger.info(f"Loaded ML model from {model_path}")
            else:
                logger.warning(f"Model file not found at {model_path}")

            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info(f"Loaded scaler from {scaler_path}")

            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.feature_names = self.metadata.get("feature_names", [])
                self.optimal_threshold = self.metadata.get("optimal_threshold", 0.5)
                logger.info(f"Loaded model metadata: version {self.metadata.get('model_version')}")

            tld_path = self.model_dir / "tld_phish_rates.json"
            if tld_path.exists():
                with open(tld_path, "r", encoding="utf-8") as f:
                    tld_data = json.load(f)
                from app.services.feature_extractor import set_tld_phish_rates
                set_tld_phish_rates(tld_data.get("rates", {}), tld_data.get("default_rate", 0.5))
                logger.info(f"Loaded learned TLD phishing rates ({len(tld_data.get('rates', {}))} TLDs)")
        except Exception as e:
            logger.error(f"Error loading ML artifacts: {e}", exc_info=True)

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict_phishing_probability(self, features_dict: Dict[str, float]) -> Tuple[float, float]:
        """Predict phishing probability for a single feature dictionary.

        Returns (phishing_probability, confidence).
        phishing_probability is in [0.0, 1.0].
        confidence is the distance from uncertain (e.g. normalized certainty).
        """
        if not self.is_loaded:
            # Fallback heuristic if model is unavailable
            return 0.5, 0.0

        cols = self.feature_names if self.feature_names else list(features_dict.keys())
        df = pd.DataFrame([[features_dict[c] for c in cols]], columns=cols)

        if self.scaler is not None and self.metadata.get("uses_scaled_features", True):
            X_input = self.scaler.transform(df)
        else:
            X_input = df.values

        # Calibrated model or sklearn classifier predict_proba
        proba = self.model.predict_proba(X_input)[0]
        # proba[1] is phishing class probability
        phish_prob = float(proba[1])
        # Confidence score (0.0 at 0.5 probability, 1.0 at 0.0 or 1.0)
        confidence = float(min(1.0, abs(phish_prob - 0.5) * 2.0))
        return phish_prob, confidence


# Singleton instance
ml_service = ModelService()
