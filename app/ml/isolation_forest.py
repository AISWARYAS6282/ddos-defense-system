"""
app/ml/isolation_forest.py  —  Division 3
Unsupervised anomaly detection using Isolation Forest.
Trains on normal traffic, flags statistical outliers.
"""
import os
import logging
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from .feature_extractor import extract_features, extract_batch

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")

# How many normal events to collect before training
MIN_TRAIN_SAMPLES = 100
# Contamination = expected fraction of anomalies in training data
CONTAMINATION = 0.05


class AnomalyDetector:
    """
    Wraps scikit-learn IsolationForest.
    - Collects normal events until MIN_TRAIN_SAMPLES reached
    - Trains automatically
    - Scores every event in real-time
    """

    def __init__(self):
        self._model = None
        self._training_buffer = []
        self._is_trained = False
        self._total_scored = 0
        self._total_anomalies = 0

        # Try loading a saved model
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def score_event(self, event: dict) -> dict:
        """
        Score a single event.
        Returns:
            {
                'anomaly_score': float (0.0–1.0, higher = more anomalous),
                'is_anomaly': bool,
                'model_ready': bool,
            }
        """
        # Collect normal events for training
        if not event.get("is_attack", False):
            self._training_buffer.append(event)
            if len(self._training_buffer) >= MIN_TRAIN_SAMPLES and not self._is_trained:
                self._train()

        if not self._is_trained:
            return {"anomaly_score": 0.0, "is_anomaly": False, "model_ready": False}

        features = extract_features(event).reshape(1, -1)

        # IsolationForest score_samples returns negative values
        # More negative = more anomalous
        raw_score = self._model.score_samples(features)[0]

        # Convert to 0.0–1.0 scale (0 = normal, 1 = anomaly)
        # Typical range is roughly -0.8 to 0.0
        anomaly_score = float(np.clip(1.0 - (raw_score + 0.8) / 0.8, 0.0, 1.0))

        prediction = self._model.predict(features)[0]  # -1 = anomaly, 1 = normal
        is_anomaly = prediction == -1

        self._total_scored += 1
        if is_anomaly:
            self._total_anomalies += 1

        return {
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly": is_anomaly,
            "model_ready": True,
        }

    def retrain(self) -> bool:
        """Force retrain using the current buffer."""
        if len(self._training_buffer) < MIN_TRAIN_SAMPLES:
            return False
        self._train()
        return True

    def get_stats(self) -> dict:
        return {
            "model_ready": self._is_trained,
            "training_samples": len(self._training_buffer),
            "min_samples_needed": MIN_TRAIN_SAMPLES,
            "total_scored": self._total_scored,
            "total_anomalies": self._total_anomalies,
            "anomaly_rate": round(
                self._total_anomalies / max(self._total_scored, 1), 3
            ),
        }

    def reset(self):
        """Clear model and buffer."""
        self._model = None
        self._is_trained = False
        self._training_buffer = []
        self._total_scored = 0
        self._total_anomalies = 0
        if os.path.exists(MODEL_PATH):
            os.remove(MODEL_PATH)

    # ── Private ───────────────────────────────────────────────────────────────

    def _train(self):
        try:
            X = extract_batch(self._training_buffer)
            self._model = IsolationForest(
                n_estimators=100,
                contamination=CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X)
            self._is_trained = True
            self._save()
            logger.info(
                f"[ML] Isolation Forest trained on "
                f"{len(self._training_buffer)} samples."
            )
        except Exception as e:
            logger.error(f"[ML] Training failed: {e}")

    def _save(self):
        try:
            joblib.dump(self._model, MODEL_PATH)
        except Exception as e:
            logger.warning(f"[ML] Could not save model: {e}")

    def _load(self):
        if os.path.exists(MODEL_PATH):
            try:
                self._model = joblib.load(MODEL_PATH)
                self._is_trained = True
                logger.info("[ML] Loaded saved Isolation Forest model.")
            except Exception as e:
                logger.warning(f"[ML] Could not load model: {e}")


# Global singleton
anomaly_detector = AnomalyDetector()
