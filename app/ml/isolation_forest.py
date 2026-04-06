"""
app/ml/isolation_forest.py  —  Division 3 FINAL FIX
"""
import os
import logging
import numpy as np

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest.pkl")
MIN_TRAIN_SAMPLES = 100
CONTAMINATION = 0.05


class AnomalyDetector:
    def __init__(self):
        self._model          = None
        self._is_trained     = False
        self._training_buffer = []
        self._total_scored   = 0
        self._total_anomalies = 0
        self._load()

    # ── Public ────────────────────────────────────────────────────────────────

    def score_event(self, event: dict) -> dict:
        """Score one event. Always returns a safe dict."""
        try:
            # Collect normal events for training
            if not event.get("is_attack", False):
                self._training_buffer.append(event)
                if len(self._training_buffer) >= MIN_TRAIN_SAMPLES and not self._is_trained:
                    self._train()

            if not self._is_trained:
                return {
                    "anomaly_score": 0.0,
                    "is_anomaly":    False,
                    "model_ready":   False,
                }

            features = self._extract(event).reshape(1, -1)
            raw      = self._model.score_samples(features)[0]
            score    = float(np.clip(1.0 - (raw + 0.8) / 0.8, 0.0, 1.0))
            is_anom  = self._model.predict(features)[0] == -1

            self._total_scored   += 1
            self._total_anomalies += 1 if is_anom else 0

            return {
                "anomaly_score": round(score, 3),
                "is_anomaly":    is_anom,
                "model_ready":   True,
            }
        except Exception as e:
            logger.warning(f"[ML] score_event error: {e}")
            return {"anomaly_score": 0.0, "is_anomaly": False, "model_ready": False}

    def retrain(self) -> bool:
        """Retrain on current buffer. Resets display counters."""
        if len(self._training_buffer) < 10:
            return False
        # Reset counters so UI shows fresh state
        self._total_scored    = 0
        self._total_anomalies = 0
        self._train()
        return True

    def get_stats(self) -> dict:
        return {
            "model_ready":        self._is_trained,
            "training_samples":   len(self._training_buffer),
            "min_samples_needed": MIN_TRAIN_SAMPLES,
            "total_scored":       self._total_scored,
            "total_anomalies":    self._total_anomalies,
            "anomaly_rate":       round(
                self._total_anomalies / max(self._total_scored, 1), 3
            ),
        }

    def reset(self):
        self._model           = None
        self._is_trained      = False
        self._training_buffer = []
        self._total_scored    = 0
        self._total_anomalies = 0
        if os.path.exists(MODEL_PATH):
            os.remove(MODEL_PATH)

    # ── Private ───────────────────────────────────────────────────────────────

    def _train(self):
        try:
            from sklearn.ensemble import IsolationForest
            import joblib
            X = np.vstack([self._extract(e) for e in self._training_buffer])
            self._model = IsolationForest(
                n_estimators=100,
                contamination=CONTAMINATION,
                random_state=42,
                n_jobs=-1,
            )
            self._model.fit(X)
            self._is_trained = True
            try:
                import joblib
                joblib.dump(self._model, MODEL_PATH)
            except Exception:
                pass
            logger.info(f"[ML] Trained on {len(self._training_buffer)} samples.")
        except Exception as e:
            logger.error(f"[ML] Training failed: {e}")

    def _load(self):
        if os.path.exists(MODEL_PATH):
            try:
                import joblib
                self._model      = joblib.load(MODEL_PATH)
                self._is_trained = True
                logger.info("[ML] Loaded saved model.")
            except Exception as e:
                logger.warning(f"[ML] Could not load model: {e}")

    @staticmethod
    def _extract(event: dict) -> np.ndarray:
        """Convert event to feature vector."""
        ATTACK_MAP   = {None:0,"SYN_FLOOD":1,"UDP_FLOOD":2,"HTTP_FLOOD":3,
                        "ICMP_FLOOD":4,"DNS_AMPLIFICATION":5,"GENERIC":6}
        PROTOCOL_MAP = {"TCP":0,"UDP":1,"ICMP":2,None:0}
        pc    = int(event.get("packet_count", 1))
        atk   = ATTACK_MAP.get(event.get("attack_type"), 0)
        proto = PROTOCOL_MAP.get(event.get("protocol"), 0)
        hour  = 0
        ts    = event.get("timestamp","")
        try:
            if "T" in ts:
                hour = int(ts.split("T")[1][:2])
        except Exception:
            pass
        return np.array([
            pc,
            1 if event.get("is_attack") else 0,
            atk, proto, hour,
            np.log1p(pc),
        ], dtype=np.float32)


# Global singleton
anomaly_detector = AnomalyDetector()
