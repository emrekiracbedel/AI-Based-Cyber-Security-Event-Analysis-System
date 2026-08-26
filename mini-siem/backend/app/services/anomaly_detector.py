"""
ML anomaly detection: IsolationForest on engineered features + optional StandardScaler.
Model bundle trained by scripts/train_anomaly_model.py (joblib).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.config import settings

SOURCE_MAP = {
    "syslog": 0,
    "windows_event": 1,
    "web_server": 2,
    "ip_traffic": 3,
    "unknown": 4,
}


def feature_vector(event: dict[str, Any]) -> np.ndarray:
    ts = event.get("timestamp") or ""
    hour = 12
    try:
        ts_clean = ts.replace("Z", "+00:00")
        hour = datetime.fromisoformat(ts_clean).hour
    except (ValueError, TypeError, OSError):
        pass
    hour_sin = float(np.sin(2 * np.pi * hour / 24.0))
    hour_cos = float(np.cos(2 * np.pi * hour / 24.0))
    msg = event.get("message") or ""
    L = min(len(msg), 10_000) / 5000.0
    tpl = event.get("log_template") or event.get("message") or ""
    t = (hash(tpl) % 997) / 997.0
    st = SOURCE_MAP.get(str(event.get("source_type", "unknown")), 4) / 4.0
    status = (event.get("http_status") or 0) / 600.0
    return np.array([[hour_sin, hour_cos, L, t, st, status]], dtype=np.float64)


class AnomalyDetector:
    def __init__(self, model_path: Path | None = None) -> None:
        self.path = model_path or settings.iforest_model_path
        self.bundle: dict[str, Any] | None = None
        self.load()

    def load(self) -> bool:
        if not self.path.is_file():
            self.bundle = None
            return False
        try:
            self.bundle = joblib.load(self.path)
            return True
        except Exception:
            self.bundle = None
            return False

    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        x = feature_vector(event)
        if not self.bundle:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "reason": "no_model",
            }
        scaler = self.bundle.get("scaler")
        model = self.bundle.get("model")
        if scaler is None or model is None:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "reason": "invalid_bundle",
            }
        xs = scaler.transform(x)
        pred = int(model.predict(xs)[0])
        score = float(model.score_samples(xs)[0])
        is_anomaly = pred == -1
        return {
            "anomaly_score": score,
            "is_anomaly": is_anomaly,
            "reason": "iforest",
        }


_detector: AnomalyDetector | None = None


def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        _detector = AnomalyDetector()
    return _detector
