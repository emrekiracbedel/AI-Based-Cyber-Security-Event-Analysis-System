"""
Train IsolationForest on synthetic normal + anomalous log feature vectors.
Run from repo root or backend folder:

  cd mini-siem/backend
  set PYTHONPATH=.
  python scripts/train_anomaly_model.py

Writes models/iforest.joblib (StandardScaler + IsolationForest).
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from app.config import settings
from app.services.anomaly_detector import feature_vector
from app.services.log_template import extract_template


def _event(ts: str, st: str, msg: str, status: int | None = None) -> dict:
    e = {
        "timestamp": ts,
        "source_type": st,
        "message": msg,
        "http_status": status,
        "log_template": extract_template(msg),
    }
    return e


def build_dataset() -> tuple[np.ndarray, np.ndarray]:
    normal_msgs = []
    for i in range(3000):
        normal_msgs.append(
            _event(
                "2026-04-04T10:00:00+00:00",
                str(np.random.choice(["web_server", "syslog", "windows_event"])),
                f"GET /api/health/{i % 100} ok status",
                int(np.random.choice([200, 200, 200, 301, 404])),
            )
        )
    Xn = np.vstack([feature_vector(e)[0] for e in normal_msgs])

    anomaly_msgs = []
    for i in range(400):
        anomaly_msgs.append(
            _event(
                "2026-04-04T03:00:00+00:00",
                "web_server",
                "UNION SELECT * FROM users WHERE '1'='1' " + "A" * 800,
                500,
            )
        )
        anomaly_msgs.append(
            _event(
                "2026-04-04T03:01:00+00:00",
                "unknown",
                "ZZZ" * 500 + str(i),
                None,
            )
        )
    Xa = np.vstack([feature_vector(e)[0] for e in anomaly_msgs])

    X = np.vstack([Xn, Xa])
    y = np.array([0] * len(Xn) + [1] * len(Xa))
    return X, y


def main() -> None:
    X, _y = build_dataset()
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = IsolationForest(
        n_estimators=200,
        contamination=0.12,
        random_state=42,
    )
    model.fit(Xs)
    settings.iforest_model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"scaler": scaler, "model": model}, settings.iforest_model_path)
    print(f"Wrote {settings.iforest_model_path}")


if __name__ == "__main__":
    main()
