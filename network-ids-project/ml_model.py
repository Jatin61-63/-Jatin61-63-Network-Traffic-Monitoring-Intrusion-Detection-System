"""Lightweight Isolation Forest anomaly detector for packet metadata only."""
from pathlib import Path
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = Path(__file__).resolve().parent / "models" / "isolation_forest.pkl"
FEATURES = ["packet_size", "duration", "src_port", "dst_port", "protocol_code", "syn_flag"]

def protocol_code(protocol):
    return {"TCP": 1, "UDP": 2, "ICMP": 3}.get(str(protocol).upper(), 0)

def to_features(record):
    flags = str(record.get("flags", ""))
    return [
        float(record.get("packet_size", 0)),
        float(record.get("duration", 0)),
        float(record.get("src_port", 0)),
        float(record.get("dst_port", 0)),
        float(protocol_code(record.get("protocol", ""))),
        1.0 if "S" in flags and "A" not in flags else 0.0,
    ]

class TrafficAnomalyModel:
    def __init__(self):
        self.model = None

    def train_demo_model(self, samples=1200, seed=42):
        rng = np.random.default_rng(seed)
        X = np.column_stack([
            rng.normal(650, 240, samples).clip(40, 1500),
            rng.exponential(.7, samples).clip(.001, 8),
            rng.choice([80, 443, 53, 123, 51514, 53001], samples),
            rng.choice([80, 443, 53, 123, 22, 3389], samples),
            rng.choice([1, 2, 3], samples),
            rng.choice([0, 1], samples, p=[.82, .18]),
        ])
        self.model = IsolationForest(n_estimators=150, contamination=.04, random_state=seed)
        self.model.fit(X)
        MODEL_PATH.parent.mkdir(exist_ok=True)
        with MODEL_PATH.open("wb") as f:
            pickle.dump(self.model, f)
        return {"samples": samples, "model": "IsolationForest", "saved_to": str(MODEL_PATH)}

    def load(self):
        if MODEL_PATH.exists():
            with MODEL_PATH.open("rb") as f:
                self.model = pickle.load(f)
        else:
            self.train_demo_model()
        return self

    def predict(self, record):
        if self.model is None:
            self.load()
        features = np.array([to_features(record)], dtype=float)
        raw = int(self.model.predict(features)[0])
        score = float(self.model.decision_function(features)[0])
        # Higher anomaly confidence is a normalized, illustrative score, not a probability.
        confidence = round(max(0.0, min(1.0, .5 - score)), 3)
        return {"label": "Suspicious" if raw == -1 else "Normal", "anomaly_score": round(-score, 4),
                "confidence": confidence}

if __name__ == "__main__":
    detector = TrafficAnomalyModel()
    print(detector.train_demo_model())
