"""
Train an Isolation Forest anomaly detector on the synthetic dataset.

Saves:
    ml/model.pkl   - trained sklearn pipeline

Run:
    python ml/train_model.py
"""

import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

HERE = os.path.dirname(__file__)
DATA = os.path.join(HERE, "dataset.csv")
MODEL = os.path.join(HERE, "model.pkl")

FEATURES = ["packet_size", "req_per_sec", "failed_logins", "unusual_port"]


def train():
    if not os.path.exists(DATA):
        raise SystemExit(f"Dataset missing. Run: python ml/generate_dataset.py")

    df = pd.read_csv(DATA)
    X = df[FEATURES]

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=150,
            contamination=0.17,   # ~ fraction of attack samples in data
            random_state=42,
        )),
    ])
    pipe.fit(X)

    # Quick sanity check on training data.
    preds = pipe.predict(X)           # 1 = normal, -1 = anomaly
    anomaly_flag = (preds == -1).astype(int)
    agreement = (anomaly_flag == df["label"]).mean()
    print(f"[INFO] Train-set agreement with labels: {agreement:.2%}")

    joblib.dump({"pipeline": pipe, "features": FEATURES}, MODEL)
    print(f"[OK] Saved model -> {MODEL}")


if __name__ == "__main__":
    train()
