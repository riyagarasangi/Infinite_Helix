"""
Module 5: ML-based Anomaly Detection.

Loads the trained Isolation Forest (ml/model.pkl) and evaluates either:
    1) the full synthetic dataset (for a dashboard view), or
    2) a single user-provided record.
"""

import os
import joblib
import pandas as pd

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "..", "ml", "model.pkl")
DATA_PATH = os.path.join(HERE, "..", "ml", "dataset.csv")


def _load():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "Model not trained yet. Run:\n"
            "    python ml/generate_dataset.py\n"
            "    python ml/train_model.py"
        )
    blob = joblib.load(MODEL_PATH)
    return blob["pipeline"], blob["features"]


def evaluate_dataset() -> dict:
    pipe, feats = _load()
    df = pd.read_csv(DATA_PATH)
    preds = pipe.predict(df[feats])            # 1 = normal, -1 = anomaly
    scores = pipe.decision_function(df[feats]) # higher = more normal
    df = df.copy()
    df["prediction"] = ["anomaly" if p == -1 else "normal" for p in preds]
    df["score"] = scores.round(4)

    total = len(df)
    anomalies = int((df["prediction"] == "anomaly").sum())
    # true_label is for display only
    true_positives = int(((df["prediction"] == "anomaly") & (df["label"] == 1)).sum())
    false_positives = int(((df["prediction"] == "anomaly") & (df["label"] == 0)).sum())

    # return a small sample (first 40) so the table renders fast
    sample = df.head(40).to_dict(orient="records")
    return {
        "total": total,
        "anomalies": anomalies,
        "normal": total - anomalies,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "sample": sample,
        "features": feats,
        "score_bins": _histogram(scores),
    }


def predict_one(record: dict) -> dict:
    pipe, feats = _load()
    row = pd.DataFrame([[float(record.get(f, 0)) for f in feats]], columns=feats)
    pred = int(pipe.predict(row)[0])
    score = float(pipe.decision_function(row)[0])
    return {
        "label": "anomaly" if pred == -1 else "normal",
        "is_anomaly": pred == -1,
        "score": round(score, 4),
        "input": record,
    }


def _histogram(scores, bins: int = 10):
    lo, hi = float(min(scores)), float(max(scores))
    if hi == lo:
        return [{"range": f"{lo:.2f}", "count": len(scores)}]
    step = (hi - lo) / bins
    counts = [0] * bins
    for s in scores:
        idx = min(int((s - lo) / step), bins - 1)
        counts[idx] += 1
    return [
        {
            "range": f"{lo + i*step:.2f} .. {lo + (i+1)*step:.2f}",
            "count": c,
        }
        for i, c in enumerate(counts)
    ]
