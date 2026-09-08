import os
import joblib


MODEL_PATH = "data/models/isolation_forest.joblib"


def load_baseline():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Behavioral baseline not found: {MODEL_PATH}"
        )

    bundle = joblib.load(MODEL_PATH)

    return bundle["model"], bundle["features"]


def predict_anomalies(df):
    model, features = load_baseline()

    X = df[features].copy()

    predictions = model.predict(X)
    scores = model.decision_function(X)

    result = df.copy()
    result["anomaly"] = predictions
    result["anomaly_score"] = scores

    return result