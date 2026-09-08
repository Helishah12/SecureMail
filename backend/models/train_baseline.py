import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

DATASET = "data/dataset.csv"
MODEL_PATH = "data/models/isolation_forest.joblib"

BEHAVIORAL_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "avg_packet_size",
]


def main():
    df = pd.read_csv(DATASET)

    X = df[BEHAVIORAL_FEATURES].copy()

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": BEHAVIORAL_FEATURES
        },
        MODEL_PATH
    )

    predictions = model.predict(X)
    anomaly_count = (predictions == -1).sum()

    print(f"Training samples: {len(X)}")
    print(f"Features: {len(BEHAVIORAL_FEATURES)}")
    print(f"Anomalies in training data: {anomaly_count}")
    print(f"Anomaly rate: {anomaly_count / len(X) * 100:.2f}%")
    print(f"Model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()