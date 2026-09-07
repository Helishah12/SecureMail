from sklearn.ensemble import IsolationForest


BEHAVIORAL_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "avg_packet_size",
]


def train_isolation_forest(df):
    X = df[BEHAVIORAL_FEATURES].copy()

    X = X.fillna(X.median())

    model = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42
    )

    model.fit(X)

    result = df.copy()

    # +1 = normal
    # -1 = anomalous
    result["anomaly"] = model.predict(X)

    # Lower / more negative = more anomalous
    result["anomaly_score"] = model.decision_function(X)

    return model, result