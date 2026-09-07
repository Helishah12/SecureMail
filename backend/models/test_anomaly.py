import pandas as pd

from isolation_forest import train_isolation_forest

df = pd.read_csv("../../data/dataset.csv")

print(f"Total sessions: {len(df)}")

model, result = train_isolation_forest(df)


print("\nAnomaly counts:")
print(result["anomaly"].value_counts())

anomaly_count = (result["anomaly"] == -1).sum()
anomaly_percentage = anomaly_count / len(result) * 100

print(f"\nAnomalies detected: {anomaly_count}")
print(f"Anomaly percentage: {anomaly_percentage:.3f}%")


BEHAVIORAL_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "avg_packet_size",
]

columns_to_show = [
    "session_id",
    *BEHAVIORAL_FEATURES,
    "anomaly_score",
]

print("\nMost anomalous sessions:")

print(
    result[result["anomaly"] == -1]
    .sort_values("anomaly_score")
    [columns_to_show]
    .head(10)
    .to_string(index=False)
)



print("\nMost normal sessions:")

print(
    result[result["anomaly"] == 1]
    .sort_values("anomaly_score", ascending=False)
    [columns_to_show]
    .head(10)
    .to_string(index=False)
)


print("\nAnomaly score statistics:")

print(
    result.groupby("anomaly")["anomaly_score"]
    .describe()
)