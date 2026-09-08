import pandas as pd
import numpy as np

DATASET = "data/dataset.csv"

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

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\nColumns:")
    for col in df.columns:
        print(f"  {col}")

    # Create derived behavioral features if needed
    if "session_duration_seconds" not in df.columns:
        if "session_start" in df.columns and "session_end" in df.columns:
            df["session_start"] = pd.to_datetime(df["session_start"])
            df["session_end"] = pd.to_datetime(df["session_end"])
            df["session_duration_seconds"] = (
                df["session_end"] - df["session_start"]
            ).dt.total_seconds()

    if "avg_packet_size" not in df.columns:
        if {"bytes_sent", "bytes_received", "packet_count"} <= set(df.columns):
            df["avg_packet_size"] = (
                df["bytes_sent"] + df["bytes_received"]
            ) / df["packet_count"].replace(0, np.nan)

    print("\nBehavioral feature availability:")
    for feature in BEHAVIORAL_FEATURES:
        if feature in df.columns:
            print(f"  ✓ {feature}")
        else:
            print(f"  ✗ {feature} MISSING")

    available = [
        f for f in BEHAVIORAL_FEATURES
        if f in df.columns
    ]

    if not available:
        print("\nNo behavioral features available.")
        return

    print("\nMissing values:")
    for feature in available:
        missing = df[feature].isna().sum()
        print(f"  {feature}: {missing} ({missing / len(df) * 100:.2f}%)")

    print("\nBasic statistics:")
    print(
        df[available]
        .describe()
        .T[
            ["count", "mean", "std", "min", "25%", "50%", "75%", "max"]
        ]
        .to_string()
    )

    print("\nUnique values:")
    for feature in available:
        print(f"  {feature}: {df[feature].nunique()}")

    print("\nZero values:")
    for feature in available:
        zeros = (df[feature] == 0).sum()
        print(f"  {feature}: {zeros} ({zeros / len(df) * 100:.2f}%)")

    print("\nNegative values:")
    for feature in available:
        negatives = (df[feature] < 0).sum()
        print(f"  {feature}: {negatives}")

    print("\nExtreme values (> 99th percentile):")
    for feature in available:
        p99 = df[feature].quantile(0.99)
        count = (df[feature] > p99).sum()
        print(
            f"  {feature}: threshold={p99:.3f}, "
            f"count={count}"
        )

    if "protocol" in df.columns:
        print("\nProtocol distribution:")
        print(df["protocol"].value_counts().to_string())

    if "encryption_mode" in df.columns:
        print("\nEncryption distribution:")
        print(df["encryption_mode"].value_counts().to_string())

    for label in ["risk_level", "security_risk_level", "label"]:
        if label in df.columns:
            print(f"\n{label} distribution:")
            print(df[label].value_counts().to_string())

    print("\nFeature correlations:")
    print(
        df[available]
        .corr()
        .round(3)
        .to_string()
    )


if __name__ == "__main__":
    main()