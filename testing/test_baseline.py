import os
import glob
import pandas as pd

from backend.analysis.feature_extractor import extract_features
from backend.models.isolation_forest import predict_anomalies


PCAP_DIR = "data/PCAPs"
BASELINE_DATASET = "data/dataset.csv"
OUTPUT_FILE = "data/pcap_baseline_results.csv"

BEHAVIORAL_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "avg_packet_size",
]


def prepare_features(sessions):
    df = pd.DataFrame(sessions)

    if df.empty:
        return df

    df["session_duration_seconds"] = (
        df["session_end"] - df["session_start"]
    )

    df["bytes_total"] = (
        df["bytes_sent"] + df["bytes_received"]
    )

    df["avg_packet_size"] = (
        df["bytes_total"] / df["packet_count"]
    )

    return df


def print_session_details(analyzed, baseline):
    print("\n  Session details:")

    for _, row in analyzed.iterrows():
        status = "ANOMALY" if row["anomaly"] == -1 else "NORMAL"

        print(f"\n  [{status}] {row['session_id']}")
        print(f"    Protocol: {row['protocol']}")
        print(f"    Anomaly score: {row['anomaly_score']:.6f}")

        print("\n    Behavioral features:")

        for feature in BEHAVIORAL_FEATURES:
            value = row[feature]

            percentile = (
                baseline[feature] <= value
            ).mean() * 100

            print(
                f"      {feature}: "
                f"{value:.3f} "
                f"({percentile:.1f}th percentile)"
            )


def main():
    files = sorted(
        glob.glob(os.path.join(PCAP_DIR, "*.pcap"))
        + glob.glob(os.path.join(PCAP_DIR, "*.pcapng"))
    )

    if not files:
        print(f"No PCAP files found in {PCAP_DIR}")
        return

    baseline = pd.read_csv(BASELINE_DATASET)

    missing_features = [
        feature
        for feature in BEHAVIORAL_FEATURES
        if feature not in baseline.columns
    ]

    if missing_features:
        print("Baseline dataset is missing:")
        for feature in missing_features:
            print(f"  {feature}")
        return

    results = []

    for path in files:
        filename = os.path.basename(path)

        print("\n" + "=" * 60)
        print(f"Analyzing: {filename}")
        print("=" * 60)

        try:
            sessions = extract_features(path)

            if not sessions:
                print("  No mail sessions detected")

                continue

            df = prepare_features(sessions)

            analyzed = predict_anomalies(df)

            anomalies = (
                analyzed["anomaly"] == -1
            ).sum()

            total = len(analyzed)

            print(f"  Sessions: {total}")
            print(f"  Anomalies: {anomalies}")
            print(f"  Normal: {total - anomalies}")
            print(
                f"  Anomaly rate: "
                f"{anomalies / total * 100:.2f}%"
            )

            print_session_details(
                analyzed,
                baseline
            )

            for _, row in analyzed.iterrows():
                results.append({
                    "file": filename,
                    "session_id": row["session_id"],
                    "protocol": row["protocol"],
                    "anomaly": int(row["anomaly"]),
                    "anomaly_score": float(
                        row["anomaly_score"]
                    ),
                    **{
                        feature: row[feature]
                        for feature in BEHAVIORAL_FEATURES
                    }
                })

        except Exception as e:
            print(f"\n  ERROR: {e}")

    result_df = pd.DataFrame(results)

    if result_df.empty:
        print("\nNo sessions were successfully analyzed.")
        return

    result_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    valid = result_df["anomaly"].notna()

    print(f"Files tested: {len(files)}")
    print(f"Sessions analyzed: {valid.sum()}")
    print(
        f"Anomalous sessions: "
        f"{(result_df.loc[valid, 'anomaly'] == -1).sum()}"
    )
    print(
        f"Normal sessions: "
        f"{(result_df.loc[valid, 'anomaly'] == 1).sum()}"
    )

    print("\nResults by file:")

    for filename, group in result_df.groupby("file"):
        anomalies = (
            group["anomaly"] == -1
        ).sum()

        total = len(group)

        print(
            f"  {filename}: "
            f"{anomalies}/{total} anomalous "
            f"({anomalies / total * 100:.2f}%)"
        )

    print(f"\nResults saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()