BEHAVIORAL_FEATURES = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "avg_packet_size",
]


FEATURE_NAMES = {
    "packet_count": "Packet count",
    "bytes_sent": "Bytes sent",
    "bytes_received": "Bytes received",
    "retransmission_count": "Retransmissions",
    "tls_handshake_duration": "TLS handshake duration",
    "session_duration_seconds": "Session duration",
    "avg_packet_size": "Average packet size",
}


def build_explanation(df, row):
    explanations = []

    for feature in BEHAVIORAL_FEATURES:
        value = row[feature]

        if value is None:
            continue

        percentile = (df[feature] <= value).mean() * 100

        if percentile >= 95:
            explanations.append({
                "feature": feature,
                "description": (
                    f"{FEATURE_NAMES[feature]} is unusually high "
                    f"({percentile:.1f}th percentile)"
                ),
                "percentile": percentile,
            })

        elif percentile <= 5:
            explanations.append({
                "feature": feature,
                "description": (
                    f"{FEATURE_NAMES[feature]} is unusually low "
                    f"({percentile:.1f}th percentile)"
                ),
                "percentile": percentile,
            })

    explanations.sort(
        key=lambda x: abs(x["percentile"] - 50),
        reverse=True
    )

    return explanations[:3]