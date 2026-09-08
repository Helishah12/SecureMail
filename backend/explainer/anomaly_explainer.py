FEATURE_NAMES = {
    "packet_count": "Packet count",
    "bytes_sent": "Bytes sent",
    "bytes_received": "Bytes received",
    "retransmission_count": "Retransmissions",
    "tls_handshake_duration": "TLS handshake duration",
    "session_duration_seconds": "Session duration",
    "avg_packet_size": "Average packet size",
}


FEATURE_ACTIONS = {
    "packet_count": (
        "Review the session for unusually high-volume or persistent "
        "communication and verify that the traffic is expected."
    ),

    "bytes_sent": (
        "Investigate the unusually high outbound data volume and verify "
        "that the mail server was expected to transmit this amount of data."
    ),

    "bytes_received": (
        "Investigate the unusually high inbound data volume and verify "
        "that the received traffic is expected."
    ),

    "retransmission_count": (
        "Investigate packet loss, network instability, congestion, or "
        "connection problems that could explain the retransmissions."
    ),

    "tls_handshake_duration": (
        "Investigate TLS negotiation performance, network latency, and "
        "server-side TLS configuration."
    ),

    "session_duration_seconds": (
        "Verify whether the unusually long-lived mail session is expected "
        "and investigate persistent connections that cannot be explained "
        "by normal mail-server activity."
    ),

    "avg_packet_size": (
        "Review the traffic characteristics and verify that the unusually "
        "large or small packet sizes are consistent with expected mail "
        "server behavior."
    ),
}


def build_explanation(df, row):

    explanations = []

    for feature in FEATURE_NAMES:

        value = row.get(feature)

        if value is None:
            continue

        # Ignore missing/invalid values.
        if feature not in df.columns:
            continue

        percentile = (df[feature] <= value).mean() * 100

        # --------------------------------------------------------
        # Unusually high
        # --------------------------------------------------------

        if percentile >= 95:

            explanations.append({
                "feature": feature,
                "description": (
                    f"{FEATURE_NAMES[feature]} is unusually high "
                    f"({percentile:.1f}th percentile)"
                ),
                "percentile": percentile,
                "recommendation": FEATURE_ACTIONS[feature],
            })


        elif percentile <= 5:

            explanations.append({
                "feature": feature,
                "description": (
                    f"{FEATURE_NAMES[feature]} is unusually low "
                    f"({percentile:.1f}th percentile)"
                ),
                "percentile": percentile,
                "recommendation": (
                    f"Review the session to determine whether the unusually "
                    f"low {FEATURE_NAMES[feature].lower()} is expected."
                ),
            })

    # Most extreme deviations first.
    explanations.sort(
        key=lambda x: abs(x["percentile"] - 50),
        reverse=True
    )

    return explanations[:3]