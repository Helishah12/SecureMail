import pandas as pd

from backend.analysis.feature_extractor import extract_features


PCAP = "data/PCAPs/test0.pcapng"


def main():
    sessions = extract_features(PCAP)

    df = pd.DataFrame(sessions)

    print(df[
        [
            "session_start",
            "session_end",
            "packet_count",
            "bytes_sent",
            "bytes_received",
            "tls_handshake_duration",
        ]
    ].to_string(index=False))


if __name__ == "__main__":
    main()