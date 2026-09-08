import pandas as pd

from backend.analysis.rule_engine import evaluate_session
from backend.explainer.rule_explainer import explain_findings
from backend.explainer.anomaly_explainer import build_explanation


def test_rule_explainer(name, features):
    result = evaluate_session(features)
    explanations = explain_findings(result["findings"])

    print("\n" + "=" * 75)
    print(f"RULE EXPLAINER: {name}")
    print("=" * 75)

    print(f"Risk score : {result['risk_score']}")
    print(f"Risk level : {result['risk_level']}")

    assert len(explanations) == len(result["findings"])

    for explanation in explanations:

        print(f"\n[{explanation['severity']}] {explanation['rule']}")
        print(f"Finding        : {explanation['finding']}")
        print(f"Points         : +{explanation['points']}")
        print(f"Explanation    : {explanation['explanation']}")
        print(f"Recommendation : {explanation['recommendation']}")

        # Every finding must have an explanation
        assert explanation["explanation"]
        assert explanation["explanation"].strip()

        # Every finding must have a recommendation
        assert explanation["recommendation"]
        assert explanation["recommendation"].strip()



test_rule_explainer(
    "Self-signed TLS 1.2",
    {
        "tls_version": "TLS 1.2",
        "starttls_offered": 1,
        "starttls_success": 1,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "self_signed": 1,
        "hostname_match": 1,
        "cert_key_algorithm": "RSA",
        "cert_key_size": 2048,
        "cert_signature_algorithm": "SHA256_RSA",
        "forward_secrecy": 1,
    }
)


test_rule_explainer(
    "Expired certificate",
    {
        "tls_version": "TLS 1.2",
        "starttls_offered": 1,
        "starttls_success": 1,
        "cert_expired": 1,
        "cert_not_yet_valid": 0,
        "self_signed": 0,
        "hostname_match": 1,
        "cert_key_algorithm": "RSA",
        "cert_key_size": 2048,
        "cert_signature_algorithm": "SHA256_RSA",
        "forward_secrecy": 1,
    }
)


test_rule_explainer(
    "Multiple security weaknesses",
    {
        "tls_version": "TLS 1.0",
        "starttls_offered": 1,
        "starttls_success": 1,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "self_signed": 1,
        "hostname_match": 0,
        "cert_key_algorithm": "RSA",
        "cert_key_size": 1024,
        "cert_signature_algorithm": "SHA1_RSA",
        "forward_secrecy": 0,
    }
)


test_rule_explainer(
    "Plaintext with STARTTLS failure",
    {
        "tls_version": None,
        "starttls_offered": 1,
        "starttls_success": 0,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "self_signed": 0,
        "hostname_match": 1,
        "cert_key_algorithm": "RSA",
        "cert_key_size": 2048,
        "cert_signature_algorithm": "SHA256_RSA",
        "forward_secrecy": 0,
    }
)


test_rule_explainer(
    "Secure TLS 1.3",
    {
        "tls_version": "TLS 1.3",
        "starttls_offered": 1,
        "starttls_success": 1,
        "cert_expired": 0,
        "cert_not_yet_valid": 0,
        "self_signed": 0,
        "hostname_match": 1,
        "cert_key_algorithm": "RSA",
        "cert_key_size": 2048,
        "cert_signature_algorithm": "SHA256_RSA",
        "forward_secrecy": 1,
    }
)


print("\n" + "=" * 75)
print("ANOMALY EXPLAINER")
print("=" * 75)


# Synthetic reference population.
# Values are deliberately varied so percentile calculations
# have meaningful high/low values.

df = pd.DataFrame({
    "packet_count": [
        100, 120, 150, 180, 200,
        220, 250, 280, 300, 350,
        400, 450, 500, 550, 600,
        650, 700, 750, 800, 900
    ],

    "bytes_sent": [
        1000, 1200, 1500, 1800, 2000,
        2200, 2500, 2800, 3000, 3500,
        4000, 4500, 5000, 5500, 6000,
        6500, 7000, 7500, 8000, 9000
    ],

    "bytes_received": [
        2000, 2200, 2500, 2800, 3000,
        3200, 3500, 3800, 4000, 4500,
        5000, 5500, 6000, 6500, 7000,
        7500, 8000, 8500, 9000, 10000
    ],

    "retransmission_count": [
        0, 0, 0, 1, 1,
        1, 1, 2, 2, 2,
        2, 3, 3, 3, 4,
        4, 5, 5, 6, 7
    ],

    "tls_handshake_duration": [
        0.01, 0.02, 0.03, 0.04, 0.05,
        0.06, 0.07, 0.08, 0.09, 0.10,
        0.11, 0.12, 0.13, 0.14, 0.15,
        0.16, 0.17, 0.18, 0.19, 0.20
    ],

    "session_duration_seconds": [
        1, 2, 3, 4, 5,
        6, 7, 8, 9, 10,
        11, 12, 13, 14, 15,
        16, 17, 18, 19, 20
    ],

    "avg_packet_size": [
        100, 110, 120, 130, 140,
        150, 160, 170, 180, 190,
        200, 210, 220, 230, 240,
        250, 260, 270, 280, 290
    ]
})


anomalous_row = pd.Series({
    "packet_count": 5000,
    "bytes_sent": 50000,
    "bytes_received": 60000,
    "retransmission_count": 20,
    "tls_handshake_duration": 2.0,
    "session_duration_seconds": 100,
    "avg_packet_size": 1000
})


anomaly_explanations = build_explanation(
    df,
    anomalous_row
)


print("\nAnomalous session:")

assert len(anomaly_explanations) > 0
assert len(anomaly_explanations) <= 3

for explanation in anomaly_explanations:

    print(f"\nFeature        : {explanation['feature']}")
    print(f"Description    : {explanation['description']}")
    print(f"Percentile     : {explanation['percentile']:.1f}")
    print(f"Recommendation : {explanation['recommendation']}")

    assert explanation["description"]
    assert explanation["recommendation"]
    assert explanation["recommendation"].strip()


low_anomaly_row = pd.Series({
    "packet_count": 1,
    "bytes_sent": 1,
    "bytes_received": 1,
    "retransmission_count": 0,
    "tls_handshake_duration": 0.001,
    "session_duration_seconds": 0.1,
    "avg_packet_size": 10
})


low_explanations = build_explanation(
    df,
    low_anomaly_row
)


print("\nLow-value anomalous session:")

assert len(low_explanations) > 0
assert len(low_explanations) <= 3

for explanation in low_explanations:

    print(f"\nFeature        : {explanation['feature']}")
    print(f"Description    : {explanation['description']}")
    print(f"Percentile     : {explanation['percentile']:.1f}")
    print(f"Recommendation : {explanation['recommendation']}")

    assert explanation["description"]
    assert explanation["recommendation"]
    assert explanation["recommendation"].strip()


print("\n" + "=" * 75)
print("ALL EXPLAINER TESTS PASSED")
print("=" * 75)