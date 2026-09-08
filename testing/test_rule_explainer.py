from backend.analysis.rule_engine import evaluate_session
from backend.explainer.rule_explainer import explain_findings


def test_session(name, features):
    result = evaluate_session(features)

    explanations = explain_findings(result["findings"])

    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    print(f"Risk score : {result['risk_score']}")
    print(f"Risk level : {result['risk_level']}")

    for explanation in explanations:
        print(f"\n[{explanation['severity']}] {explanation['rule']}")
        print(f"Finding    : {explanation['finding']}")
        print(f"Points     : +{explanation['points']}")
        print(f"Explanation: {explanation['explanation']}")



test_session(
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


test_session(
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



test_session(
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


test_session(
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