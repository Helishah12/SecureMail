RULE_EXPLANATIONS = {
    "TLS_VERSION": {
        "TLS 1.2": (
            "TLS 1.2 provides encrypted communication but is older than "
            "TLS 1.3 and lacks some of its security and performance improvements."
        ),
        "TLS 1.1": (
            "TLS 1.1 is obsolete and should no longer be used for secure "
            "mail communication."
        ),
        "TLS 1.0": (
            "TLS 1.0 is obsolete and vulnerable to known security weaknesses. "
            "Modern secure mail services should use TLS 1.2 or TLS 1.3."
        ),
    },

    "ENCRYPTION": (
        "The session was not protected by TLS encryption. Communication may "
        "be exposed to interception or modification while in transit."
    ),

    "STARTTLS_FAILURE": (
        "The server offered STARTTLS but the TLS negotiation failed. "
        "This can cause the connection to continue without the intended "
        "transport encryption."
    ),

    "CERT_EXPIRED": (
        "The certificate has expired. An expired certificate cannot provide "
        "valid assurance that the server's identity is currently trusted."
    ),

    "CERT_NOT_YET_VALID": (
        "The certificate is not yet valid according to its validity period. "
        "This may indicate an incorrectly configured or invalid certificate."
    ),

    "SELF_SIGNED": (
        "The certificate is self-signed rather than being signed by a "
        "trusted certificate authority. Server identity is therefore harder "
        "to verify automatically."
    ),

    "HOSTNAME_MISMATCH": (
        "The certificate hostname does not match the server being contacted. "
        "This can indicate a certificate misconfiguration and may prevent "
        "reliable verification of the server's identity."
    ),

    "WEAK_KEY": (
        "The RSA certificate uses a key smaller than 2048 bits. "
        "Small RSA keys provide weaker cryptographic security."
    ),

    "WEAK_SIGNATURE": {
        "SHA-1": (
            "The certificate uses SHA-1, a deprecated hashing algorithm "
            "with known collision weaknesses."
        ),
        "MD5": (
            "The certificate uses MD5, a cryptographically broken hashing "
            "algorithm that should not be used for certificate signatures."
        ),
    },

    "NO_FORWARD_SECRECY": (
        "The session does not provide forward secrecy. If the server's "
        "long-term private key is compromised, previously recorded encrypted "
        "traffic may be at greater risk of decryption."
    ),
}


RULE_RECOMMENDATIONS = {
    "TLS_VERSION": {
        "TLS 1.2": (
            "Prefer TLS 1.3 where supported. If TLS 1.2 is required for "
            "compatibility, ensure it is securely configured."
        ),
        "TLS 1.1": (
            "Disable TLS 1.1 and upgrade the mail server to support "
            "TLS 1.2 or TLS 1.3."
        ),
        "TLS 1.0": (
            "Disable TLS 1.0 and upgrade the mail server to support "
            "TLS 1.2 or TLS 1.3."
        ),
    },

    "ENCRYPTION": (
        "Enable TLS encryption for the mail service and avoid transmitting "
        "mail credentials or content over plaintext connections."
    ),

    "STARTTLS_FAILURE": (
        "Investigate the TLS negotiation failure and correct the server "
        "or certificate configuration. Prevent fallback to plaintext "
        "where possible."
    ),

    "CERT_EXPIRED": (
        "Renew the expired certificate and install a currently valid "
        "certificate on the mail server."
    ),

    "CERT_NOT_YET_VALID": (
        "Check the certificate validity dates and verify the server/client "
        "system clock. Install the correct certificate if necessary."
    ),

    "SELF_SIGNED": (
        "Replace the self-signed certificate with a certificate issued by "
        "a trusted certificate authority, where appropriate."
    ),

    "HOSTNAME_MISMATCH": (
        "Install a certificate whose hostname or SAN matches the mail "
        "server being contacted and verify the server configuration."
    ),

    "WEAK_KEY": (
        "Replace the weak RSA certificate with one using a key size of "
        "at least 2048 bits."
    ),

    "WEAK_SIGNATURE": {
        "SHA-1": (
            "Replace the certificate with one using a modern signature "
            "algorithm such as SHA-256 or stronger."
        ),
        "MD5": (
            "Replace the certificate with one using a modern cryptographic "
            "signature algorithm such as SHA-256 or stronger."
        ),
    },

    "NO_FORWARD_SECRECY": (
        "Configure the mail server to use TLS cipher suites and key "
        "exchange mechanisms that provide forward secrecy."
    ),
}


def explain_finding(finding):

    rule = finding.get("rule")
    message = finding.get("message", "")
    severity = finding.get("severity")
    points = finding.get("points", 0)

    explanation = None
    recommendation = None

    if rule == "TLS_VERSION":

        if "TLS 1.2" in message:
            explanation = RULE_EXPLANATIONS["TLS_VERSION"]["TLS 1.2"]
            recommendation = RULE_RECOMMENDATIONS["TLS_VERSION"]["TLS 1.2"]

        elif "TLS 1.1" in message:
            explanation = RULE_EXPLANATIONS["TLS_VERSION"]["TLS 1.1"]
            recommendation = RULE_RECOMMENDATIONS["TLS_VERSION"]["TLS 1.1"]

        elif "TLS 1.0" in message:
            explanation = RULE_EXPLANATIONS["TLS_VERSION"]["TLS 1.0"]
            recommendation = RULE_RECOMMENDATIONS["TLS_VERSION"]["TLS 1.0"]


    elif rule == "WEAK_SIGNATURE":

        if "SHA-1" in message or "SHA1" in message.upper():
            explanation = RULE_EXPLANATIONS["WEAK_SIGNATURE"]["SHA-1"]
            recommendation = RULE_RECOMMENDATIONS["WEAK_SIGNATURE"]["SHA-1"]

        elif "MD5" in message.upper():
            explanation = RULE_EXPLANATIONS["WEAK_SIGNATURE"]["MD5"]
            recommendation = RULE_RECOMMENDATIONS["WEAK_SIGNATURE"]["MD5"]



    else:
        explanation = RULE_EXPLANATIONS.get(rule)
        recommendation = RULE_RECOMMENDATIONS.get(rule)


    if explanation is None:
        explanation = message

    if recommendation is None:
        recommendation = (
            "Review the affected mail server configuration and investigate "
            "the reported security finding."
        )

    return {
        "rule": rule,
        "severity": severity,
        "points": points,
        "finding": message,
        "explanation": explanation,
        "recommendation": recommendation,
    }


def explain_findings(findings):

    return [
        explain_finding(finding)
        for finding in findings
    ]