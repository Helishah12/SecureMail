def evaluate_session(features):
    score = 0
    findings = []

    def add_finding(rule, severity, message, points):
        nonlocal score

        score += points

        findings.append({
            "rule": rule,
            "severity": severity,
            "message": message,
            "points": points
        })

    # ============================================================
    # A. TLS / ENCRYPTION
    # ============================================================

    tls = features.get("tls_version")

    if tls == "TLS 1.3":
        pass

    elif tls == "TLS 1.2":
        add_finding(
            "TLS_VERSION",
            "LOW",
            "TLS 1.2 detected",
            5
        )

    elif tls == "TLS 1.1":
        add_finding(
            "TLS_VERSION",
            "HIGH",
            "TLS 1.1 detected",
            25
        )

    elif tls == "TLS 1.0":
        add_finding(
            "TLS_VERSION",
            "HIGH",
            "TLS 1.0 detected",
            35
        )

    else:
        add_finding(
            "ENCRYPTION",
            "HIGH",
            "No encryption / plaintext detected",
            35
        )

    # STARTTLS offered but failed
    if (
        features.get("starttls_offered") is True
        and features.get("starttls_success") is False
    ):
        add_finding(
            "STARTTLS_FAILURE",
            "HIGH",
            "STARTTLS was offered but negotiation failed",
            30
        )

    # ============================================================
    # B. CERTIFICATE
    # ============================================================

    if features.get("cert_expired") is True:
        add_finding(
            "CERT_EXPIRED",
            "HIGH",
            "Certificate has expired",
            25
        )

    if features.get("cert_not_yet_valid") is True:
        add_finding(
            "CERT_NOT_YET_VALID",
            "HIGH",
            "Certificate is not yet valid",
            20
        )

    if features.get("self_signed") is True:
        add_finding(
            "SELF_SIGNED",
            "MEDIUM",
            "Certificate is self-signed",
            15
        )

    if features.get("hostname_match") is False:
        add_finding(
            "HOSTNAME_MISMATCH",
            "HIGH",
            "Certificate hostname does not match",
            20
        )

    # ============================================================
    # C. CRYPTOGRAPHIC KEY
    # ============================================================

    key_algorithm = features.get("cert_key_algorithm")
    key_size = features.get("cert_key_size")

    if key_algorithm == "RSA":
        if key_size is not None and key_size < 2048:
            add_finding(
                "WEAK_KEY",
                "HIGH",
                f"Weak RSA key size: {key_size} bits",
                20
            )

    # ECDSA is currently informational because the extractor
    # does not yet expose the curve size.
    elif key_algorithm == "ECDSA":
        pass

    # ============================================================
    # D. SIGNATURE ALGORITHM
    # ============================================================

    signature = features.get("cert_signature_algorithm")

    if signature is not None:
        signature = str(signature).upper()

        if "SHA1" in signature or "SHA-1" in signature:
            add_finding(
                "WEAK_SIGNATURE",
                "MEDIUM",
                "Certificate uses SHA-1 signature algorithm",
                10
            )

        elif "MD5" in signature:
            add_finding(
                "WEAK_SIGNATURE",
                "MEDIUM",
                "Certificate uses MD5 signature algorithm",
                10
            )

    # ============================================================
    # E. FORWARD SECRECY
    # ============================================================

    if features.get("forward_secrecy") is False:
        add_finding(
            "NO_FORWARD_SECRECY",
            "MEDIUM",
            "Session does not provide forward secrecy",
            10
        )

    # ============================================================
    # RISK LEVEL
    # ============================================================

    if score >= 70:
        risk_level = "CRITICAL"

    elif score >= 40:
        risk_level = "HIGH"

    elif score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "findings": findings
    }