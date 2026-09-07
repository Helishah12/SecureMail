import sys
import re
import json
import shutil
import subprocess
import pandas as pd
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ============================================================
# TSHARK
# ============================================================

TSHARK = shutil.which("tshark")

if not TSHARK:
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]

    for path in candidates:
        if shutil.which(path):
            TSHARK = path
            break

if not TSHARK:
    raise RuntimeError(
        "TShark not found. Install Wireshark or add TShark to PATH."
    )


# ============================================================
# EMAIL PORTS
# ============================================================

PORT_PROTOCOL = {
    25: "SMTP",
    465: "SMTP",
    587: "SMTP",
    143: "IMAP",
    993: "IMAP",
    110: "POP3",
    995: "POP3"
}

IMPLICIT_TLS_PORTS = {465, 993, 995}


# ============================================================
# TSHARK FIELD DISCOVERY
# ============================================================

def get_available_fields():
    result = subprocess.run(
        [TSHARK, "-G", "fields"],
        capture_output=True,
        text=True,
        errors="ignore"
    )

    fields = set()

    for line in result.stdout.splitlines():

        if not line.startswith("F"):
            continue

        matches = re.findall(
            r"\b[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+\b",
            line
        )

        for field in matches:
            fields.add(field)

    return fields


AVAILABLE = get_available_fields()


def pick(*names):
    for name in names:
        if name in AVAILABLE:
            return name
    return None


# ============================================================
# FIELDS
# ============================================================

F = {
    "time": pick("frame.time_epoch"),
    "stream": pick("tcp.stream"),

    "src": pick("ip.src", "ipv6.src"),
    "dst": pick("ip.dst", "ipv6.dst"),

    "srcport": pick("tcp.srcport"),
    "dstport": pick("tcp.dstport"),

    "tcp_len": pick("tcp.len"),

    # Raw application payload lets us identify email protocols even when
    # they use non-standard ports (for example SMTP on 2525).
    "payload": pick("tcp.payload"),

    "retrans": pick(
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission"
    ),

    "smtp": pick(
        "smtp.request",
        "smtp.response"
    ),

    "imap": pick(
        "imap.request",
        "imap.response"
    ),

    "pop": pick(
        "pop.request",
        "pop.response"
    ),

    "tls_type": pick("tls.handshake.type"),

    "tls_version": pick(
        "tls.handshake.version",
        "tls.handshake.extensions.supported_version"
    ),

    "cipher": pick(
        "tls.handshake.ciphersuite"
    ),

    "sni": pick(
        "tls.handshake.extensions_server_name"
    ),

    "keyshare": pick(
        "tls.handshake.extensions_key_share_group",
        "tls.handshake.extensions_key_share_selected_group"
    ),

    "certificate": pick(
        "tls.handshake.certificate"
    )
}


# ============================================================
# READ PCAP
# ============================================================

def read_pcap(path):

    fields = [
        x for x in F.values()
        if x is not None
    ]

    cmd = [
        TSHARK,
        "-r",
        path,
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=a"
    ]

    for field in fields:
        cmd.extend(["-e", field])

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="ignore"
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    lines = result.stdout.splitlines()

    if not lines:
        return pd.DataFrame()

    header = lines[0].split("\t")

    rows = []

    for line in lines[1:]:
        values = line.split("\t")

        if len(values) < len(header):
            values += [""] * (len(header) - len(values))

        if len(values) > len(header):
            values = values[:len(header)]

        rows.append(values)

    df = pd.DataFrame(rows, columns=header)

    # Map actual TShark column names back to our logical names
    rename = {}

    for logical, actual in F.items():
        if actual and actual in df.columns:
            rename[actual] = logical

    df.rename(columns=rename, inplace=True)

    print(f"Packets read: {len(df)}")

    return df


# ============================================================
# HELPERS
# ============================================================

def clean(value):

    if value is None:
        return ""

    if pd.isna(value):
        return ""

    return str(value).strip()


def contains_value(value, pattern):

    value = clean(value)

    return bool(
        re.search(
            pattern,
            value,
            re.IGNORECASE
        )
    )


def first_value(series):

    for value in series:

        value = clean(value)

        if value:
            return value

    return None


# ============================================================
# PROTOCOL DETECTION
# ============================================================

def detect_protocol(session):

    # --------------------------------------------------------
    # 1. Strongest evidence: TShark's protocol dissectors
    # --------------------------------------------------------
    for column, protocol in [
        ("smtp", "SMTP"),
        ("imap", "IMAP"),
        ("pop", "POP3")
    ]:

        if column in session.columns:

            for value in session[column]:

                if clean(value):
                    return protocol

    # --------------------------------------------------------
    # 2. Raw plaintext application data.
    # This is what allows SMTP/IMAP/POP3 on non-standard ports.
    # --------------------------------------------------------
    if "payload" in session.columns:

        for value in session["payload"]:

            value = clean(value)

            if not value:
                continue

            # TShark tcp.payload is normally hexadecimal.
            try:
                raw = bytes.fromhex(
                    value.replace(":", "").replace(" ", "")
                )
            except Exception:
                raw = value.encode(errors="ignore")

            upper = raw.upper()

            # SMTP
            if any(marker in upper for marker in [
                b"EHLO", b"HELO", b"MAIL FROM:",
                b"RCPT TO:", b"STARTTLS",
                b"220 ", b"250 ", b"354 "
            ]):
                return "SMTP"

            # IMAP
            if any(marker in upper for marker in [
                b"IMAP", b"CAPABILITY",
                b"AUTHENTICATE", b"SELECT ",
                b"FETCH ", b"STORE ", b"IDLE",
                b"STARTTLS"
            ]):
                # STARTTLS alone is ambiguous, so require another
                # IMAP marker if possible.
                if b"IMAP" in upper or any(
                    marker in upper for marker in [
                        b"CAPABILITY", b"AUTHENTICATE",
                        b"SELECT ", b"FETCH ",
                        b"STORE ", b"IDLE"
                    ]
                ):
                    return "IMAP"

            # POP3
            if any(marker in upper for marker in [
                b"+OK", b"-ERR", b"STLS",
                b"CAPA", b"USER ", b"PASS ",
                b"RETR ", b"LIST", b"TOP "
            ]):
                return "POP3"

    # --------------------------------------------------------
    # 3. Known-port fallback.
    # --------------------------------------------------------
    ports = []

    for column in ["srcport", "dstport"]:

        if column in session.columns:

            for value in session[column]:

                try:
                    ports.append(int(float(value)))
                except Exception:
                    pass

    for port in ports:

        if port in PORT_PROTOCOL:
            return PORT_PROTOCOL[port]

    # --------------------------------------------------------
    # 4. No reliable protocol evidence.
    # Do NOT guess SMTP/IMAP/POP3.
    # --------------------------------------------------------
    return "UNKNOWN"


# ============================================================
# TLS DETECTION
# ============================================================

def has_tls(session):

    if "tls_type" not in session.columns:
        return False

    for value in session["tls_type"]:

        if clean(value):
            return True

    return False


# ============================================================
# STARTTLS
# ============================================================

def detect_starttls(session):

    text = ""

    for column in ["smtp", "imap", "pop"]:

        if column in session.columns:

            text += " ".join(
                session[column]
                .astype(str)
                .tolist()
            ).upper()

    offered = 0
    success = 0

    if "STARTTLS" in text or "STLS" in text:
        offered = 1

    if (
        "220 TLS GO AHEAD" in text
        or "BEGIN TLS NEGOTIATION" in text
        or "+OK" in text and ("STLS" in text or "TLS" in text)
        or "OK BEGIN TLS" in text
    ):
        success = 1

    return offered, success


# ============================================================
# ENCRYPTION MODE
# ============================================================

def detect_encryption(session, protocol):

    offered, success = detect_starttls(session)

    ports = []

    for column in ["srcport", "dstport"]:

        if column in session.columns:

            for value in session[column]:

                try:
                    ports.append(int(float(value)))
                except:
                    pass

    if any(port in IMPLICIT_TLS_PORTS for port in ports):
        return "TLS", offered, success

    if success and has_tls(session):
        return "STARTTLS", offered, success

    if offered and has_tls(session):
        return "STARTTLS", offered, 1

    if has_tls(session):
        return "TLS", offered, success

    return "PLAINTEXT", offered, success


# ============================================================
# TLS VERSION
# ============================================================

def get_tls_version(session):

    if "tls_version" not in session.columns:
        return None

    values = []

    for value in session["tls_version"]:

        value = clean(value)

        if value:
            values.append(value)

    text = " ".join(values).lower()

    if "1.3" in text:
        return "TLS 1.3"

    if "1.2" in text:
        return "TLS 1.2"

    if "1.1" in text:
        return "TLS 1.1"

    if "1.0" in text:
        return "TLS 1.0"

    # TLS wire versions
    if "0x0304" in text:
        return "TLS 1.3"

    if "0x0303" in text:
        return "TLS 1.2"

    if "0x0302" in text:
        return "TLS 1.1"

    if "0x0301" in text:
        return "TLS 1.0"

    return None


# ============================================================
# CIPHER SUITE
# ============================================================

CIPHER_MAP = {

    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",

    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",

    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",

    0xC013: "ECDHE_RSA_AES_128_CBC_SHA",
    0xC014: "ECDHE_RSA_AES_256_CBC_SHA",

    0x002F: "RSA_AES_128_CBC_SHA",
    0x0035: "RSA_AES_256_CBC_SHA",

    0x000A: "RSA_3DES_EDE_CBC_SHA",
    0x0004: "RSA_RC4_128_MD5",
    0x0005: "RSA_RC4_128_SHA"
}


def cipher_name(value):

    value = clean(value)

    if not value:
        return None

    # TShark may return comma-separated occurrences.
    values = value.split(",")

    for item in values:

        item = item.strip()

        # Hex format
        match = re.search(
            r"0x([0-9a-fA-F]{4})",
            item
        )

        if match:

            cipher_id = int(
                match.group(1),
                16
            )

            return CIPHER_MAP.get(
                cipher_id,
                f"UNKNOWN_0x{cipher_id:04X}"
            )

        # Decimal ID
        if item.isdigit():

            cipher_id = int(item)

            if cipher_id in CIPHER_MAP:
                return CIPHER_MAP[cipher_id]

        # Already decoded by TShark
        if "_" in item or "TLS_" in item:

            return item

    return None


def get_cipher(session):

    if "cipher" not in session.columns:
        return None

    # Prefer ServerHello = handshake type 2
    if "tls_type" in session.columns:

        for _, row in session.iterrows():

            tls_type = clean(row.get("tls_type"))
            cipher = clean(row.get("cipher"))

            if (
                re.search(
                    r"(?:^|,)2(?:,|$)",
                    tls_type
                )
                and cipher
            ):

                result = cipher_name(cipher)

                if result:
                    return result

    # Fallback
    for value in session["cipher"]:

        result = cipher_name(value)

        if result:
            return result

    return None


# ============================================================
# KEY EXCHANGE
# ============================================================

def get_key_exchange(session, tls_version, cipher):

    cipher_text = clean(cipher).upper()

    if tls_version == "TLS 1.3":

        if "keyshare" in session.columns:

            for value in session["keyshare"]:

                if clean(value):
                    return "ECDHE"

        return "ECDHE"

    if "ECDHE" in cipher_text:
        return "ECDHE"

    if "DHE" in cipher_text:
        return "DHE"

    if "RSA" in cipher_text:
        return "RSA"

    return None


def get_forward_secrecy(key_exchange, tls_version):

    if tls_version == "TLS 1.3":
        return 1

    if key_exchange in ["ECDHE", "DHE"]:
        return 1

    if key_exchange == "RSA":
        return 0

    return None


# ============================================================
# CERTIFICATE
# ============================================================

def parse_certificate(session):

    result = {
        "cert_expired": None,
        "cert_not_yet_valid": None,
        "cert_key_algorithm": None,
        "cert_key_size": None,
        "cert_signature_algorithm": None,
        "self_signed": None,
        "hostname_match": None
    }

    if not CRYPTO_AVAILABLE:
        return result

    if "certificate" not in session.columns:
        return result

    for value in session["certificate"]:

        value = clean(value)

        if not value:
            continue

        # Remove separators that TShark can introduce.
        value = value.replace(":", "")
        value = value.replace(" ", "")
        value = value.replace(",", "")

        try:

            der = bytes.fromhex(value)

            cert = x509.load_der_x509_certificate(
                der,
                default_backend()
            )

            # Use capture time if possible.
            if "time" in session.columns:

                timestamps = []

                for t in session["time"]:

                    try:
                        timestamps.append(float(t))
                    except:
                        pass

                if timestamps:

                    check_time = datetime.fromtimestamp(
                        timestamps[0],
                        timezone.utc
                    )
                else:
                    check_time = datetime.now(timezone.utc)

            else:
                check_time = datetime.now(timezone.utc)

            not_after = (
                cert.not_valid_after_utc
                if hasattr(cert, "not_valid_after_utc")
                else cert.not_valid_after
            )

            not_before = (
                cert.not_valid_before_utc
                if hasattr(cert, "not_valid_before_utc")
                else cert.not_valid_before
            )

            result["cert_expired"] = int(
                check_time > not_after
            )

            result["cert_not_yet_valid"] = int(
                check_time < not_before
            )

            result["self_signed"] = int(
                cert.issuer == cert.subject
            )

            public_key = cert.public_key()

            key_name = type(public_key).__name__

            if "RSA" in key_name:

                result["cert_key_algorithm"] = "RSA"
                result["cert_key_size"] = public_key.key_size

            elif "EllipticCurve" in key_name:

                result["cert_key_algorithm"] = "ECDSA"
                result["cert_key_size"] = public_key.key_size

            else:

                result["cert_key_algorithm"] = key_name

            result["cert_signature_algorithm"] = (
                cert.signature_algorithm_oid._name
            )

            # Hostname matching is only checked if SNI is available.
            if "sni" in session.columns:

                sni = first_value(session["sni"])

                if sni:

                    names = []

                    try:

                        san = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )

                        names = san.value.get_values_for_type(
                            x509.DNSName
                        )

                    except Exception:
                        pass

                    hostname_ok = False

                    for name in names:

                        if name.lower() == sni.lower():
                            hostname_ok = True
                            break

                        if name.startswith("*."):

                            suffix = name[1:].lower()

                            if sni.lower().endswith(suffix):
                                hostname_ok = True
                                break

                    result["hostname_match"] = int(hostname_ok)

            return result

        except Exception:
            continue

    return result


# ============================================================
# TRAFFIC FEATURES
# ============================================================

def traffic_features(session):

    packet_count = len(session)

    bytes_sent = 0
    bytes_received = 0

    # Determine client direction using the first SYN when possible.
    client_ip = None

    if "src" in session.columns:

        for _, row in session.iterrows():

            src = clean(row.get("src"))

            # First sender is normally the client.
            if src:
                client_ip = src
                break

    for _, row in session.iterrows():

        try:
            length = int(float(row.get("tcp_len", 0)))
        except:
            length = 0

        src = clean(row.get("src"))

        if client_ip and src == client_ip:
            bytes_sent += length
        else:
            bytes_received += length

    retransmissions = 0

    if "retrans" in session.columns:

        for value in session["retrans"]:

            if clean(value):
                retransmissions += 1

    times = []

    if "time" in session.columns:

        for value in session["time"]:

            try:
                times.append(float(value))
            except:
                pass

    if times:

        session_start = min(times)
        session_end = max(times)

    else:

        session_start = None
        session_end = None

    handshake_duration = None

    if "tls_type" in session.columns and times:

        tls_times = []

        for i, value in enumerate(session["tls_type"]):

            if clean(value):

                if i < len(times):
                    tls_times.append(times[i])

        if len(tls_times) >= 2:

            handshake_duration = round(
                max(tls_times) - min(tls_times),
                4
            )

        elif len(tls_times) == 1:

            handshake_duration = 0.0

    return {
        "packet_count": packet_count,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "retransmission_count": retransmissions,
        "tls_handshake_duration": handshake_duration,
        "session_start": session_start,
        "session_end": session_end
    }


# ============================================================
# BUILD SESSION
# ============================================================

def build_session(session, session_id):

    protocol = detect_protocol(session)

    encryption_mode, starttls_offered, starttls_success = (
        detect_encryption(
            session,
            protocol
        )
    )

    tls_version = get_tls_version(session)

    cipher = get_cipher(session)

    key_exchange = get_key_exchange(
        session,
        tls_version,
        cipher
    )

    forward_secrecy = get_forward_secrecy(
        key_exchange,
        tls_version
    )

    certificate = parse_certificate(session)

    traffic = traffic_features(session)

    return {

        "session_id": session_id,

        "protocol": protocol,

        "encryption_mode": encryption_mode,

        "starttls_offered": starttls_offered,

        "starttls_success": starttls_success,

        "tls_version": tls_version,

        "cipher_suite": cipher,

        "key_exchange": key_exchange,

        "forward_secrecy": forward_secrecy,

        "cert_expired": certificate["cert_expired"],

        "cert_not_yet_valid": certificate["cert_not_yet_valid"],

        "cert_key_algorithm": certificate["cert_key_algorithm"],

        "cert_key_size": certificate["cert_key_size"],

        "cert_signature_algorithm": certificate[
            "cert_signature_algorithm"
        ],

        "self_signed": certificate["self_signed"],

        "hostname_match": certificate["hostname_match"],

        "packet_count": traffic["packet_count"],

        "bytes_sent": traffic["bytes_sent"],

        "bytes_received": traffic["bytes_received"],

        "retransmission_count": traffic[
            "retransmission_count"
        ],

        "tls_handshake_duration": traffic[
            "tls_handshake_duration"
        ],

        "session_start": traffic["session_start"],

        "session_end": traffic["session_end"]
    }


# ============================================================
# MAIN EXTRACTION
# ============================================================

def extract_features(pcap_path):

    df = read_pcap(pcap_path)

    if df.empty:
        return []

    if "stream" not in df.columns:
        raise RuntimeError(
            "tcp.stream is not available in this TShark installation."
        )

    # Convert stream IDs.
    df["stream"] = df["stream"].astype(str)

    sessions = []

    stream_ids = [
        x for x in df["stream"].unique()
        if clean(x)
    ]

    for stream_id in stream_ids:

        session = df[
            df["stream"] == stream_id
        ].copy()

        protocol = detect_protocol(session)

        # Only keep email sessions.
        if protocol not in ["SMTP", "IMAP", "POP3"]:
            continue

        # Keep streams with actual email dissector evidence, raw
        # application evidence, or TLS on a known mail port.
        has_email_text = False

        for column in ["smtp", "imap", "pop"]:

            if column in session.columns:

                if any(clean(x) for x in session[column]):
                    has_email_text = True
                    break

        has_raw_payload = False

        if "payload" in session.columns:

            has_raw_payload = any(
                clean(x)
                for x in session["payload"]
            )

        known_mail_port = False

        for column in ["srcport", "dstport"]:

            if column in session.columns:

                for value in session[column]:

                    try:
                        if int(float(value)) in PORT_PROTOCOL:
                            known_mail_port = True
                            break
                    except Exception:
                        pass

        if (
            protocol == "UNKNOWN"
            and not has_email_text
            and not has_raw_payload
            and not (known_mail_port and has_tls(session))
        ):
            continue

        sessions.append(
            build_session(
                session,
                f"PCAP-{len(sessions) + 1:06d}"
            )
        )

    return sessions


# ============================================================
# PROGRAM
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) < 2:

        print(
            "Usage: python pcap_extractor.py <pcap_file>"
        )

        sys.exit(1)

    pcap_path = sys.argv[1]

    sessions = extract_features(pcap_path)

    print(
        f"\nExtracted {len(sessions)} session(s) "
        f"from {pcap_path}\n"
    )

    for session in sessions:

        print(
            json.dumps(
                session,
                indent=2,
                default=str
            )
        )