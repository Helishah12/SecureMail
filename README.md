# SecureMailScope

AI-Assisted Cryptographic Security Posture Assessment for SMTP, IMAP, and POP3

SecureMailScope analyzes email network traffic from PCAP/PCAPNG files to identify cryptographic security weaknesses and unusual session behavior.

## Architecture

PCAP / PCAPNG
      ↓
TShark Feature Extraction
      ↓
Session Features
      ↓
 ┌───────────────┬──────────────────┐
 │ Rule Engine   │ Isolation Forest │
 │ Security Risk │ Behavioral       │
 └───────┬───────┴────────┬─────────┘
         └───────┬─────────┘
                 ↓
          Combined Analysis
                 ↓
            Explainability
                 ↓
              FastAPI

## Features

- SMTP, IMAP and POP3 session detection
- TLS and STARTTLS analysis
- Certificate and cryptographic key analysis
- Deterministic security risk scoring
- Isolation Forest-based behavioral anomaly detection
- Feature-level anomaly explanations
- REST API for PCAP analysis

## Security Analysis

The rule engine evaluates:

- TLS version
- STARTTLS failures
- Certificate validity
- Self-signed certificates
- Hostname mismatches
- Weak RSA keys
- Weak signature algorithms
- Forward secrecy

Risk levels:

Score    Risk
0–19     LOW
20–39    MEDIUM
40–69    HIGH
70+      CRITICAL

## Behavioral Analysis

Isolation Forest analyzes network-level features including:

- Packet count
- Bytes transferred
- Retransmissions
- TLS handshake duration
- Session duration
- Average packet size

Security risk and behavioral anomalies are treated as separate signals.
An anomaly does not inherently indicate malicious activity.

## Project Structure

mailscope/
├── backend/
│   ├── analysis/
│   ├── models/
│   └── app.py
├── data/
├── overview.py
├── test_ov.py
├── requirements.txt
├── README.md
└── .gitignore

## Setup

Install dependencies:

pip install -r requirements.txt

Install TShark and verify:

tshark --version

Run the API:

uvicorn backend.app:app --reload

API documentation:

http://127.0.0.1:8000/docs

## Testing

Run the integration test:

python overview.py
python test_ov.py

## Current Status

- [x] PCAP feature extraction
- [x] SMTP / IMAP / POP3 analysis
- [x] Security rule engine
- [x] Isolation Forest anomaly detection
- [x] Behavioral explainability
- [x] FastAPI integration
- [ ] Rule-engine explainability
- [ ] Persistent behavioral baseline
- [ ] Frontend dashboard