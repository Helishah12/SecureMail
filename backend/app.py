from fastapi import FastAPI, UploadFile, File, HTTPException
from tempfile import NamedTemporaryFile
import os
import pandas as pd

from backend.analysis.feature_extractor import extract_features
from backend.analysis.analyzer import analyze_sessions
from backend.explainer.rule_explainer import explain_findings
from backend.explainer.anomaly_explainer import build_explanation


app = FastAPI(title="SecureMailScope")


@app.get("/")
def root():
    return {
        "message": "SecureMailScope API is running"
    }


@app.post("/analyze")
async def analyze_pcap(file: UploadFile = File(...)):


    if not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported"
        )

    suffix = os.path.splitext(file.filename)[1]

    with NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(await file.read())
        temp_path = temp.name

    try:


        sessions = extract_features(temp_path)

        if not sessions:
            return {
                "filename": file.filename,
                "session_count": 0,
                "sessions": [],
                "message": (
                    "No SMTP, IMAP, or POP3 sessions detected"
                )
            }

        df = pd.DataFrame(sessions)

        df["session_duration_seconds"] = (
            df["session_end"] - df["session_start"]
        )

        df["bytes_total"] = (
            df["bytes_sent"] + df["bytes_received"]
        )

        df["avg_packet_size"] = (
            df["bytes_total"] / df["packet_count"]
        )


        result = analyze_sessions(df)


        output = []

        for _, row in result.iterrows():


            rule_explanations = explain_findings(
                row["security_findings"]
            )


            if row["anomaly"] == -1:
                behavioral_explanations = build_explanation(
                    df,
                    row
                )
            else:
                behavioral_explanations = []


            item = {
                "session_id": row["session_id"],
                "protocol": row["protocol"],

                "security_risk_score": row[
                    "security_risk_score"
                ],

                "security_risk_level": row[
                    "security_risk_level"
                ],

                "anomaly": int(row["anomaly"]),

                "anomaly_score": float(
                    row["anomaly_score"]
                ),

                "assessment": row["assessment"],

                # Original rule-engine findings
                "security_findings": row[
                    "security_findings"
                ],

                # Human-readable rule explanations
                "rule_explanations": rule_explanations,

                # Behavioral anomaly explanations
                "behavioral_explanations": (
                    behavioral_explanations
                )
            }

            output.append(item)

        return {
            "filename": file.filename,
            "session_count": len(output),
            "sessions": output
        }

    finally:

        if os.path.exists(temp_path):
            os.remove(temp_path)