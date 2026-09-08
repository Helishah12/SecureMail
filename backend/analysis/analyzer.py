from backend.analysis.rule_engine import evaluate_session
from backend.models.isolation_forest import predict_anomalies

def analyze_sessions(df):
    security_results = []

    for _, row in df.iterrows():
        result = evaluate_session(row.to_dict())

        security_results.append(result)

    result_df = df.copy()

    result_df["security_risk_score"] = [
        r["risk_score"] for r in security_results
    ]

    result_df["security_risk_level"] = [
        r["risk_level"] for r in security_results
    ]

    result_df["security_findings"] = [
        r["findings"] for r in security_results
    ]

    behavioral_df = predict_anomalies(df)

    result_df["anomaly"] = behavioral_df["anomaly"]
    result_df["anomaly_score"] = behavioral_df["anomaly_score"]

    def get_assessment(row):
        high_security = row["security_risk_level"] in {"HIGH", "CRITICAL"}
        anomalous = row["anomaly"] == -1

        if high_security and anomalous:
            return "SECURITY_RISK_AND_BEHAVIORAL_ANOMALY"
        if high_security:
            return "SECURITY_RISK"
        if anomalous:
            return "BEHAVIORAL_ANOMALY"
        return "NO_NOTABLE_ISSUES"

    result_df["assessment"] = result_df.apply(get_assessment, axis=1)

    return result_df