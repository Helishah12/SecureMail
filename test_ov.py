import pandas as pd

from backend.analysis.analyzer import analyze_sessions
from backend.analysis.explainer import build_explanation


df = pd.read_csv("data/dataset.csv")
result = analyze_sessions(df)

print(f"Total sessions: {len(result)}")

print("\nAssessment counts:")
print(result["assessment"].value_counts())

print("\nSample results:")
print(
    result[
        [
            "session_id",
            "protocol",
            "security_risk_score",
            "security_risk_level",
            "anomaly",
            "anomaly_score",
            "assessment",
        ]
    ]
    .head(20)
    .to_string(index=False)
)

print("\nAnomaly explanations:")

anomalies = result[result["anomaly"] == -1]

for _, row in anomalies.head(10).iterrows():
    explanations = build_explanation(df, row)

    print(f"\n{row['session_id']}")

    for explanation in explanations:
        print(f"- {explanation['description']}")