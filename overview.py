# inspect_dataset.py

import pandas as pd

FILE = "data/dataset.csv"

df = pd.read_csv(FILE)

print("=" * 70)
print("DATASET OVERVIEW")
print("=" * 70)

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")

print("\nColumns:")
for i, col in enumerate(df.columns, 1):
    print(f"{i:2}. {col} ({df[col].dtype})")


# ------------------------------------------------------------
# Missing values
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("MISSING VALUES")
print("=" * 70)

missing = df.isna().sum()
missing_pct = (missing / len(df) * 100).round(2)

missing_table = pd.DataFrame({
    "missing": missing,
    "percentage": missing_pct
})

print(missing_table[missing_table["missing"] > 0])


# ------------------------------------------------------------
# Categorical / boolean-like columns
# ------------------------------------------------------------

categorical = [
    "protocol",
    "encryption_mode",
    "tls_version",
    "cipher_suite",
    "key_exchange",
    "cert_key_algorithm",
    "cert_signature_algorithm",
    "rule_risk_label"
]

print("\n" + "=" * 70)
print("CATEGORICAL DISTRIBUTIONS")
print("=" * 70)

for col in categorical:
    if col in df.columns:
        print(f"\n--- {col} ---")
        print(df[col].value_counts(dropna=False).to_string())


# ------------------------------------------------------------
# Behavioral features
# ------------------------------------------------------------

behavioral = [
    "packet_count",
    "bytes_sent",
    "bytes_received",
    "retransmission_count",
    "tls_handshake_duration",
    "session_duration_seconds",
    "bytes_total",
    "avg_packet_size"
]

print("\n" + "=" * 70)
print("BEHAVIORAL FEATURES")
print("=" * 70)

existing = [c for c in behavioral if c in df.columns]

print(
    df[existing]
    .describe()
    .T
    .round(3)
    .to_string()
)


# ------------------------------------------------------------
# Percentiles — especially useful for anomalies
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("BEHAVIORAL PERCENTILES")
print("=" * 70)

percentiles = [0, 0.01, 0.05, 0.25, 0.50, 0.75, 0.95, 0.99, 1.00]

print(
    df[existing]
    .quantile(percentiles)
    .round(3)
    .to_string()
)


# ------------------------------------------------------------
# Number of unique values
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("UNIQUE VALUES")
print("=" * 70)

for col in df.columns:
    print(f"{col:30} {df[col].nunique(dropna=False):>8}")


# ------------------------------------------------------------
# Correlation between behavioral features
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("BEHAVIORAL CORRELATION")
print("=" * 70)

print(
    df[existing]
    .corr()
    .round(2)
    .to_string()
)


# ------------------------------------------------------------
# Existing extreme values
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("TOP 10 EXTREME VALUES")
print("=" * 70)

for col in existing:
    print(f"\n--- {col} ---")
    print(df.nlargest(10, col)[[col]].to_string(index=False))


# ------------------------------------------------------------
# Rule score distribution (ONLY for understanding dataset)
# ------------------------------------------------------------

if "rule_risk_score" in df.columns:
    print("\n" + "=" * 70)
    print("RULE RISK SCORE DISTRIBUTION")
    print("=" * 70)

    print(df["rule_risk_score"].describe().round(2))

    if "rule_risk_label" in df.columns:
        print("\nRisk labels:")
        print(df["rule_risk_label"].value_counts().to_string())


print("\n" + "=" * 70)
print("DONE")
print("=" * 70)