
import json
from datetime import timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="SOC Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SOC Threat Detection Dashboard")
st.caption("Security Monitoring | Threat Detection | MITRE ATT&CK")

# Load alerts
alerts_path = Path(__file__).parent / "reports" / "alerts.json"

if not alerts_path.exists():
    st.error("Run detector.py first.")
    st.stop()

with alerts_path.open("r", encoding="utf-8") as file:
    alerts = json.load(file)

df = pd.DataFrame(alerts)

if df.empty:
    st.success("No security alerts detected.")
    st.stop()

df["timestamp"] = pd.to_datetime(
    df["timestamp"], utc=True
)

# Initialize filter reset state
if "filter_version" not in st.session_state:
    st.session_state.filter_version = 0

v = st.session_state.filter_version

# Sidebar filters
st.sidebar.header("🔎 Security Filters")

severity = st.sidebar.multiselect(
    "Severity",
    sorted(df["severity"].dropna().unique()),
    key=f"severity_{v}"
)

attack_type = st.sidebar.multiselect(
    "Attack Type",
    sorted(df["rule"].dropna().unique()),
    key=f"attack_{v}"
)

source_ip = st.sidebar.multiselect(
    "Source IP",
    sorted(df["src_ip"].dropna().unique()),
    key=f"ip_{v}"
)

username = st.sidebar.multiselect(
    "Username",
    sorted(df["username"].dropna().unique()),
    key=f"user_{v}"
)

min_date = df["timestamp"].min().date()
max_date = df["timestamp"].max().date()

date_range = st.sidebar.date_input(
    "Date Range (UTC)",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date,
    key=f"date_{v}"
)

if st.sidebar.button("Reset Filters"):
    st.session_state.filter_version += 1
    st.rerun()

# Apply filters
filtered_df = df.copy()

if severity:
    filtered_df = filtered_df[
        filtered_df["severity"].isin(severity)
    ]

if attack_type:
    filtered_df = filtered_df[
        filtered_df["rule"].isin(attack_type)
    ]

if source_ip:
    filtered_df = filtered_df[
        filtered_df["src_ip"].isin(source_ip)
    ]

if username:
    filtered_df = filtered_df[
        filtered_df["username"].isin(username)
    ]

# Inclusive date range
if len(date_range) == 2:
    start_date, end_date = date_range
    start = pd.Timestamp(start_date, tz="UTC")
    end = pd.Timestamp(
        end_date + timedelta(days=1), tz="UTC"
    )

    filtered_df = filtered_df[
        (filtered_df["timestamp"] >= start) &
        (filtered_df["timestamp"] < end)
    ]
else:
    st.info("Select both start and end dates.")

# Metrics
st.subheader("Security Overview")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", len(df))
col2.metric("Filtered Alerts", len(filtered_df))
col3.metric(
    "Critical",
    (filtered_df["severity"] == "critical").sum()
)
col4.metric(
    "High",
    (filtered_df["severity"] == "high").sum()
)

st.divider()

# Alert table
st.subheader("Detected Security Events")

if filtered_df.empty:
    st.warning("No alerts match the selected filters.")
else:
    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Alerts by Severity")
        st.bar_chart(
            filtered_df["severity"].value_counts()
        )

    with col2:
        st.subheader("Attack Types")
        st.bar_chart(
            filtered_df["rule"].value_counts()
        )

    # Investigation
    st.subheader("Incident Investigation")

    selected_ip = st.selectbox(
        "Investigate Source IP",
        sorted(filtered_df["src_ip"].unique())
    )

    investigation = filtered_df[
        filtered_df["src_ip"] == selected_ip
    ]

    st.dataframe(
        investigation,
        use_container_width=True,
        hide_index=True
    )

    # MITRE Mapping
    st.subheader("MITRE ATT&CK Mapping")

    st.dataframe(
        filtered_df[
            ["rule", "mitre_attack", "severity"]
        ].drop_duplicates(),
        use_container_width=True,
        hide_index=True
    )

    # Export
    export_df = filtered_df.copy()
    export_df["timestamp"] = export_df[
        "timestamp"
    ].dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    st.download_button(
        "Download Filtered Alerts (JSON)",
        data=export_df.to_json(
            orient="records", indent=2
        ),
        file_name="filtered_security_alerts.json",
        mime="application/json"
    )
