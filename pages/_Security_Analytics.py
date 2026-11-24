

import streamlit as st
import pandas as pd
from src.scan_history import get_scan_history

st.set_page_config(
    page_title="Security Analytics | PhishShield X",
    page_icon="📊",
    layout="wide"
)

st.title("📊 Security Analytics")
st.caption("Monitor phishing investigation activity and threat patterns.")

try:
    history = get_scan_history()

    if history is None or len(history) == 0:
        st.info("No investigation data available yet. Scan emails to generate analytics.")
        st.stop()

    df = pd.DataFrame(history)

    st.subheader("Security Overview")

    total_scans = len(df)

    high_risk = (
        int((df["risk_level"] == "HIGH").sum())
        if "risk_level" in df.columns else 0
    )

    medium_risk = (
        int((df["risk_level"] == "MEDIUM").sum())
        if "risk_level" in df.columns else 0
    )

    low_risk = (
        int((df["risk_level"] == "LOW").sum())
        if "risk_level" in df.columns else 0
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Scans", total_scans)
    col2.metric("High Risk", high_risk)
    col3.metric("Medium Risk", medium_risk)
    col4.metric("Low Risk", low_risk)

    st.divider()

    st.subheader("Threat Level Distribution")

    if "risk_level" in df.columns:
        risk_distribution = df["risk_level"].value_counts()
        st.bar_chart(risk_distribution)

    st.divider()

    st.subheader("Average Risk Score")

    if "risk_score" in df.columns:

        average_risk = pd.to_numeric(
            df["risk_score"],
            errors="coerce"
        ).mean()

        if pd.notna(average_risk):
            st.metric("Average Risk Score", f"{average_risk:.2f}/100")

            st.progress(
                min(max(float(average_risk) / 100, 0.0), 1.0)
            )

    st.divider()

    st.subheader("Daily Investigation Trend")

    if "scan_time" in df.columns:

        df["scan_time"] = pd.to_datetime(
            df["scan_time"],
            errors="coerce"
        )

        daily_scans = (
            df.dropna(subset=["scan_time"])
            .assign(Date=lambda x: x["scan_time"].dt.date)
            .groupby("Date")
            .size()
        )

        if not daily_scans.empty:
            st.line_chart(daily_scans)
        else:
            st.info("No valid scan timestamps found.")

    st.divider()

    st.subheader("Header Spoofing Indicators")

    if "spoofing_detected" in df.columns:

        spoofing_count = df["spoofing_detected"].astype(str).str.lower().isin(
            ["true", "1", "yes"]
        ).sum()

        col1, col2 = st.columns(2)

        col1.metric("Possible Spoofing Indicators", int(spoofing_count))
        col2.metric(
            "Other Scans",
            int(total_scans - spoofing_count)
        )

    st.divider()

    st.subheader("Recent Investigations")

    st.dataframe(
        df.head(10),
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "Download Security Analytics CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="phishshield_security_analytics.csv",
        mime="text/csv"
    )

except Exception as error:
    st.error(f"Unable to generate security analytics: {error}")
    st.info("Check the database schema and scan history module.")

st.caption(
    "Analytics are based on locally stored investigation records. "
    "They represent detected indicators, not confirmed cyberattacks."
)
