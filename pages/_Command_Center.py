
import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

from src.scan_history import initialize_database, get_scan_history

st.set_page_config(
    page_title="Command Center | PhishShield X",
    page_icon="🛡️",
    layout="wide"
)

# -------------------- THEME --------------------

st.markdown("""
<style>
.stApp {
    background: #080d18;
    color: #e8eefc;
}
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
h1, h2, h3 {
    color: #eaf2ff !important;
}
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #111c30, #0c1424);
    border: 1px solid #263b59;
    padding: 18px;
    border-radius: 13px;
}
[data-testid="stMetricLabel"] {
    color: #9aacc7 !important;
}
[data-testid="stMetricValue"] {
    color: #42e8d5 !important;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #263b59;
    border-radius: 10px;
}
.section {
    background: #101a2b;
    border: 1px solid #243750;
    border-radius: 13px;
    padding: 17px;
    margin-bottom: 12px;
}
.small-muted {
    color: #8da2bf;
    font-size: 13px;
}
</style>
""", unsafe_allow_html=True)

# -------------------- HEADER --------------------

st.markdown("""
<div style="display:flex; justify-content:space-between; align-items:center;">
    <div>
        <div style="color:#42e8d5; letter-spacing:3px; font-size:12px;">
            PHISHSHIELD X / SECURITY OPERATIONS
        </div>
        <h1 style="margin:5px 0 0 0;">COMMAND CENTER</h1>
        <p style="color:#91a5c2; margin-top:5px;">
            Centralized email threat monitoring and investigation overview
        </p>
    </div>
    <div style="text-align:right; color:#42e8d5;">
        <div style="font-size:12px;">SYSTEM STATUS</div>
        <div style="font-size:20px; font-weight:bold;">● MONITORING</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()

# -------------------- LOAD DATABASE --------------------

try:
    initialize_database()
    history = get_scan_history()

    if isinstance(history, pd.DataFrame):
        df = history.copy()
    else:
        df = pd.DataFrame(history)

except Exception as e:
    st.error(f"Unable to load scan history: {e}")
    st.stop()

required_columns = [
    "scan_time", "sender", "subject", "risk_level",
    "risk_score", "urls_found", "attachments_found",
    "spoofing_detected"
]

for col in required_columns:
    if col not in df.columns:
        df[col] = None

if df.empty:
    st.info("No scan records found. Upload and scan an email from Email Forensics to populate the Command Center.")
    st.markdown("### Quick Access")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Open Email Forensics", use_container_width=True):
            st.switch_page("pages/2_Email_Forensics.py")
    with c2:
        if st.button("Open URL Intelligence", use_container_width=True):
            st.switch_page("pages/3_URL_Intelligence.py")
    with c3:
        if st.button("Open Scan History", use_container_width=True):
            st.switch_page("pages/6_Scan_History.py")
    st.stop()

# -------------------- DATA CLEANING --------------------

df["risk_level"] = df["risk_level"].fillna("LOW").astype(str).str.upper()
df["sender"] = df["sender"].fillna("Unknown").astype(str)
df["subject"] = df["subject"].fillna("No Subject").astype(str)

for col in ["risk_score", "urls_found", "attachments_found"]:
    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

df["spoofing_detected"] = (
    df["spoofing_detected"]
    .astype(str)
    .str.lower()
    .isin(["true", "1", "yes"])
)

df["scan_time"] = pd.to_datetime(df["scan_time"], errors="coerce")

total_scans = len(df)
high = int((df["risk_level"] == "HIGH").sum())
medium = int((df["risk_level"] == "MEDIUM").sum())
low = int((df["risk_level"] == "LOW").sum())
threats = high + medium
safe_rate = (low / total_scans * 100) if total_scans else 0
avg_score = df["risk_score"].mean()
spoofing_count = int(df["spoofing_detected"].sum())
total_urls = int(df["urls_found"].sum())
total_attachments = int(df["attachments_found"].sum())

# -------------------- KPI CARDS --------------------

st.markdown("## Security Overview")

k1, k2, k3, k4, k5 = st.columns(5)

k1.metric("TOTAL SCANS", f"{total_scans:,}")
k2.metric("HIGH RISK", f"{high:,}")
k3.metric("MEDIUM RISK", f"{medium:,}")
k4.metric("LOW RISK", f"{low:,}")
k5.metric("AVG RISK SCORE", f"{avg_score:.1f}/100")

st.write("")

k6, k7, k8, k9 = st.columns(4)
k6.metric("THREATS DETECTED", f"{threats:,}")
k7.metric("SPOOFING ALERTS", f"{spoofing_count:,}")
k8.metric("URLS ANALYSED", f"{total_urls:,}")
k9.metric("ATTACHMENTS FOUND", f"{total_attachments:,}")

st.divider()

# -------------------- FILTERS --------------------

st.markdown("## Investigation Filters")

f1, f2 = st.columns(2)

with f1:
    selected_risk = st.multiselect(
        "Filter by risk level",
        ["HIGH", "MEDIUM", "LOW"],
        default=["HIGH", "MEDIUM", "LOW"]
    )

with f2:
    search_sender = st.text_input("Search sender")

filtered = df[df["risk_level"].isin(selected_risk)].copy()

if search_sender.strip():
    filtered = filtered[
        filtered["sender"].str.contains(search_sender, case=False, na=False)
    ]

# -------------------- CHARTS --------------------

st.divider()
st.markdown("## Threat Intelligence Analytics")

left, right = st.columns(2)

with left:
    st.markdown("### Risk Distribution")

    risk_counts = df["risk_level"].value_counts()
    labels = ["HIGH", "MEDIUM", "LOW"]
    values = [int(risk_counts.get(x, 0)) for x in labels]

    fig, ax = plt.subplots(figsize=(6, 4), facecolor="#101a2b")
    ax.set_facecolor("#101a2b")

    if sum(values) > 0:
        ax.pie(
            values,
            labels=labels,
            autopct="%1.1f%%",
            startangle=90,
            wedgeprops={"width": 0.38, "edgecolor": "#101a2b"},
            textprops={"color": "white"}
        )
        ax.text(
            0, 0, f"{total_scans}\nSCANS",
            ha="center", va="center",
            color="white", fontsize=15, fontweight="bold"
        )

    st.pyplot(fig)
    plt.close(fig)

with right:
    st.markdown("### Risk Score Distribution")

    fig, ax = plt.subplots(figsize=(6, 4), facecolor="#101a2b")
    ax.set_facecolor("#101a2b")

    ax.hist(
        df["risk_score"],
        bins=10,
        edgecolor="white",
        alpha=0.85
    )
    ax.set_xlabel("Risk Score", color="white")
    ax.set_ylabel("Number of Scans", color="white")
    ax.tick_params(colors="white")
    ax.grid(alpha=0.15)

    st.pyplot(fig)
    plt.close(fig)

# -------------------- SECOND CHART ROW --------------------

left, right = st.columns(2)

with left:
    st.markdown("### Risk Level Comparison")

    fig, ax = plt.subplots(figsize=(6, 4), facecolor="#101a2b")
    ax.set_facecolor("#101a2b")

    ax.bar(
        labels,
        values,
        edgecolor="white",
        alpha=0.85
    )
    ax.set_ylabel("Number of Emails", color="white")
    ax.tick_params(colors="white")
    ax.grid(axis="y", alpha=0.15)

    st.pyplot(fig)
    plt.close(fig)

with right:
    st.markdown("### Threat Indicators")

    indicator_names = [
        "Suspicious URLs",
        "Attachments",
        "Spoofing Alerts"
    ]
    indicator_values = [
        total_urls,
        total_attachments,
        spoofing_count
    ]

    fig, ax = plt.subplots(figsize=(6, 4), facecolor="#101a2b")
    ax.set_facecolor("#101a2b")

    ax.barh(
        indicator_names,
        indicator_values,
        edgecolor="white",
        alpha=0.85
    )
    ax.set_xlabel("Count", color="white")
    ax.tick_params(colors="white")
    ax.grid(axis="x", alpha=0.15)

    st.pyplot(fig)
    plt.close(fig)

# -------------------- SCAN TIMELINE --------------------

st.divider()
st.markdown("## Scan Activity Timeline")

timeline = df.dropna(subset=["scan_time"]).copy()

if not timeline.empty:
    daily = (
        timeline.set_index("scan_time")
        .resample("D")
        .size()
        .reset_index(name="scans")
    )

    st.line_chart(
        daily.set_index("scan_time")["scans"],
        use_container_width=True
    )
else:
    st.caption("Date-wise activity is unavailable because scan timestamps could not be read.")

# -------------------- RECENT INVESTIGATIONS --------------------

st.divider()
st.markdown("## Recent Investigations")

recent = filtered.sort_values(
    "scan_time", ascending=False, na_position="last"
).head(15)

display_columns = [
    "scan_time", "sender", "subject", "risk_level",
    "risk_score", "urls_found", "attachments_found",
    "spoofing_detected"
]

recent_display = recent[display_columns].copy()
recent_display["scan_time"] = recent_display["scan_time"].astype(str)

st.dataframe(
    recent_display,
    use_container_width=True,
    hide_index=True
)

st.download_button(
    "Download Investigation Records (CSV)",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="phishshield_investigation_records.csv",
    mime="text/csv"
)

# -------------------- SECURITY INSIGHTS --------------------

st.divider()
st.markdown("## Security Insights")

i1, i2, i3 = st.columns(3)

with i1:
    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.markdown("### Threat Rate")
    st.metric("High + Medium Risk", f"{threats}")
    st.caption("Scans classified as HIGH or MEDIUM risk.")
    st.markdown("</div>", unsafe_allow_html=True)

with i2:
    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.markdown("### Safe Email Rate")
    st.metric("Low Risk Share", f"{safe_rate:.1f}%")
    st.caption("Share of scans classified as LOW risk.")
    st.markdown("</div>", unsafe_allow_html=True)

with i3:
    st.markdown('<div class="section">', unsafe_allow_html=True)
    st.markdown("### Spoofing Monitoring")
    st.metric("Spoofing Indicators", spoofing_count)
    st.caption("Records marked with a spoofing indicator.")
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------- QUICK ACTIONS --------------------

st.divider()
st.markdown("## Quick Actions")

a1, a2, a3, a4 = st.columns(4)

with a1:
    if st.button("Email Forensics", use_container_width=True):
        st.switch_page("pages/2_Email_Forensics.py")

with a2:
    if st.button("URL Intelligence", use_container_width=True):
        st.switch_page("pages/3_URL_Intelligence.py")

with a3:
    if st.button("Explainable AI", use_container_width=True):
        st.switch_page("pages/4_Explainable_AI.py")

with a4:
    if st.button("Scan History", use_container_width=True):
        st.switch_page("pages/6_Scan_History.py")

st.markdown("""
<div style="text-align:center; color:#647994; padding:25px 0 5px 0;">
    PHISHSHIELD X · INTELLIGENT EMAIL THREAT INVESTIGATION PLATFORM
</div>
""", unsafe_allow_html=True)

