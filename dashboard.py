
import streamlit as st
import pandas as pd
import sys
import os
import random
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from src.scan_history import get_scan_history

st.set_page_config(
    page_title="PHISHSHIELD X | SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;800&family=Inter:wght@400;500;600;700&display=swap');

.stApp {
    background: radial-gradient(ellipse at top right,#132b40 0%,#080f1c 48%,#060a12 100%);
    color:#e8f2ff;
    font-family:Inter,sans-serif;
}
[data-testid="stSidebar"] {
    background:#0b1524;
    border-right:1px solid #1c354c;
}
.block-container {padding-top:2rem; max-width:1500px;}
h1,h2,h3 {color:#e8f2ff !important;}
.hero {
    background:linear-gradient(110deg,#102c3b,#102039 60%,#17213c);
    border:1px solid #24546a;
    border-radius:20px;
    padding:30px;
    box-shadow:0 0 35px #00e5ff12;
    margin-bottom:25px;
}
.hero-title {
    font-family:Orbitron,sans-serif;
    font-size:32px;
    font-weight:800;
    color:#eaffff;
    letter-spacing:2px;
}
.hero-sub {color:#91b5c8;font-size:13px;letter-spacing:2px;}
.live {
    display:inline-block;
    background:#103d32;
    color:#4dffb0;
    padding:7px 13px;
    border-radius:20px;
    font-size:12px;
    border:1px solid #1a805e;
}
.kpi {
    background:linear-gradient(145deg,#13263b,#0c1829);
    border:1px solid #25445c;
    border-radius:15px;
    padding:20px;
    min-height:125px;
}
.kpi-label {font-size:11px;color:#88a7bc;letter-spacing:1.5px;}
.kpi-value {font-family:Orbitron,sans-serif;font-size:30px;font-weight:700;margin-top:12px;color:#f3faff;}
.kpi-note {font-size:11px;color:#46e5b0;margin-top:5px;}
.panel {
    background:#101d2d;
    border:1px solid #223d55;
    border-radius:16px;
    padding:20px;
    min-height:170px;
}
.panel-title {font-size:13px;letter-spacing:1.5px;color:#9ab7ca;font-weight:700;}
.threat-number {
    font-family:Orbitron,sans-serif;
    font-size:42px;
    color:#4dffb0;
    margin:15px 0;
}
.module {
    background:linear-gradient(145deg,#15283d,#0d192a);
    border:1px solid #28445b;
    border-radius:14px;
    padding:18px;
    min-height:125px;
}
.module-icon {font-size:27px;}
.module-name {font-weight:700;color:#e5f5ff;margin-top:10px;}
.module-desc {font-size:11px;color:#8ca9bd;margin-top:5px;}
hr {border-color:#20374b;}
.stButton>button {
    background:#102f3c;
    border:1px solid #267b80;
    color:#dffeff;
    border-radius:10px;
    font-weight:600;
    min-height:42px;
}
.stButton>button:hover {
    background:#15505a;
    border-color:#4dffb0;
    color:white;
}
</style>
""", unsafe_allow_html=True)

try:
    history = get_scan_history()
    df = pd.DataFrame(history) if history else pd.DataFrame()
except Exception as e:
    df = pd.DataFrame()
    st.error(f"Could not load scan history: {e}")

total = len(df)
high = int((df["risk_level"] == "HIGH").sum()) if total else 0
medium = int((df["risk_level"] == "MEDIUM").sum()) if total else 0
low = int((df["risk_level"] == "LOW").sum()) if total else 0
avg_score = round(df["risk_score"].mean(),1) if total else 0
threat_rate = round(high / total * 100,1) if total else 0

# HERO
st.markdown("""
<div class="hero">
 <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:20px">
  <div>
   <div class="hero-sub">ADVANCED EMAIL DEFENSE SYSTEM / SOC TERMINAL</div>
   <div class="hero-title">PHISHSHIELD <span style="color:#4dffb0">X</span></div>
   <div style="color:#b0c9d9;margin-top:12px">
    AI-POWERED EMAIL THREAT INVESTIGATION & INTELLIGENCE
   </div>
  </div>
  <div style="text-align:right">
   <div class="live">● SYSTEM ONLINE</div>
   <div style="color:#91b5c8;font-size:12px;margin-top:12px">
    THREAT MONITORING CENTER
   </div>
  </div>
 </div>
</div>
""", unsafe_allow_html=True)

st.markdown("### ◈ SECURITY INTELLIGENCE OVERVIEW")

# KPI CARDS
cols = st.columns(4)
cards = [
    ("TOTAL SCANS",total,"EMAILS ANALYZED"),
    ("HIGH THREATS",high,"CRITICAL INVESTIGATIONS"),
    ("MEDIUM THREATS",medium,"MODERATE RISK"),
    ("AVG RISK SCORE",f"{avg_score}/100","BASED ON SAVED SCANS")
]

for col,(label,value,note) in zip(cols,cards):
    col.markdown(f"""
    <div class="kpi">
      <div class="kpi-label">{label}</div>
      <div class="kpi-value">{value}</div>
      <div class="kpi-note">● {note}</div>
    </div>
    """,unsafe_allow_html=True)

st.write("")
left,right = st.columns([1.25,1])

# THREAT DISTRIBUTION
with left:
    st.markdown('<div class="panel"><div class="panel-title">◈ THREAT DISTRIBUTION</div></div>',unsafe_allow_html=True)
    if total:
        chart = pd.DataFrame({
            "Threat Level":["HIGH","MEDIUM","LOW"],
            "Scans":[high,medium,low]
        })
        st.bar_chart(chart.set_index("Threat Level"),height=230)
    else:
        st.info("No scan data yet. Your threat analytics will appear here after investigations.")

# SECURITY SCORE
with right:
    st.markdown('<div class="panel"><div class="panel-title">◈ THREAT EXPOSURE INDEX</div></div>',unsafe_allow_html=True)
    st.markdown(f"""
    <div style="background:#102238;border:1px solid #28445b;
    border-radius:15px;text-align:center;padding:27px;margin-top:8px">
       <div style="font-size:12px;color:#92b1c5;letter-spacing:2px">HIGH-RISK SCAN SHARE</div>
       <div style="font-family:Orbitron;font-size:47px;color:#ff667e;margin:12px">
       {threat_rate}%
       </div>
       <div style="font-size:12px;color:#8daabe">
       {high} HIGH-RISK SCANS / {total} TOTAL SCANS
       </div>
    </div>
    """,unsafe_allow_html=True)

st.write("")
st.markdown("### ◈ THREAT ACTIVITY TIMELINE")

if total:
    activity = df.copy()
    activity["scan_time"] = pd.to_datetime(activity["scan_time"],errors="coerce")
    activity = activity.dropna(subset=["scan_time"])
    if not activity.empty:
        daily = activity.groupby(activity["scan_time"].dt.date).size()
        st.area_chart(daily,height=220)
    else:
        st.info("No valid timestamps found.")
else:
    st.info("Your scan timeline will populate automatically after the first email scan.")

st.markdown("### ◈ RECENT SECURITY INVESTIGATIONS")

if total:
    st.dataframe(
        df[["scan_time","sender","subject","risk_level","risk_score"]].head(8),
        use_container_width=True,
        hide_index=True
    )
else:
    st.info("Investigation feed is awaiting its first scan.")

st.markdown("### ◈ DEFENSE MODULES")

modules = [
    ("📧","EMAIL FORENSICS","Inspect email headers and content","pages/2_Email_Forensics.py"),
    ("🌐","URL INTELLIGENCE","Analyze suspicious links","pages/3_URL_Intelligence.py"),
    ("🧠","EXPLAINABLE AI","Understand model predictions","pages/4_Explainable_AI.py"),
    ("🔬","RESEARCH LAB","Compare ML model performance","pages/5_Research_Lab.py"),
    ("📜","SCAN HISTORY","Review previous investigations","pages/6_Scan_History.py"),
    ("📊","SECURITY ANALYTICS","Explore threat statistics","pages/7_Security_Analytics.py")
]

for start in range(0,len(modules),3):
    cols = st.columns(3)
    for col,(icon,name,desc,path) in zip(cols,modules[start:start+3]):
        with col:
            st.markdown(f"""
            <div class="module">
              <div class="module-icon">{icon}</div>
              <div class="module-name">{name}</div>
              <div class="module-desc">{desc}</div>
            </div>
            """,unsafe_allow_html=True)
            if st.button("OPEN MODULE →",key=name,use_container_width=True):
                st.switch_page(path)

st.markdown("---")
st.markdown(
    "<center style='color:#607e95;font-size:11px;letter-spacing:2px'>"
    "PHISHSHIELD X  |  INTELLIGENT CYBER DEFENSE  |  SOC TERMINAL"
    "</center>",
    unsafe_allow_html=True
)

# ==========================================
# ADVANCED VISUAL INTELLIGENCE SECTION
# ==========================================

import matplotlib.pyplot as plt
import numpy as np

st.markdown("---")
st.markdown("## 🌐 ADVANCED THREAT INTELLIGENCE")
st.caption("DEEP SECURITY VISUALIZATION AND INVESTIGATION ANALYTICS")

if not df.empty:

    visual_df = df.copy()
    visual_df["risk_score"] = pd.to_numeric(
        visual_df["risk_score"], errors="coerce"
    ).fillna(0)

    visual_df["scan_time"] = pd.to_datetime(
        visual_df["scan_time"], errors="coerce"
    )

    # 1. DONUT CHART
    st.markdown("### ◈ THREAT SEVERITY RADAR")

    col1, col2 = st.columns([1, 1])

    with col1:
        fig, ax = plt.subplots(figsize=(6, 4))
        fig.patch.set_facecolor("#101d2d")
        ax.set_facecolor("#101d2d")

        values = [high, medium, low]
        labels = ["HIGH", "MEDIUM", "LOW"]

        if sum(values) > 0:
            ax.pie(
                values,
                labels=labels,
                autopct="%1.1f%%",
                startangle=90,
                wedgeprops={"width": 0.42},
                textprops={"color": "white"}
            )
            ax.text(
                0, 0, str(total),
                ha="center", va="center",
                color="white", fontsize=25,
                fontweight="bold"
            )
        ax.set_title(
            "THREAT DISTRIBUTION",
            color="white", pad=15
        )
        st.pyplot(fig)
        plt.close(fig)

    with col2:
        st.markdown("#### SECURITY STATUS")
        st.metric("High Risk Share", f"{threat_rate}%")
        st.metric("Average Risk Score", f"{avg_score}/100")
        st.metric("Total Investigations", total)

        st.progress(min(avg_score / 100, 1.0))
        st.caption("Average risk score indicator")

    st.markdown("---")

    # 2. RISK SCORE DISTRIBUTION
    st.markdown("### ◈ RISK SCORE DISTRIBUTION")

    fig, ax = plt.subplots(figsize=(11, 3.5))
    fig.patch.set_facecolor("#101d2d")
    ax.set_facecolor("#101d2d")

    ax.hist(
        visual_df["risk_score"],
        bins=10,
        edgecolor="white",
        alpha=0.85
    )
    ax.set_xlabel("Risk Score", color="white")
    ax.set_ylabel("Number of Scans", color="white")
    ax.tick_params(colors="white")
    ax.set_title("EMAIL RISK SCORE FREQUENCY", color="white")
    ax.grid(alpha=0.15)

    st.pyplot(fig, use_container_width=True)
    plt.close(fig)

    st.markdown("---")

    # 3. SCAN ACTIVITY HEATMAP
    st.markdown("### ◈ INVESTIGATION ACTIVITY HEATMAP")

    time_df = visual_df.dropna(subset=["scan_time"]).copy()

    if not time_df.empty:
        time_df["weekday"] = time_df["scan_time"].dt.day_name()
        time_df["hour"] = time_df["scan_time"].dt.hour

        weekdays = [
            "Monday", "Tuesday", "Wednesday",
            "Thursday", "Friday", "Saturday", "Sunday"
        ]

        heatmap_data = pd.crosstab(
            time_df["weekday"], time_df["hour"]
        ).reindex(weekdays, fill_value=0)

        fig, ax = plt.subplots(figsize=(12, 4))
        fig.patch.set_facecolor("#101d2d")
        ax.set_facecolor("#101d2d")

        image = ax.imshow(
            heatmap_data.values,
            aspect="auto",
            cmap="viridis"
        )

        ax.set_yticks(range(len(weekdays)))
        ax.set_yticklabels(weekdays, color="white")
        ax.set_xlabel("Hour of Day", color="white")
        ax.set_title("SCAN FREQUENCY BY DAY AND HOUR", color="white")
        ax.tick_params(colors="white")

        fig.colorbar(image, ax=ax, label="Number of scans")
        st.pyplot(fig, use_container_width=True)
        plt.close(fig)
    else:
        st.info("Timestamp data is unavailable for the heatmap.")

    st.markdown("---")

    # 4. SENDER ANALYSIS
    st.markdown("### ◈ SENDER INTELLIGENCE")

    if "sender" in visual_df.columns:
        sender_counts = (
            visual_df["sender"]
            .fillna("Unknown")
            .value_counts()
            .head(8)
        )

        st.bar_chart(
            sender_counts,
            height=300,
            horizontal=True
        )

    st.markdown("---")

    # 5. THREAT CATEGORY BREAKDOWN
    st.markdown("### ◈ THREAT CATEGORY BREAKDOWN")

    threat_data = pd.DataFrame({
        "Category": ["High Risk", "Medium Risk", "Low Risk"],
        "Count": [high, medium, low]
    })

    st.dataframe(
        threat_data,
        use_container_width=True,
        hide_index=True
    )

    st.markdown("---")

    # 6. SECURITY INSIGHTS
    st.markdown("### ◈ AUTOMATED SECURITY INSIGHTS")

    insights = []

    if high:
        insights.append(
            f"⚠️ {high} high-risk investigation(s) require attention."
        )

    if medium:
        insights.append(
            f"🟠 {medium} medium-risk investigation(s) detected."
        )

    if low:
        insights.append(
            f"🟢 {low} low-risk investigation(s) recorded."
        )

    if not high and not medium:
        insights.append(
            "✅ No high or medium risk scans recorded in the current history."
        )

    for insight in insights:
        st.info(insight)

else:
    st.info(
        "Advanced visual analytics will populate after email scans "
        "are saved in the database."
    )

st.markdown("---")
st.markdown("## 🛡️ PHISHSHIELD X | DEFENSE INTELLIGENCE")
st.caption(
    "AI-POWERED EMAIL SECURITY • THREAT ANALYTICS • "
    "EXPLAINABLE INVESTIGATION"
)




