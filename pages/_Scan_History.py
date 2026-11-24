
import streamlit as st
import pandas as pd
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.scan_history import get_scan_history, clear_scan_history

st.set_page_config(
    page_title="Scan History | PhishShield X",
    page_icon="📜",
    layout="wide"
)

st.title("📜 Email Scan History")
st.caption("View and manage previously investigated emails")

col1, col2 = st.columns(2)

with col1:
    if st.button("🔄 Refresh History"):
        st.rerun()

with col2:
    if st.button("🗑️ Clear History"):
        st.session_state.confirm_clear = True

if st.session_state.get("confirm_clear", False):
    st.warning("Are you sure you want to delete all scan records?")

    yes, no = st.columns(2)

    with yes:
        if st.button("Yes, Delete All"):
            clear_scan_history()
            st.session_state.confirm_clear = False
            st.success("Scan history cleared!")
            st.rerun()

    with no:
        if st.button("Cancel"):
            st.session_state.confirm_clear = False
            st.rerun()

history = get_scan_history()

if not history:
    st.info(
        "No scan history available. "
        "Upload and scan an email in Email Forensics first."
    )

else:
    df = pd.DataFrame(history)

    st.subheader("Scan Overview")

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Scans", len(df))
    c2.metric("High Risk", int((df["risk_level"] == "HIGH").sum()))
    c3.metric("Medium Risk", int((df["risk_level"] == "MEDIUM").sum()))
    c4.metric("Low Risk", int((df["risk_level"] == "LOW").sum()))

    st.divider()

    st.subheader("Filter Scan Records")

    risk_options = ["All", "HIGH", "MEDIUM", "LOW"]

    selected_risk = st.selectbox(
        "Filter by Risk Level",
        risk_options
    )

    search_sender = st.text_input("Search by Sender")

    filtered_df = df.copy()

    if selected_risk != "All":
        filtered_df = filtered_df[
            filtered_df["risk_level"] == selected_risk
        ]

    if search_sender:
        filtered_df = filtered_df[
            filtered_df["sender"].astype(str).str.contains(
                search_sender,
                case=False,
                na=False
            )
        ]

    st.subheader("Previous Email Scans")

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("Risk Distribution")

    st.bar_chart(
        filtered_df["risk_level"].value_counts()
    )

    st.download_button(
        "📥 Download Scan History CSV",
        data=filtered_df.to_csv(index=False).encode("utf-8"),
        file_name="phishshield_scan_history.csv",
        mime="text/csv"
    )

    st.caption(f"Showing {len(filtered_df)} of {len(df)} scan records.")