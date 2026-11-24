


import streamlit as st
import pandas as pd
import re
from urllib.parse import urlparse
from datetime import datetime


st.set_page_config(
    page_title="URL Intelligence | PhishShield X",
    page_icon="🔎",
    layout="wide"
)

st.title("🔎 URL Intelligence")
st.caption("Analyze suspicious URLs using rule-based security indicators.")


SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure",
    "account", "banking", "password",
    "signin", "confirm", "wallet"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd"
]


def analyze_url(url):

    url = url.strip()

    if not url:
        return None

    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("Invalid URL or missing hostname")

    hostname = parsed.hostname.lower()

    findings = []
    score = 0

    if parsed.scheme != "https":
        findings.append("Not using HTTPS")
        score += 15

    if "@" in parsed.netloc:
        findings.append("Contains @ symbol")
        score += 20

    if len(url) > 75:
        findings.append("Unusually long URL")
        score += 10

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        findings.append("Uses an IP address instead of a domain")
        score += 25

    if any(
        hostname == shortener or hostname.endswith("." + shortener)
        for shortener in SHORTENERS
    ):
        findings.append("URL shortening service detected")
        score += 15

    if any(word in url.lower() for word in SUSPICIOUS_WORDS):
        findings.append("Contains suspicious keywords")
        score += 15

    if hostname.count(".") >= 3:
        findings.append("Multiple subdomains detected")
        score += 10

    try:
        if parsed.port and parsed.port not in (80, 443):
            findings.append("Uses a non-standard port")
            score += 10
    except ValueError:
        raise ValueError("Invalid port in URL")

    score = min(score, 100)

    if score >= 60:
        status = "HIGH"
    elif score >= 30:
        status = "MEDIUM"
    else:
        status = "LOW"

    return {
        "URL": url,
        "Domain": hostname,
        "Risk Score": score,
        "Risk Level": status,
        "Findings": "; ".join(findings)
        if findings else "No configured indicators detected"
    }


url_input = st.text_area(
    "Enter URLs (one URL per line)",
    placeholder="https://example.com\nhttp://suspicious-example.com/login"
)


if st.button("Analyze URLs", type="primary"):

    urls = [
        item.strip()
        for item in url_input.splitlines()
        if item.strip()
    ]

    if not urls:

        st.warning("Please enter at least one URL.")

    else:

        results = []

        for url in urls:

            try:

                result = analyze_url(url)

                if result:
                    results.append(result)

            except Exception as error:

                st.warning(f"Could not analyze {url}: {error}")

        if results:

            df = pd.DataFrame(results)

            high_count = int((df["Risk Level"] == "HIGH").sum())
            medium_count = int((df["Risk Level"] == "MEDIUM").sum())
            low_count = int((df["Risk Level"] == "LOW").sum())

            # FINAL URL VERDICT

            st.divider()
            st.subheader("🚨 FINAL URL VERDICT")

            if high_count > 0:

                st.error(
                    "🚨 POTENTIALLY MALICIOUS URL DETECTED"
                )

                st.write(
                    f"{high_count} URL(s) have a high risk score. "
                    "Avoid opening these URLs."
                )

            elif medium_count > 0:

                st.warning(
                    "⚠️ SUSPICIOUS URL DETECTED"
                )

                st.write(
                    f"{medium_count} URL(s) contain suspicious "
                    "characteristics and require further investigation."
                )

            else:

                st.success(
                    "✅ NO MAJOR SUSPICIOUS INDICATORS DETECTED"
                )

                st.write(
                    "All analyzed URLs have a low heuristic risk score. "
                    "This does not guarantee that they are safe."
                )

            # SUMMARY

            st.subheader("📊 Analysis Summary")

            col1, col2, col3, col4 = st.columns(4)

            col1.metric("URLs Analyzed", len(df))
            col2.metric("High Risk", high_count)
            col3.metric("Medium Risk", medium_count)
            col4.metric("Low Risk", low_count)

            st.divider()

            # INDIVIDUAL URL VERDICTS

            st.subheader("🔍 Individual URL Verdicts")

            for index, row in df.iterrows():

                with st.container(border=True):

                    st.write(f"**URL {index + 1}:** {row['URL']}")

                    col1, col2 = st.columns(2)

                    col1.metric(
                        "Risk Score",
                        f"{row['Risk Score']}/100"
                    )

                    col2.metric(
                        "Risk Level",
                        row["Risk Level"]
                    )

                    if row["Risk Level"] == "HIGH":

                        st.error("🚨 POTENTIALLY MALICIOUS")

                    elif row["Risk Level"] == "MEDIUM":

                        st.warning("⚠️ SUSPICIOUS URL")

                    else:

                        st.success(
                            "✅ NO MAJOR SUSPICIOUS INDICATORS"
                        )

                    st.write("**Domain:**", row["Domain"])
                    st.write("**Findings:**", row["Findings"])

            st.divider()

            # DETAILED RESULTS TABLE

            st.subheader("URL Investigation Results")

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True
            )

            # RISK DISTRIBUTION

            st.subheader("Risk Distribution")

            distribution = (
                df["Risk Level"]
                .value_counts()
                .reindex(["HIGH", "MEDIUM", "LOW"], fill_value=0)
            )

            st.bar_chart(distribution)

            # CSV DOWNLOAD

            csv = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "📥 Download URL Analysis CSV",
                data=csv,
                file_name="phishshield_url_report.csv",
                mime="text/csv"
            )

            st.caption(
                "Analysis generated on "
                + datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            )

        else:

            st.error(
                "No valid URLs could be analyzed. "
                "Please check your input."
            )


st.divider()

st.warning(
    "This tool uses URL-based heuristic indicators. "
    "It does not visit URLs, verify website ownership, "
    "or guarantee that a URL is safe or malicious."
)
