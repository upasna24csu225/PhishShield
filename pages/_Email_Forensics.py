
import streamlit as st
import re
import pandas as pd

from email import policy
from email.parser import BytesParser

from src.risk_engine import calculate_risk, detect_header_spoofing
from src.features import extract_features
from src.url_features import extract_url_features
from src.social_engineering import detect_social_engineering
from src.email_authentication import analyze_email_authentication
from src.threat_correlation import correlate_threat_indicators
from src.scan_history import save_scan
from src.report_generator import generate_pdf_report


st.set_page_config(
    page_title="Email Forensics | PhishShield X",
    page_icon="📧",
    layout="wide"
)

st.title("📧 Email Forensics")
st.caption("Multi-layer email threat investigation and forensic analysis.")


def analyze_email(uploaded_file):

    message = BytesParser(policy=policy.default).parse(uploaded_file)

    sender = str(message.get("From", "Unknown"))
    reply_to = str(message.get("Reply-To", sender))
    subject = str(message.get("Subject", "No Subject"))

    body_parts = []
    attachments = []

    for part in message.walk():

        if part.is_multipart():
            continue

        filename = part.get_filename()

        if filename:

            payload = part.get_payload(decode=True) or b""

            attachments.append({
                "filename": filename,
                "file_type": filename.split(".")[-1].lower()
                if "." in filename else "Unknown",
                "size": len(payload)
            })

        elif part.get_content_type() == "text/plain":

            try:
                body_parts.append(part.get_content())

            except Exception:
                payload = part.get_payload(decode=True)

                if payload:
                    body_parts.append(
                        payload.decode("utf-8", errors="replace")
                    )

    body = "\n".join(body_parts)

    urls = list(set(
        re.findall(r'https?://[^\s<>"\']+', body, re.I)
    ))

    authentication = analyze_email_authentication({
        "Authentication-Results": message.get_all(
            "Authentication-Results", []
        )
    })

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "urls": urls,
        "attachments": attachments,
        "authentication": authentication
    }


uploaded_file = st.file_uploader(
    "Upload an email file (.eml)",
    type=["eml"]
)


if uploaded_file:

    if st.button("Start Email Investigation", type="primary"):

        try:

            data = analyze_email(uploaded_file)

            if not data["body"].strip():
                st.warning(
                    "No readable plain-text email body was found. "
                    "The analysis may be incomplete."
                )

            email_features = extract_features(data["body"])

            url_features = extract_url_features(data["urls"])

            social_features = detect_social_engineering(data["body"])

            header_result = detect_header_spoofing(
                data["sender"],
                data["reply_to"]
            )

            risk = calculate_risk(
                email_features,
                url_features,
                social_features
            )

            correlation = correlate_threat_indicators(
                email_features=email_features,
                url_features=url_features,
                social_features=social_features,
                header_result=header_result,
                attachments=data["attachments"],
                authentication=data["authentication"]
            )

            st.session_state["investigation"] = {
                "data": data,
                "risk": risk,
                "header_result": header_result,
                "correlation": correlation
            }

            save_scan(
                sender=data["sender"],
                subject=data["subject"],
                risk_level=risk.get("risk_level", "UNKNOWN"),
                risk_score=risk.get("risk_score", 0),
                urls_found=len(data["urls"]),
                attachments_found=len(data["attachments"]),
                spoofing_detected=header_result.get(
                    "spoofing_indicator", False
                )
            )

            st.success("Email investigation completed successfully!")

        except Exception as error:
            st.error(f"Investigation failed: {error}")


if "investigation" in st.session_state:

    result = st.session_state["investigation"]

    data = result["data"]
    risk = result["risk"]
    header_result = result["header_result"]
    correlation = result["correlation"]

    risk_score = risk.get("risk_score", 0)
    risk_level = str(risk.get("risk_level", "Low")).strip().lower()

    st.divider()

    # FINAL EMAIL VERDICT

    st.subheader("🚨 FINAL EMAIL VERDICT")

    if risk_level == "high":

        st.error("🚨 PHISHING EMAIL DETECTED")

        st.write(
            "This email has been classified as HIGH RISK. "
            "It contains multiple suspicious indicators. "
            "Avoid clicking links or downloading attachments."
        )

    elif risk_level == "medium":

        st.warning("⚠️ SUSPICIOUS EMAIL DETECTED")

        st.write(
            "This email contains suspicious indicators "
            "and requires further investigation."
        )

    elif risk_level == "low":

        st.success("✅ LIKELY LEGITIMATE EMAIL")

        st.write(
            "No major suspicious indicators were detected "
            "by the configured risk analysis."
        )

    else:

        st.info("ℹ️ EMAIL VERDICT UNAVAILABLE")

        st.write(
            "The risk engine returned an unrecognized risk level. "
            "Please verify the analysis."
        )

    col1, col2 = st.columns(2)

    col1.metric("Final Risk Score", f"{risk_score}/100")
    col2.metric("Threat Classification", risk.get("risk_level", "Unknown"))

    st.caption(
        "This verdict is based on the configured risk engine. "
        "A low-risk result does not guarantee that an email is safe."
    )

    st.divider()

    # 1. EMAIL INFORMATION

    st.subheader("1. Email Information")

    col1, col2 = st.columns(2)

    col1.write("**Sender:**")
    col1.write(data["sender"])

    col2.write("**Subject:**")
    col2.write(data["subject"])

    st.write("**Reply-To:**", data["reply_to"])

    with st.expander("View Email Body"):
        st.text(data["body"])

    st.divider()

    # 2. THREAT RISK ASSESSMENT

    st.subheader("2. Threat Risk Assessment")

    col1, col2 = st.columns(2)

    col1.metric(
        "Risk Score",
        risk.get("risk_score", "N/A")
    )

    col2.metric(
        "Risk Level",
        risk.get("risk_level", "Unknown")
    )

    evidence = risk.get("evidence", [])

    if evidence:

        st.write("**Risk Evidence**")

        for item in evidence:
            st.write("•", item)

    else:
        st.info("No risk evidence was returned by the risk engine.")

    st.divider()

    # 3. HEADER SPOOFING ANALYSIS

    st.subheader("3. Header Spoofing Analysis")

    st.write(
        "Possible Spoofing Indicator:",
        header_result.get("spoofing_indicator", False)
    )

    st.write(
        "Sender Domain:",
        header_result.get("sender_domain", "Unknown")
    )

    st.write(
        "Reply-To Domain:",
        header_result.get("reply_domain", "Unknown")
    )

    st.caption(
        "A sender and Reply-To mismatch is suspicious, "
        "but does not independently prove spoofing."
    )

    st.divider()

    # 4. EMAIL AUTHENTICATION

    st.subheader("4. Email Authentication")

    authentication_df = pd.DataFrame(
        list(data["authentication"].items()),
        columns=["Mechanism", "Result"]
    )

    st.dataframe(
        authentication_df,
        use_container_width=True,
        hide_index=True
    )

    st.caption(
        "Authentication results are extracted from available "
        "email headers and are not independently verified."
    )

    st.divider()

    # 5. THREAT INTELLIGENCE CORRELATION

    st.subheader("5. Threat Intelligence Correlation")

    col1, col2 = st.columns(2)

    col1.metric(
        "Correlation Score",
        correlation.get("correlation_score", 0)
    )

    col2.metric(
        "Overall Status",
        correlation.get("overall_status", "Unknown")
    )

    st.write(
        "Total Findings:",
        correlation.get("total_findings", 0)
    )

    findings = correlation.get("findings", [])

    if findings:

        st.dataframe(
            pd.DataFrame(findings),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No configured correlation indicators detected.")

    st.divider()

    # 6. URL INTELLIGENCE

    st.subheader("6. URL Intelligence")

    if data["urls"]:

        st.dataframe(
            pd.DataFrame({"Detected URLs": data["urls"]}),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No URLs detected.")

    st.divider()

    # 7. ATTACHMENT ANALYSIS

    st.subheader("7. Attachment Analysis")

    if data["attachments"]:

        st.dataframe(
            pd.DataFrame(data["attachments"]),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No attachments detected.")

    st.warning(
        "Attachment analysis checks metadata only. "
        "Files are not executed or malware-scanned."
    )

    st.divider()

    # 8. DOWNLOAD INVESTIGATION REPORT

    st.subheader("8. Download Investigation Report")

    try:

        pdf_report = generate_pdf_report(
            data,
            risk,
            header_result,
            correlation
        )

        st.download_button(
            label="Download PDF Report",
            data=pdf_report,
            file_name="PhishShield_Email_Report.pdf",
            mime="application/pdf"
        )

    except Exception as error:
        st.error(f"PDF generation failed: {error}")

