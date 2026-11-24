


def correlate_threat_indicators(
    email_features,
    url_features,
    social_features,
    header_result,
    attachments,
    authentication=None
):

    findings = []
    score = 0

    # Email indicators
    if email_features.get("urgency_count", 0) > 0:
        findings.append("Urgency indicators found in email")
        score += 10

    if email_features.get("credential_count", 0) > 0:
        findings.append("Credential-related language found")
        score += 10

    # URL indicators
    suspicious_urls = url_features.get("suspicious_count", 0)

    if suspicious_urls:
        findings.append(
            f"{suspicious_urls} suspicious URL(s) detected"
        )
        score += min(suspicious_urls * 15, 30)

    # Social engineering indicators
    social_count = social_features.get("total_indicators", 0)

    if social_count:
        findings.append(
            f"{social_count} social engineering indicators detected"
        )
        score += min(social_count * 5, 20)

    # Header spoofing
    if header_result.get("spoofing_indicator", False):
        findings.append("Sender and Reply-To domains do not match")
        score += 20

    # Attachment analysis
    dangerous_extensions = {
        ".exe", ".scr", ".bat", ".cmd",
        ".js", ".vbs", ".ps1", ".msi"
    }

    for attachment in attachments or []:
        filename = str(attachment.get("filename", "")).lower()

        if any(filename.endswith(ext) for ext in dangerous_extensions):
            findings.append(
                f"Potentially dangerous attachment: {filename}"
            )
            score += 15

    # Authentication analysis
    for mechanism, status in (authentication or {}).items():

        if str(status).lower() in [
            "fail", "softfail", "permerror", "temperror"
        ]:
            findings.append(
                f"{mechanism} authentication status: {status}"
            )
            score += 10

    score = min(score, 100)

    if score >= 60:
        overall_status = "HIGH"
    elif score >= 30:
        overall_status = "MEDIUM"
    else:
        overall_status = "LOW"

    return {
        "correlation_score": score,
        "overall_status": overall_status,
        "total_findings": len(findings),
        "findings": findings
    }