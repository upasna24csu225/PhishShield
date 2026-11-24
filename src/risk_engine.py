

from urllib.parse import urlparse


def calculate_risk(email_features, url_features, social_features):

    score = 0
    evidence = []

    # Email indicators
    if email_features.get("urgency_count", 0) > 0:
        score += 10
        evidence.append("Urgency-related language detected")

    if email_features.get("credential_count", 0) > 0:
        score += 15
        evidence.append("Credential-related keywords detected")

    if email_features.get("url_count", 0) > 0:
        score += 10
        evidence.append("Email contains URLs")

    # URL indicators
    suspicious_urls = url_features.get("suspicious_count", 0)

    if suspicious_urls > 0:
        score += min(suspicious_urls * 15, 40)
        evidence.append(
            f"{suspicious_urls} suspicious URL(s) detected"
        )

    # Social engineering indicators
    indicators = social_features.get("total_indicators", 0)

    if indicators > 0:
        score += min(indicators * 5, 25)
        evidence.append(
            f"{indicators} social engineering indicator(s) detected"
        )

    score = min(score, 100)

    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "evidence": evidence
    }


def detect_header_spoofing(sender, reply_to):

    def get_domain(address):
        if not address or "@" not in address:
            return ""

        return address.split("@")[-1].strip().lower().strip(">")

    sender_domain = get_domain(sender)
    reply_domain = get_domain(reply_to)

    spoofing_indicator = False

    if sender_domain and reply_domain:
        spoofing_indicator = sender_domain != reply_domain

    return {
        "spoofing_indicator": spoofing_indicator,
        "sender_domain": sender_domain or "Unavailable",
        "reply_domain": reply_domain or "Unavailable"
    }