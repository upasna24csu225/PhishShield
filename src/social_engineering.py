
def detect_social_engineering(email_text):

    text = str(email_text).lower()

    categories = {
        "urgency": [
            "urgent", "immediately", "act now",
            "within 24 hours", "limited time", "asap"
        ],
        "fear": [
            "account suspended", "account blocked",
            "legal action", "security alert",
            "unauthorized access", "your account is at risk"
        ],
        "reward": [
            "you won", "free gift", "prize",
            "lottery", "claim reward", "congratulations"
        ],
        "action": [
            "click here", "verify your account",
            "reset password", "update details",
            "confirm your identity", "login now"
        ]
    }

    results = {}
    findings = []

    for category, keywords in categories.items():

        matched = [word for word in keywords if word in text]

        results[category] = {
            "count": len(matched),
            "matched_keywords": matched
        }

        if matched:
            findings.append(
                f"{category.title()} tactics detected: {', '.join(matched)}"
            )

    total_count = sum(item["count"] for item in results.values())

    return {
        "total_indicators": total_count,
        "categories": results,
        "findings": findings,
        "suspicious": total_count > 0
    }