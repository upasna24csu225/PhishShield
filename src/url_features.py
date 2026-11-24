

import re
from urllib.parse import urlparse

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "is.gd"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "password", "bank", "confirm"
]


def extract_url_features(urls):

    if isinstance(urls, str):
        urls = re.findall(r'https?://\S+|www\.\S+', urls)

    results = []
    suspicious_count = 0

    for url in urls:
        url = url.strip(".,;:!?()[]{}<>")

        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower()

        reasons = []

        if not url.lower().startswith("https://"):
            reasons.append("Not using HTTPS")

        if "@" in url:
            reasons.append("Contains @ symbol")

        if len(url) > 100:
            reasons.append("Unusually long URL")

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]):
            reasons.append("Uses IP address")

        if any(shortener in domain for shortener in SHORTENERS):
            reasons.append("URL shortener detected")

        if any(word in url.lower() for word in SUSPICIOUS_KEYWORDS):
            reasons.append("Suspicious keyword detected")

        if len(domain.split(".")) > 3:
            reasons.append("Multiple subdomains")

        if reasons:
            suspicious_count += 1

        results.append({
            "url": url,
            "domain": domain,
            "suspicious": bool(reasons),
            "reasons": reasons
        })

    return {
        "total_urls": len(results),
        "suspicious_count": suspicious_count,
        "urls": results
    }