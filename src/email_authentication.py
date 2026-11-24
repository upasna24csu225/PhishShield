


import re


def analyze_email_authentication(headers):
    """
    Extract SPF, DKIM and DMARC results from Authentication-Results.

    Note:
    These are reported header results, not independent verification.
    """

    results = {
        "SPF": "Not available",
        "DKIM": "Not available",
        "DMARC": "Not available"
    }

    if not headers:
        return results

    auth_headers = headers.get("Authentication-Results", [])

    if isinstance(auth_headers, str):
        auth_headers = [auth_headers]

    auth_text = " ".join(
        str(value) for value in auth_headers
    ).lower()

    for mechanism in ("SPF", "DKIM", "DMARC"):

        pattern = (
            rf"(?<![\w-]){mechanism.lower()}"
            rf"\s*=\s*(pass|fail|softfail|none|neutral|temperror|permerror)"
        )

        matches = re.findall(pattern, auth_text)

        if matches:
            results[mechanism] = matches[0].upper()

    return results
