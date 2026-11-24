
import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse

URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "expire",
    "limited", "warning", "action required", "blocked"
]

CREDENTIAL_WORDS = [
    "password", "otp", "login", "credential",
    "account", "verify", "bank", "payment"
]

ACTION_WORDS = [
    "click", "open", "download", "confirm",
    "update", "verify", "submit", "register"
]

REWARD_WORDS = [
    "winner", "prize", "reward", "gift",
    "free", "lottery", "claim"
]


def count_terms(text, terms):
    text = str(text).lower()
    return sum(text.count(term) for term in terms)


def extract_features(text):
    text = str(text)
    lower = text.lower()

    urls = re.findall(r"https?://\S+|www\.\S+", text, re.I)
    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )

    # Linguistic features
    linguistic = {
        "ling_urgency_words": count_terms(lower, URGENCY_WORDS),
        "ling_exclamation_count": text.count("!"),
        "ling_question_count": text.count("?"),
        "ling_uppercase_count": sum(c.isupper() for c in text),
        "ling_word_count": len(text.split()),
        "ling_avg_word_length": (
            np.mean([len(w) for w in text.split()])
            if text.split() else 0
        ),
    }

    # Semantic cue features (keyword-based proxies)
    semantic = {
        "sem_credential_terms": count_terms(lower, CREDENTIAL_WORDS),
        "sem_action_terms": count_terms(lower, ACTION_WORDS),
        "sem_reward_terms": count_terms(lower, REWARD_WORDS),
        "sem_financial_terms": count_terms(
            lower, ["bank", "payment", "money", "refund", "invoice"]
        ),
    }

    # Contextual features available from email body text
    contextual = {
        "ctx_url_count": len(urls),
        "ctx_email_address_count": len(emails),
        "ctx_ip_url_count": sum(
            bool(re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", u))
            for u in urls
        ),
        "ctx_http_url_count": sum(u.lower().startswith("http://") for u in urls),
        "ctx_shortener_count": sum(
            any(s in u.lower() for s in ["bit.ly", "tinyurl", "t.co"])
            for u in urls
        ),
        "ctx_long_url_count": sum(len(u) > 75 for u in urls),
    }

    return {**linguistic, **semantic, **contextual}


def extract_feature_groups(text):
    features = extract_features(text)

    return {
        "Linguistic": sum(
            v for k, v in features.items() if k.startswith("ling_")
        ),
        "Semantic": sum(
            v for k, v in features.items() if k.startswith("sem_")
        ),
        "Contextual": sum(
            v for k, v in features.items() if k.startswith("ctx_")
        ),
    }


def extract_features_dataframe(texts):
    return pd.DataFrame([extract_features(t) for t in texts]).fillna(0)
