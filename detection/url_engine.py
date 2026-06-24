import re
from urllib.parse import urlparse

def analyze_url(url):

    parsed = urlparse(url)

    score = 0
    reasons = []

    domain = parsed.netloc.lower()

    # 1. HTTP instead of HTTPS
    if parsed.scheme == "http":
        score += 25
        reasons.append("Uses insecure HTTP instead of HTTPS")

    # 2. IP address used
    if re.match(r"^(\\d{1,3}\\.){3}\\d{1,3}$", domain):
        score += 30
        reasons.append("Uses raw IP address instead of domain")

    # 3. Phishing keywords
    keywords = ["login", "verify", "update", "secure", "bank", "password"]
    for word in keywords:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains phishing keyword: '{word}'")

    # 4. Too many subdomains
    if domain.count(".") > 3:
        score += 15
        reasons.append("Excessive subdomains detected")

    # 5. Long URL
    if len(url) > 80:
        score += 10
        reasons.append("Unusually long URL")

    # Risk level
    if score >= 60:
        risk = "HIGH RISK"
    elif score >= 30:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    return {
        "url": url,
        "score": score,
        "risk": risk,
        "reasons": reasons
    }