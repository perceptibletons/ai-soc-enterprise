def detect_phishing(log: dict) -> dict:
    """
    Rule-based phishing detector.
    Scores email content, URL, and sender domain for phishing signals.
    Returns {prediction, severity, confidence}
    """
    text = " ".join([
        str(log.get("email_text", "")),
        str(log.get("url", "")),
        str(log.get("sender_domain", "")),
        str(log.get("subject", "")),
    ]).lower()

    PHISHING_KWS = [
        "click", "verify", "account", "password", "urgent",
        "bank", "login", "reset", "suspend", "confirm",
        "credential", "update", "security", "alert", "expire",
        "unusual", "unauthorized", "payment", "claim", "reward",
        "immediately", "deactivat", "cancel", "overdue",
    ]

    PHISHING_DOMAINS = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
        "secure-bank", "account-alert", "login-alert",
        "paypal-secure", "update-your-info", "office365-login",
        "amazon-security", "google-verify",
    ]

    score = sum(1 for kw in PHISHING_KWS if kw in text)

    domain = str(log.get("sender_domain", "")).lower()
    for d in PHISHING_DOMAINS:
        if d in domain:
            score += 4
            break

    url = str(log.get("url", "")).lower()
    if url.startswith("http://"):
        score += 2
    for d in PHISHING_DOMAINS:
        if d in url:
            score += 3
            break

    # Normalize score to confidence 0.0–1.0
    confidence = min(score / 12.0, 0.99)
    confidence = round(confidence, 2)

    if score >= 5:
        return {"prediction": "Phishing", "severity": "HIGH", "confidence": max(confidence, 0.75)}
    elif score >= 2:
        return {"prediction": "Suspicious", "severity": "MEDIUM", "confidence": max(confidence, 0.52)}
    else:
        return {"prediction": "Benign", "severity": "LOW", "confidence": max(1.0 - confidence, 0.78)}
