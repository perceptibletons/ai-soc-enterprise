def detect_insider(log: dict) -> dict:
    """
    Rule-based insider threat detector.
    Uses login_hour, file_access_count, activity_score.
    Returns {prediction, severity, confidence}
    """
    hour = int(log.get("login_hour", 12))
    fac = int(log.get("file_access_count", 0))
    act = int(log.get("activity_score", 0))

    score = 0.0

    # Off-hours login: midnight–3am or 9pm–midnight
    if hour < 3 or hour >= 21:
        score += 0.40
    elif hour < 6 or hour >= 20:
        score += 0.18

    # Unusual file access volume
    if fac > 100:
        score += 0.35
    elif fac > 50:
        score += 0.22
    elif fac > 20:
        score += 0.10

    # High activity score
    if act > 85:
        score += 0.20
    elif act > 70:
        score += 0.10

    score = min(score, 0.99)
    confidence = round(score, 2)

    if score >= 0.60:
        return {"prediction": "Insider Threat", "severity": "HIGH", "confidence": max(confidence, 0.75)}
    elif score >= 0.30:
        return {"prediction": "Suspicious", "severity": "MEDIUM", "confidence": max(confidence, 0.50)}
    else:
        return {"prediction": "Normal", "severity": "LOW", "confidence": round(1.0 - score, 2)}
