import random

def detect_ransomware(log):
    # Simple rule-based + ML placeholder

    score = 0

    # High entropy → suspicious
    if log["entry_point_entropy"] > 6.5:
        score += 30

    if log["contains_packer_signature"]:
        score += 25

    if log["has_anti_debug_indicators"]:
        score += 20

    if log["process_activity_count"] > 15:
        score += 25

    # Decide severity
    if score >= 70:
        return {"prediction": "ransomware", "severity": "CRITICAL"}
    elif score >= 40:
        return {"prediction": "suspicious", "severity": "HIGH"}
    else:
        return {"prediction": "benign", "severity": "LOW"}