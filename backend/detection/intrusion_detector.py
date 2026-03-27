import json
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "blocked_ips.json")


def load_blocked_ips():
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        pass
    return {}


def save_blocked_ips(blocked_ips):
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
    with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
        json.dump(blocked_ips, f, indent=2)


def is_blocked_ip(src_ip):
    blocked = load_blocked_ips()
    return str(src_ip).strip() in blocked


def block_ip(src_ip, reason="Intrusion detected", prediction="Intrusion"):
    blocked = load_blocked_ips()
    src_ip = str(src_ip).strip()
    blocked[src_ip] = {
        "blocked_at": datetime.utcnow().isoformat(),
        "reason": reason,
        "prediction": prediction,
        "status": "blocked",
    }
    save_blocked_ips(blocked)
    return blocked


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def detect_intrusion(log):
    """
    Rule-based detector for now.
    Replace this later with your real ML model if needed.
    """
    score = 0.0

    packets_per_sec = _safe_float(log.get("packets_per_sec", 0))
    bytes_sent = _safe_float(log.get("bytes_sent", 0))
    duration = _safe_float(log.get("duration", 0))
    flag = str(log.get("flag", "")).upper()
    service = str(log.get("service", "")).lower()
    port = _safe_int(log.get("port", 0))

    if packets_per_sec > 1000:
        score += 0.40
    if bytes_sent > 100000:
        score += 0.25
    if flag in {"REJ", "S0", "RSTO", "SH"}:
        score += 0.15
    if port in {22, 23, 445, 3389, 8080}:
        score += 0.10
    if duration < 1.0:
        score += 0.05
    if service in {"ssh", "smtp", "other"}:
        score += 0.05

    score = min(score, 0.99)

    if score > 0.6:
        return "Intrusion", "HIGH", score
    if score > 0.3:
        return "Suspicious", "MEDIUM", score
    return "Normal", "LOW", score


def process_intrusion_log(log):
    """
    Main entry:
    - skip if source IP already blocked
    - detect
    - block source IP if malicious
    """
    src_ip = str(log.get("src_ip", "")).strip()

    if not src_ip:
        return {
            "prediction": "Unknown",
            "severity": "LOW",
            "confidence": 0.0,
            "blocked": False,
            "message": "Missing src_ip",
        }

    if is_blocked_ip(src_ip):
        return {
            "prediction": "Blocked",
            "severity": "HIGH",
            "confidence": 1.0,
            "blocked": True,
            "message": "Source IP already blocked; detection skipped.",
        }

    prediction, severity, confidence = detect_intrusion(log)

    blocked = False
    if prediction == "Intrusion":
        block_ip(
            src_ip,
            reason=f"Intrusion detected with confidence {confidence:.2f}",
            prediction=prediction,
        )
        blocked = True

    return {
        "prediction": prediction,
        "severity": severity,
        "confidence": confidence,
        "blocked": blocked,
    }


def get_blocked_ips():
    return load_blocked_ips()