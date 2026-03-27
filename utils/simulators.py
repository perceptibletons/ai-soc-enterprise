import requests
from datetime import datetime

from config.settings import BACKEND_URL_DEFAULT
from utils.scoring import normalize_severity
from utils.predictions import append_log

# ─────────────────────────────────────────────
# Ransomware
# ─────────────────────────────────────────────
def fetch_generated_ransomware_logs(backend_url=BACKEND_URL_DEFAULT, count=10):
    backend_url = str(backend_url).rstrip("/")
    target = int(count) if count is not None else 10
    collected = []
    while len(collected) < target:
        response = requests.get(f"{backend_url}/generate-ransomware", timeout=15)
        response.raise_for_status()
        batch = response.json().get("generated_logs", []) or []
        if not batch:
            break
        collected.extend(batch)
    return collected[:target]


def send_log_to_backend(backend_url, log):
    backend_url = str(backend_url).rstrip("/")
    response = requests.post(f"{backend_url}/ingest-log", json=log, timeout=15)
    response.raise_for_status()
    return response.json()


def simulate_ransomware_workflow(backend_url=BACKEND_URL_DEFAULT, count=10):
    generated_logs = fetch_generated_ransomware_logs(backend_url, count=count)
    results = []
    for log in generated_logs:
        backend_result = send_log_to_backend(backend_url, log)
        detection = backend_result.get("detection", {}) or {}
        predicted_label = detection.get("prediction", log.get("label", "unknown"))
        raw_severity = detection.get("severity", "LOW")
        severity = normalize_severity(raw_severity)
        confidence = detection.get("confidence", None)
        try:
            confidence = float(confidence)
            if confidence <= 0.0:
                confidence = 0.75
        except Exception:
            confidence = 0.75
        source = log.get("source_host_ip") or log.get("source") or "simulator"
        details = (
            f"file:{log.get('file_name', '')} "
            f"size:{log.get('file_size_bytes', '')} "
            f"entropy:{log.get('entry_point_entropy', '')}"
        ).strip().replace(',', ';')
        append_log("Ransomware", source, severity, predicted_label, confidence, details)
        results.append({
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
            "source": source,
            "file_name": log.get("file_name", ""),
            "label": log.get("label", ""),
            "prediction": predicted_label,
            "severity": severity,
            "confidence": confidence,
            "details": details,
        })
    return results


# ─────────────────────────────────────────────
# Intrusion
# ─────────────────────────────────────────────
def fetch_generated_intrusion_logs(backend_url=BACKEND_URL_DEFAULT, count=10, malicious_bias=0.5):
    backend_url = str(backend_url).rstrip("/")
    response = requests.get(
        f"{backend_url}/generate-intrusion",
        params={"count": int(count), "malicious_bias": float(malicious_bias)},
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("generated_logs", []) or []


def fetch_blocked_ips(backend_url=BACKEND_URL_DEFAULT):
    backend_url = str(backend_url).rstrip("/")
    response = requests.get(f"{backend_url}/blocked-ips", timeout=15)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def simulate_intrusion_workflow(backend_url=BACKEND_URL_DEFAULT, count=10, malicious_bias=0.5):
    generated_logs = fetch_generated_intrusion_logs(backend_url, count=count, malicious_bias=malicious_bias)
    results = []
    for log in generated_logs:
        backend_result = send_log_to_backend(backend_url, log)
        detection = backend_result.get("detection", {}) or {}
        predicted_label = detection.get("prediction", log.get("label", "unknown"))
        severity = normalize_severity(detection.get("severity", "LOW"))
        confidence = detection.get("confidence", None)
        try:
            confidence = float(confidence)
            if confidence <= 0.0 and predicted_label not in ("Blocked",):
                confidence = 0.75
        except Exception:
            confidence = 0.75
        source = log.get("src_ip") or log.get("source_ip") or log.get("source") or "simulator"
        details = (
            f"dst:{log.get('dst_ip', '')} "
            f"proto:{log.get('protocol', '')} "
            f"service:{log.get('service', '')} "
            f"flag:{log.get('flag', '')} "
            f"port:{log.get('port', '')} "
            f"pps:{log.get('packets_per_sec', '')} "
            f"bytes_sent:{log.get('bytes_sent', '')}"
        ).strip().replace(',', ';')
        append_log("Intrusion", source, severity, predicted_label, confidence, details)
        results.append({
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
            "source": source,
            "dst_ip": log.get("dst_ip", ""),
            "protocol": log.get("protocol", ""),
            "service": log.get("service", ""),
            "flag": log.get("flag", ""),
            "port": log.get("port", ""),
            "bytes_sent": log.get("bytes_sent", 0),
            "bytes_received": log.get("bytes_received", 0),
            "packets_per_sec": log.get("packets_per_sec", 0),
            "duration": log.get("duration", 0),
            "label": log.get("label", ""),
            "prediction": predicted_label,
            "severity": severity,
            "confidence": confidence,
            "blocked": bool(detection.get("blocked", False)) or predicted_label == "Blocked",
            "message": detection.get("message", ""),
            "details": details,
        })
    return results


# ─────────────────────────────────────────────
# Phishing
# ─────────────────────────────────────────────
def fetch_generated_phishing_logs(backend_url=BACKEND_URL_DEFAULT, count=10, phishing_ratio=0.5):
    backend_url = str(backend_url).rstrip("/")
    response = requests.get(
        f"{backend_url}/generate-phishing",
        params={"count": int(count), "phishing_ratio": float(phishing_ratio)},
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("generated_logs", []) or []


def simulate_phishing_workflow(backend_url=BACKEND_URL_DEFAULT, count=10, phishing_ratio=0.5):
    generated_logs = fetch_generated_phishing_logs(backend_url, count=count, phishing_ratio=phishing_ratio)
    results = []
    for log in generated_logs:
        backend_result = send_log_to_backend(backend_url, log)
        detection = backend_result.get("detection", {}) or {}
        predicted_label = detection.get("prediction", log.get("label", "unknown"))
        severity = normalize_severity(detection.get("severity", "LOW"))
        confidence = detection.get("confidence", None)
        try:
            confidence = float(confidence)
            if confidence <= 0.0:
                confidence = 0.70
        except Exception:
            confidence = 0.70
        source = log.get("sender_domain") or log.get("source") or "unknown-sender"
        recipient = log.get("recipient", "unknown@corp.com")
        details = (
            f"subject:{log.get('subject', '')[:40]} "
            f"url:{log.get('url', '')[:50]} "
            f"recipient:{recipient}"
        ).strip().replace(',', ';')
        append_log("Phishing", source, severity, predicted_label, confidence, details)
        results.append({
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
            "source": source,
            "recipient": recipient,
            "subject": log.get("subject", ""),
            "url": log.get("url", ""),
            "label": log.get("label", ""),
            "prediction": predicted_label,
            "severity": severity,
            "confidence": confidence,
            "details": details,
        })
    return results


# ─────────────────────────────────────────────
# Insider Threat
# ─────────────────────────────────────────────
def fetch_generated_insider_logs(backend_url=BACKEND_URL_DEFAULT, count=10, threat_ratio=0.4):
    backend_url = str(backend_url).rstrip("/")
    response = requests.get(
        f"{backend_url}/generate-insider",
        params={"count": int(count), "threat_ratio": float(threat_ratio)},
        timeout=15,
    )
    response.raise_for_status()
    return response.json().get("generated_logs", []) or []


def simulate_insider_workflow(backend_url=BACKEND_URL_DEFAULT, count=10, threat_ratio=0.4):
    generated_logs = fetch_generated_insider_logs(backend_url, count=count, threat_ratio=threat_ratio)
    results = []
    for log in generated_logs:
        backend_result = send_log_to_backend(backend_url, log)
        detection = backend_result.get("detection", {}) or {}
        predicted_label = detection.get("prediction", log.get("label", "unknown"))
        severity = normalize_severity(detection.get("severity", "LOW"))
        confidence = detection.get("confidence", None)
        try:
            confidence = float(confidence)
            if confidence <= 0.0:
                confidence = 0.70
        except Exception:
            confidence = 0.70
        username = log.get("username") or log.get("source") or "unknown-user"
        hour = log.get("login_hour", "?")
        fac = log.get("file_access_count", 0)
        act = log.get("activity_score", 0)
        dept = log.get("department", "")
        asset = log.get("accessed_asset_type", "")
        details = (
            f"user:{username} dept:{dept} "
            f"login:{hour}:00 files:{fac} "
            f"activity:{act} asset:{asset}"
        ).strip().replace(',', ';')
        append_log("Insider", username, severity, predicted_label, confidence, details)
        results.append({
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat()),
            "source": username,
            "department": dept,
            "login_hour": hour,
            "file_access_count": fac,
            "activity_score": act,
            "accessed_asset": asset,
            "label": log.get("label", ""),
            "prediction": predicted_label,
            "severity": severity,
            "confidence": confidence,
            "details": details,
        })
    return results
