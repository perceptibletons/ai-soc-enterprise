from fastapi import APIRouter
from detection.ransomware_detector import detect_ransomware
from detection.intrusion_detector import process_intrusion_log, get_blocked_ips
from detection.phishing_detector import detect_phishing
from detection.insider_detector import detect_insider

router = APIRouter()


@router.post("/ingest-log")
def ingest_log(log: dict):
    attack_type = str(log.get("type") or log.get("attack_type") or "").lower()

    if attack_type == "intrusion":
        result = process_intrusion_log(log)
        return {"message": "Intrusion processed", "log": log, "detection": result}

    if attack_type == "phishing":
        result = detect_phishing(log)
        return {"message": "Phishing processed", "log": log, "detection": result}

    if attack_type == "insider":
        result = detect_insider(log)
        return {"message": "Insider processed", "log": log, "detection": result}

    # Default: ransomware
    result = detect_ransomware(log)
    return {"message": "Log processed", "log": log, "detection": result}


@router.get("/blocked-ips")
def blocked_ips():
    return get_blocked_ips()