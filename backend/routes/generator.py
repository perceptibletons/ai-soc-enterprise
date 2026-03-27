from fastapi import APIRouter
from generator.ransomware_generator import generate_batch
from generator.intrusion_generator import generate_intrusion_logs
from generator.phishing_generator import generate_phishing_batch
from generator.insider_generator import generate_insider_batch

router = APIRouter()

@router.get("/generate-ransomware")
def generate_ransomware(count: int = 10, ransomware_ratio: float = 0.5):
    logs = generate_batch(count, ransomware_ratio=ransomware_ratio)
    return {"generated_logs": logs}

@router.get("/generate-intrusion")
def generate_intrusion(count: int = 10, malicious_bias: float = 0.5):
    logs = generate_intrusion_logs(count=count, malicious_bias=malicious_bias)
    return {"generated_logs": logs}

@router.get("/generate-phishing")
def generate_phishing(count: int = 10, phishing_ratio: float = 0.5):
    logs = generate_phishing_batch(n=count, phishing_ratio=phishing_ratio)
    return {"generated_logs": logs}

@router.get("/generate-insider")
def generate_insider(count: int = 10, threat_ratio: float = 0.4):
    logs = generate_insider_batch(n=count, threat_ratio=threat_ratio)
    return {"generated_logs": logs}