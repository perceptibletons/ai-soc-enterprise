import os
import pandas as pd
from datetime import datetime

try:
    from utils.prediction_functions import (
        predict_phishing, predict_ransomware,
        predict_intrusion, predict_insider, append_log, read_logs as util_read_logs
    )
except Exception:
    def predict_phishing(email_text="", url="", sender_domain=""):
        text = (email_text or url or sender_domain or "").lower()
        score = 0.8 if ("click" in text or "verify" in text or "password" in text) else 0.2
        label = "Phishing" if score > 0.6 else "Benign"
        severity = "HIGH" if score > 0.6 else ("MEDIUM" if score > 0.35 else "LOW")
        return {"label": label, "severity": severity, "confidence": score}

    def predict_ransomware(file_name="", file_size=0, process_activity=0):
        score = 0.85 if file_size > 100_000_000 and process_activity > 20 else 0.2
        label = "Ransomware" if score > 0.6 else "Benign"
        severity = "HIGH" if score > 0.6 else ("MEDIUM" if score > 0.35 else "LOW")
        return {"label": label, "severity": severity, "confidence": score}

    def predict_intrusion(src_ip=None, dst_ip=None, protocol=None, packet_size=0, packets_per_sec=0):
        score = 0.9 if packets_per_sec > 1000 or packet_size > 100_000 else 0.2
        label = "Intrusion" if score > 0.6 else "Normal"
        severity = "HIGH" if score > 0.6 else ("MEDIUM" if score > 0.35 else "LOW")
        return {"label": label, "severity": severity, "confidence": score}

    def predict_insider(login_time=None, file_access_count=0, activity_score=0):
        h = login_time.hour if hasattr(login_time, "hour") else (int(login_time) if login_time is not None else 12)
        score = 0.9 if (h < 2 or h > 22) and file_access_count > 50 else 0.25
        label = "Insider Threat" if score > 0.6 else "Normal"
        severity = "HIGH" if score > 0.6 else ("MEDIUM" if score > 0.35 else "LOW")
        return {"label": label, "severity": severity, "confidence": score}

    def append_log(*args, **kwargs):
        logs_dir = "logs"
        os.makedirs(logs_dir, exist_ok=True)
        path = os.path.join(logs_dir, "attack_logs.csv")
        header = ["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"]
        row = [datetime.utcnow().isoformat()] + list(args[:6])
        if len(row) < len(header):
            row += [""] * (len(header) - len(row))
        write_header = not os.path.exists(path)
        import csv
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(header)
            w.writerow(row)
        return True

    def util_read_logs(n=2000):
        path = os.path.join("logs", "attack_logs.csv")
        if not os.path.exists(path):
            return pd.DataFrame(columns=["timestamp","attack_type","source","severity","label","confidence","details"])
        df = pd.read_csv(path, parse_dates=["timestamp"])
        return df.sort_values("timestamp", ascending=False).head(n)

def read_logs(n=2000):
    try:
        return util_read_logs(n)
    except Exception:
        return pd.DataFrame(columns=["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"])
