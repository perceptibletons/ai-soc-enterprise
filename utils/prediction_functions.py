# utils/prediction_functions.py
"""
Prediction and logging utilities for AI-SOC platform.

This module:
- Loads models from ../models (phishing_vectorizer.pkl, phishing_detector.pkl,
  malware_detector.pkl, network_scaler.pkl, network_isoforest.pkl, network_autoencoder.pkl, optional insider_model.pkl)
- Exposes:
    predict_phishing(email_text, url, sender_domain)
    predict_ransomware(file_name, file_size, process_activity)
    predict_intrusion(src_ip, dst_ip, protocol, packet_size, packets_per_sec, port, service, flag)
    predict_insider(login_time, file_access_count, activity_score)
    append_log(attack_type, source, severity, label, confidence, details="")
    read_logs(n=2000)
- Falls back to heuristics if specific models are missing.
"""
import os
import pickle
import csv
from datetime import datetime
from typing import Optional, Dict, Any
import numpy as np
import pandas as pd

# -------------------------
# Configuration / thresholds
# -------------------------
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(LOGS_DIR, "attack_logs.csv")

AUTOENCODER_ERROR_THRESHOLD = 0.1   # adjust after observing reconstruction errors
INTRUSION_COMBINE_STRICT = True    # if True, treat iso OR autoencoder anomaly as intrusion

# -------------------------
# Helper: try loading pickle
# -------------------------
def _try_load(path):
    try:
        with open(path, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None

# -------------------------
# Load models (if present)
# -------------------------
phishing_vectorizer = _try_load(os.path.join(MODELS_DIR, "phishing_vectorizer.pkl"))
phishing_model = _try_load(os.path.join(MODELS_DIR, "phishing_model.pkl")) or _try_load(os.path.join(MODELS_DIR, "phishing_detector.pkl"))

malware_model = _try_load(os.path.join(MODELS_DIR, "malware_detector.pkl")) or _try_load(os.path.join(MODELS_DIR, "ransomware_model.pkl"))

network_scaler = _try_load(os.path.join(MODELS_DIR, "network_scaler.pkl"))
network_isoforest = _try_load(os.path.join(MODELS_DIR, "network_isoforest.pkl"))
network_autoencoder = _try_load(os.path.join(MODELS_DIR, "network_autoencoder.pkl"))

insider_model = _try_load(os.path.join(MODELS_DIR, "insider_model.pkl"))

# -------------------------
# Utility functions
# -------------------------
def _safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def _parse_bool_like(v):
    """Accept 1/0, 'yes'/'no', 'true'/'false' etc."""
    if v is None:
        return 0
    if isinstance(v, (int, float)):
        return 1 if v else 0
    s = str(v).strip().lower()
    if s in ("1","true","yes","y","t"):
        return 1
    return 0

# -------------------------
# Phishing prediction
# -------------------------
def predict_phishing(email_text: str = "", url: str = "", sender_domain: str = "") -> Dict[str, Any]:
    """
    Returns: {label, severity, confidence}
    Uses vectorizer + model if present; otherwise heuristic.
    """
    text = " ".join([p for p in [email_text, url, sender_domain] if p]).strip()
    # Use real model if available
    if phishing_vectorizer is not None and phishing_model is not None:
        try:
            X = phishing_vectorizer.transform([text])
            # prefer predict_proba if available
            if hasattr(phishing_model, "predict_proba"):
                probs = phishing_model.predict_proba(X)[0]
                # assume positive class at index 1
                conf = float(max(probs))
                pred = phishing_model.predict(X)[0]
            else:
                pred = phishing_model.predict(X)[0]
                conf = 0.9
            # Map model prediction -> label
            # Commonly 1 == phishing; adapt if necessary.
            label = "Phishing" if int(pred) in (1, True) else "Benign"
            severity = "HIGH" if label == "Phishing" else "LOW"
            return {"label": label, "severity": severity, "confidence": float(conf)}
        except Exception:
            pass

    # Heuristic fallback
    kws = ["click", "verify", "account", "password", "urgent", "bank", "login", "reset", "suspend"]
    score = sum(1 for k in kws if k in text.lower())
    if score >= 2:
        return {"label": "Phishing", "severity": "HIGH", "confidence": 0.85}
    if score == 1:
        return {"label": "Suspicious", "severity": "MEDIUM", "confidence": 0.6}
    return {"label": "Benign", "severity": "LOW", "confidence": 0.25}

# -------------------------
# Ransomware / Malware prediction
# -------------------------
def predict_ransomware(file_name: str = "", file_size: Optional[float] = None, process_activity: Optional[int] = None,
                       num_sections: Optional[int] = None, num_imports: Optional[int] = None, num_exports: Optional[int] = None,
                       contains_packer_sig: Optional[int] = None, entry_point_entropy: Optional[float] = None,
                       avg_section_entropy: Optional[float] = None, has_digital_signature: Optional[int] = None,
                       has_tls_callback: Optional[int] = None, has_anti_debug: Optional[int] = None,
                       has_anti_vm: Optional[int] = None) -> Dict[str, Any]:
    """
    Predict ransomware/malware using the malware_model if present.
    Model expects 11 features (as inspected):
      filesize, num_sections, num_imports, num_exports, contains_packer_sig,
      entry_point_entropy, avg_section_entropy, has_digital_signature,
      has_tls_callback, has_anti_debug, has_anti_vm
    """
    # Fill defaults and coerce
    fs = _safe_float(file_size, 0)
    ns = int(num_sections or 0)
    ni = int(num_imports or 0)
    ne = int(num_exports or 0)
    packer = _parse_bool_like(contains_packer_sig)
    epe = _safe_float(entry_point_entropy, 0.0)
    ase = _safe_float(avg_section_entropy, 0.0)
    sig = _parse_bool_like(has_digital_signature)
    tls = _parse_bool_like(has_tls_callback)
    adb = _parse_bool_like(has_anti_debug)
    avm = _parse_bool_like(has_anti_vm)

    features = np.array([[fs, ns, ni, ne, packer, epe, ase, sig, tls, adb, avm]])

    if malware_model is not None:
        try:
            # if model expects scaling or other preprocessing, adjust here
            if hasattr(malware_model, "predict_proba"):
                probs = malware_model.predict_proba(features)[0]
                conf = float(max(probs))
                pred = malware_model.predict(features)[0]
            else:
                pred = malware_model.predict(features)[0]
                conf = 0.9
            label = "Malicious" if int(pred) in (1, True) else "Benign"
            severity = "HIGH" if label == "Malicious" else "LOW"
            return {"label": label, "severity": severity, "confidence": float(conf)}
        except Exception:
            pass

    # Heuristic fallback using file size and process activity
    pa = int(process_activity or 0)
    if fs > 100_000_000 and pa > 20:
        return {"label": "Ransomware", "severity": "HIGH", "confidence": 0.86}
    if pa > 10:
        return {"label": "Suspicious", "severity": "MEDIUM", "confidence": 0.6}
    return {"label": "Benign", "severity": "LOW", "confidence": 0.2}


# Insider threat (optional)
# -------------------------
def predict_insider(login_time, file_access_count: Optional[int] = None, activity_score: Optional[int] = None) -> Dict[str, Any]:
    """
    If an insider model is present it will be used (expects [hour, file_access_count, activity_score]).
    Otherwise use a heuristic.
    login_time: can be a datetime.time object or int hour 0-23
    """
    # normalize
    if hasattr(login_time, "hour"):
        hour = int(login_time.hour)
    else:
        try:
            hour = int(login_time)
        except Exception:
            hour = 12

    fac = int(file_access_count or 0)
    act = int(activity_score or 0)

    if insider_model is not None:
        try:
            feat = np.array([[hour, fac, act]])
            pred = insider_model.predict(feat)
            label = "Insider Threat" if int(pred[0]) in (1, True) else "Normal"
            sev = "HIGH" if label == "Insider Threat" else "LOW"
            return {"label": label, "severity": sev, "confidence": 0.9}
        except Exception:
            pass

    # Heuristic fallback
    if (hour < 2 or hour > 22) and fac > 50:
        return {"label": "Insider Threat", "severity": "HIGH", "confidence": 0.88}
    if fac > 20 or act > 80:
        return {"label": "Suspicious", "severity": "MEDIUM", "confidence": 0.62}
    return {"label": "Normal", "severity": "LOW", "confidence": 0.2}

# -------------------------
# Logging utilities
# -------------------------
def append_log(attack_type: str, source: str, severity: str, label: str, confidence: float, details: str = "") -> bool:
    """
    Append an incident row to logs/attack_logs.csv
    Columns: timestamp, attack_type, source, severity, label, confidence, details
    """
    os.makedirs(LOGS_DIR, exist_ok=True)
    write_header = not os.path.exists(LOG_FILE)
    row = [datetime.utcnow().isoformat(), attack_type, source or "", severity, label, float(confidence), details or ""]
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if write_header:
                w.writerow(["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"])
            w.writerow(row)
        return True
    except Exception as e:
        # If logging fails, still return False and allow UI to continue
        print("append_log error:", e)
        return False

def read_logs(n: int = 2000) -> pd.DataFrame:
    """Read the latest n logs (most recent first). Returns a DataFrame with parsed timestamps."""
    if not os.path.exists(LOG_FILE):
        # return empty DataFrame with columns expected by UI
        cols = ["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"]
        return pd.DataFrame(columns=cols)
    try:
        df = pd.read_csv(LOG_FILE)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df.sort_values("timestamp", ascending=False).head(n)
    except Exception:
        # if read fails, return empty df
        cols = ["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"]
        return pd.DataFrame(columns=cols)

# -------------------------
# End of file
# -------------------------