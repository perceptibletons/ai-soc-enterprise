# utils/analytics.py
import os
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Path to logs file (relative to project root)
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "attack_logs.csv")

def read_logs(n=5000):
    """
    Read logs from the CSV and return a DataFrame sorted by timestamp descending.
    If file missing or empty, returns empty DataFrame with expected columns.
    Optimized to only parse dates for the most recent chunk of rows.
    """
    cols = ["timestamp","attack_type","source","severity","label","confidence","details","true_label"]
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame(columns=cols)
    try:
        df = pd.read_csv(LOG_FILE, keep_default_na=False)
    except pd.errors.EmptyDataError:
        return pd.DataFrame(columns=cols)
    
    for c in cols:
        if c not in df.columns:
            df[c] = ""
            
    # CRITICAL OPTIMIZATION: Take tail first assuming chronological append.
    # This avoids parsing dates for 100,000 rows if we only need 50.
    df = df.tail(max(n, 10000)).copy()
    
    try:
        df["confidence"] = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.0)
    except Exception:
        df["confidence"] = 0.0
        
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        
    return df.sort_values("timestamp", ascending=False).head(n)

def compute_threat_score(df):
    """
    Compute a threat score (0..100) using severity weights and confidence.
    """
    if df is None or df.empty:
        return 10
    weights = {"HIGH":3, "MEDIUM":2, "LOW":1}
    df2 = df.copy()
    df2["sev_w"] = df2["severity"].map(weights).fillna(1)
    df2["conf"] = pd.to_numeric(df2["confidence"], errors="coerce").fillna(0.0)
    raw = (df2["sev_w"] * df2["conf"]).mean()
    score = float(np.clip(raw / 3 * 100, 0, 100))
    return int(score)

def daily_attack_trend(df, period='h'):
    """
    Return aggregated counts by time bucket.
    period: pandas offset alias, e.g., 'h' for hourly, 'd' for daily
    """
    if df is None or df.empty:
        return pd.DataFrame({"time_bucket": [], "count": []})
    tmp = df.copy()
    tmp["time_bucket"] = tmp["timestamp"].dt.floor(period)
    out = tmp.groupby("time_bucket").size().reset_index(name="count")
    return out

def compute_metrics_from_labels(df, label_col="true_label", pred_col="label"):
    """
    Compute accuracy/precision/recall/f1/confusion_matrix using labeled incidents.
    Expects df to have a column 'true_label' (1 or 0) or strings 'True Positive'/'False Positive'.
    Returns None if not enough labels available.
    """
    if df is None or df.empty:
        return None
    if label_col not in df.columns:
        return None
    df2 = df.copy()
    # Normalize true_label to binary 1/0
    def to_binary_true(v):
        if pd.isna(v) or v == "" or str(v).strip().lower() in ("", "none", "nan"):
            return None
        s = str(v).strip().lower()
        if s in ("1", "true", "true positive", "tp", "yes"):
            return 1
        if s in ("0", "false", "false positive", "fp", "no"):
            return 0
        # fallback numeric
        try:
            return int(float(s))
        except Exception:
            return None

    df2["_y_true"] = df2[label_col].apply(to_binary_true)
    # drop unlabeled
    df2 = df2.dropna(subset=["_y_true"])
    if df2.empty:
        return None

    # Convert predictions to binary: treat common benign labels as 0; others 1
    def pred_to_binary(p):
        s = str(p).strip().lower()
        if s in ("benign", "normal", "false", "no", "0", "", "none"):
            return 0
        # else treat as malicious/predicted as positive
        return 1

    df2["_y_pred"] = df2[pred_col].apply(pred_to_binary).astype(int)
    y_true = df2["_y_true"].astype(int).values
    y_pred = df2["_y_pred"].astype(int).values

    metrics = {}
    metrics["accuracy"] = float(accuracy_score(y_true, y_pred))
    metrics["precision"] = float(precision_score(y_true, y_pred, zero_division=0))
    metrics["recall"] = float(recall_score(y_true, y_pred, zero_division=0))
    metrics["f1"] = float(f1_score(y_true, y_pred, zero_division=0))
    cm = confusion_matrix(y_true, y_pred)
    metrics["confusion_matrix"] = cm.tolist()
    metrics["labeled_count"] = int(len(df2))

    return metrics