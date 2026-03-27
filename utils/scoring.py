import pandas as pd
from datetime import datetime, timedelta

def normalize_severity(sev):
    sev = str(sev).strip().upper() if sev is not None else ""
    if sev in ["CRITICAL", "HIGH"]:
        return "HIGH"
    elif sev == "MEDIUM":
        return "MEDIUM"
    elif sev == "LOW":
        return "LOW"
    return "LOW"

def compute_asset_risk_scores(logs_df, top_n=10):
    if logs_df is None or logs_df.empty:
        return pd.DataFrame()

    df = logs_df.copy()
    df['confidence'] = pd.to_numeric(df.get('confidence', 0), errors='coerce').fillna(0.0)
    df['severity_norm'] = df.get('severity', '').apply(normalize_severity)
    severity_map = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
    df['sev_w'] = df['severity_norm'].map(severity_map).fillna(0).astype(int)

    agg = df.groupby('source').agg(
        Attacks=('attack_type', 'count'),
        Avg_Confidence=('confidence', 'mean'),
        Max_Sev_Weight=('sev_w', 'max'),
        Highest_Severity=('severity_norm', lambda x: ", ".join(pd.Series(x.dropna().astype(str).unique())[:1]) if not x.dropna().empty else ""),
        Last_Seen=('timestamp', 'max'),
        Top_Attacks=('attack_type', lambda x: ", ".join(pd.Series(x.dropna().astype(str).unique()[:3])))
    ).reset_index().rename(columns={'source': 'Asset'})

    max_attacks = int(agg['Attacks'].max()) or 1

    agg['freq_score'] = agg['Attacks'] / max_attacks * 40.0
    agg['conf_score'] = agg['Avg_Confidence'].clip(0, 1.0) * 40.0
    agg['sev_score'] = (agg['Max_Sev_Weight'] / 3.0) * 20.0

    agg['Risk Score'] = (agg['freq_score'] + agg['conf_score'] + agg['sev_score']).round().astype(int).clip(0, 100)

    try:
        agg['Last_Seen'] = pd.to_datetime(agg['Last_Seen'], errors='coerce').dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    except Exception:
        agg['Last_Seen'] = agg['Last_Seen'].astype(str).fillna("")

    agg['Avg_Confidence'] = agg['Avg_Confidence'].round(2)
    result = agg[['Asset', 'Risk Score', 'Attacks', 'Highest_Severity', 'Avg_Confidence', 'Last_Seen', 'Top_Attacks']]
    result = result.sort_values('Risk Score', ascending=False).head(top_n).reset_index(drop=True)
    return result

def compute_security_posture(logs_df, window_hours=24):
    try:
        if logs_df is None or logs_df.empty:
            return {'score': 100, 'category': 'Secure', 'total_attacks': 0, 'avg_sev': 0.0, 'avg_conf': 0.0}

        df = logs_df.copy()
        df['timestamp'] = pd.to_datetime(df.get('timestamp'), errors='coerce')
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        recent = df[df['timestamp'] >= cutoff].copy()
        if recent.empty:
            return {'score': 100, 'category': 'Secure', 'total_attacks': 0, 'avg_sev': 0.0, 'avg_conf': 0.0}

        total_attacks = len(recent)
        severity_map = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        recent['severity_norm'] = recent.get('severity', '').apply(normalize_severity)
        recent['sev_w'] = recent['severity_norm'].map(severity_map).fillna(1).astype(float)
        
        avg_sev = float(recent['sev_w'].mean()) if not recent['sev_w'].empty else 1.0

        recent['confidence'] = pd.to_numeric(recent.get('confidence', 0), errors='coerce').fillna(0.0)
        avg_conf = float(recent['confidence'].mean()) if not recent['confidence'].empty else 0.0

        # Count actual threats vs benign traffic
        high_count = len(recent[recent['severity_norm'] == 'HIGH'])
        med_count = len(recent[recent['severity_norm'] == 'MEDIUM'])
        threat_count = high_count + med_count
        threat_ratio = threat_count / max(total_attacks, 1)

        # 1. Volume Penalty (Max 25 points): Capped at 50 true threats per 24h
        vol_penalty = min(threat_count, 50.0) / 50.0 * 25.0

        # 2. Density Penalty (Max 35 points): Ratio of bad traffic to good traffic
        density_penalty = threat_ratio * 35.0

        # 3. Severity Penalty (Max 40 points): Based on avg severity (1.0 to 3.0)
        # If all traffic is LOW (benign), avg_sev is 1.0, and penalty is 0.
        sev_penalty = max(0.0, (avg_sev - 1.0) / 2.0) * 40.0

        penalty = vol_penalty + density_penalty + sev_penalty
        score = int(round(100.0 - penalty))
        score = max(0, min(100, score))

        if score >= 80:
            category = "Strong"
        elif score >= 60:
            category = "Moderate"
        elif score >= 40:
            category = "Weak"
        else:
            category = "Critical"

        return {'score': score, 'category': category, 'total_attacks': total_attacks, 'avg_sev': round(avg_sev, 2), 'avg_conf': round(avg_conf, 2)}
    except Exception:
        return {'score': 50, 'category': 'Unknown', 'total_attacks': 0, 'avg_sev': 0.0, 'avg_conf': 0.0}
