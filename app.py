import streamlit as st
import pandas as pd
import numpy as np
import os
import requests
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

# ── Imports ──
from config.settings import BACKEND_URL_DEFAULT
from utils.scoring import normalize_severity, compute_asset_risk_scores, compute_security_posture
from utils.predictions import predict_phishing, predict_insider, append_log, read_logs
from utils.simulators import (
    simulate_ransomware_workflow, simulate_intrusion_workflow,
    simulate_phishing_workflow, simulate_insider_workflow,
    fetch_blocked_ips
)
from utils.analytics import compute_threat_score, daily_attack_trend, read_logs as analytics_read_logs, compute_metrics_from_labels
from ui.components import (
    severity_badge_html, render_ai_investigation, render_mitre_mapping,
    render_attack_map, section_header, metric_card
)

# ── Page config ──
st.set_page_config(
    page_title="AI-SOC | Enterprise Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
st.markdown("<meta name='viewport' content='width=device-width, initial-scale=1'>", unsafe_allow_html=True)

# ── Load CSS ──
css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
try:
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
except Exception:
    pass

# ── Plotly theme helper ──
def styled_chart_layout(fig, height=340):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(6,6,14,0.8)",
        font=dict(family="Inter, sans-serif", color="#a09ac0", size=11),
        title_font=dict(family="Inter, sans-serif", color="#f1f0ff", size=13),
        margin=dict(l=16, r=16, t=36, b=16),
        legend=dict(bgcolor="rgba(10,10,20,0.8)", bordercolor="rgba(139,92,246,0.2)", borderwidth=1),
        height=height,
    )
    fig.update_xaxes(gridcolor="rgba(139,92,246,0.08)", linecolor="rgba(139,92,246,0.15)", tickcolor="rgba(139,92,246,0.15)")
    fig.update_yaxes(gridcolor="rgba(139,92,246,0.08)", linecolor="rgba(139,92,246,0.15)", tickcolor="rgba(139,92,246,0.15)")
    return fig

# ── Sidebar ──
with st.sidebar:
    st.markdown("""
    <div style="padding:20px 0 16px 0;">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">
        <div style="width:42px;height:42px;background:linear-gradient(135deg,#7c3aed,#06b6d4);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;box-shadow:0 0 15px rgba(124,58,237,0.4);">🛡️</div>
        <div>
          <div style="font-size:1.5rem;font-weight:900;background:linear-gradient(90deg, #ffffff, #c4b5fd);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-0.02em;text-shadow:0px 0px 20px rgba(167,139,250,0.4);">AI-SOC</div>
          <div style="font-size:0.75rem;font-weight:800;letter-spacing:0.15em;text-transform:uppercase;color:#22d3ee;margin-top:2px;text-shadow:0px 0px 10px rgba(34,211,238,0.4);">Enterprise Platform</div>
        </div>
      </div>
      <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.4),transparent);margin:12px 0;"></div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='font-size:0.65rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6b6490;margin-bottom:8px;'>Navigation</div>", unsafe_allow_html=True)
    page = st.radio(
        "Navigation",
        ["Dashboard Overview", "Phishing Detection", "Ransomware Detection",
         "Intrusion Detection", "Insider Threat Detection", "Incident Logs"],
        label_visibility="collapsed"
    )

    st.markdown("""
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:20px 0 14px 0;"></div>
    <div style="font-size:0.65rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#6b6490;margin-bottom:10px;">System Status</div>
    """, unsafe_allow_html=True)

    for label in ["IDS Engine Active", "ML Model Running", "Sensors Connected"]:
        st.markdown(f"""
        <div style="display:flex;align-items:center;gap:8px;padding:6px 0;">
          <div style="width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px rgba(34,197,94,0.5);animation:blink 2s ease-in-out infinite;flex-shrink:0;"></div>
          <span style="font-size:0.79rem;font-weight:500;color:#a09ac0;">{label}</span>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:16px 0 12px 0;"></div>
    <div style="font-size:0.65rem;color:#4a4470;text-transform:uppercase;letter-spacing:0.08em;">AI-SOC MVP · v2.0</div>
    """, unsafe_allow_html=True)

# ── Compute metrics ──
logs_df = read_logs(2000)
if not logs_df.empty:
    logs_df = logs_df.copy()
    logs_df["severity_norm"] = logs_df["severity"].apply(normalize_severity)
else:
    logs_df = logs_df.copy()
    logs_df["severity_norm"] = pd.Series([], dtype=str)

total_threats = len(logs_df)
high_cnt  = int(logs_df[logs_df['severity_norm'] == "HIGH"].shape[0])  if not logs_df.empty else 0
med_cnt   = int(logs_df[logs_df['severity_norm'] == "MEDIUM"].shape[0]) if not logs_df.empty else 0
safe_cnt  = max(0, 1000 - total_threats)

# ── Page header + KPI bar ──
st.markdown("""
<div style="display:flex;align-items:baseline;gap:14px;margin:0 0 4px 0;">
  <h1 style="font-size:1.7rem;font-weight:900;letter-spacing:-0.03em;margin:0;color:#f1f0ff;">Threat Monitoring</h1>
  <span style="font-size:0.72rem;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:#7c3aed;background:rgba(124,58,237,0.12);border:1px solid rgba(124,58,237,0.25);padding:3px 10px;border-radius:99px;">LIVE</span>
</div>
<div style="font-size:0.8rem;color:#6b6490;margin-bottom:20px;">Real-time security intelligence dashboard</div>
""", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c1.markdown(metric_card("Total Threats Detected", total_threats, "card card-total"), unsafe_allow_html=True)
c2.markdown(metric_card("High Severity", high_cnt, "card card-high"), unsafe_allow_html=True)
c3.markdown(metric_card("Medium Severity", med_cnt, "card card-med"), unsafe_allow_html=True)
c4.markdown(metric_card("Safe Traffic", safe_cnt, "card card-safe"), unsafe_allow_html=True)

st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:24px 0;'></div>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# DASHBOARD OVERVIEW
# ═══════════════════════════════════════════════════════════════
if page == "Dashboard Overview":

    left, right = st.columns([1.4, 2.6])
    logs_df_full = analytics_read_logs(5000)

    with left:
        section_header("Threat Level", "⚠️")
        gauge_val = compute_threat_score(logs_df_full)
        g_theme = "danger" if gauge_val >= 65 else ("warning" if gauge_val >= 35 else "safe")
        g_col = "#ef4444" if g_theme == "danger" else ("#f97316" if g_theme == "warning" else "#22c55e")
        st.markdown(f"""
        <div class="cyber-gauge-wrap">
          <div class="cyber-gauge-ring {g_theme}"></div>
          <div class="cyber-gauge-center">
            <div class="cyber-gauge-value" style="color:{g_col};text-shadow:0 0 15px {g_col}66;">{gauge_val}</div>
            <div class="cyber-gauge-label">Threat Score</div>
          </div>
        </div>
        """.replace("{{g_theme}}", g_theme).replace("{{g_col}}", g_col).replace("{{gauge_val}}", str(gauge_val)), unsafe_allow_html=True)
        
        st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)

        section_header("Security Posture", "🛡️")
        posture = compute_security_posture(logs_df_full, window_hours=24)
        posture_val = posture.get('score', 100)
        posture_cat = posture.get('category', 'Unknown')
        cat_color = {"Strong": "#22c55e", "Moderate": "#f97316", "Weak": "#ef4444", "Critical": "#dc2626"}.get(posture_cat, "#a09ac0")
        
        p_theme = "danger" if posture_val < 40 else ("warning" if posture_val < 70 else "safe")
        st.markdown(f"""
        <div class="cyber-gauge-wrap">
          <div class="cyber-gauge-ring {p_theme}"></div>
          <div class="cyber-gauge-center">
            <div class="cyber-gauge-value" style="color:{cat_color};text-shadow:0 0 15px {cat_color}66;">{posture_val}</div>
            <div class="cyber-gauge-label">Posture Index</div>
          </div>
        </div>
        """.replace("{{p_theme}}", p_theme).replace("{{cat_color}}", cat_color).replace("{{posture_val}}", str(posture_val)), unsafe_allow_html=True)
        
        st.markdown(f"""
        <div style="text-align:center;margin-top:12px;padding:10px;background:rgba(255,255,255,0.03);border:1px solid rgba(139,92,246,0.15);border-radius:10px;">
          <span style="font-size:0.7rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#6b6490;">Status</span>
          <span style="font-weight:900;font-size:0.95rem;color:{cat_color};margin:0 8px;">●  {posture_cat}</span>
          <br>
          <span style="font-size:0.7rem;color:#8ecfd8;">Last 24h · {posture.get('total_attacks',0)} events</span>
        </div>""", unsafe_allow_html=True)

    with right:
        section_header("Live SOC Alerts", "🔴")
        recent = analytics_read_logs(20)
        if recent.empty:
            st.info("No alerts yet — use detection pages to create incidents.")
        else:
            html = "<div>"
            for i, row in recent.head(20).iterrows():
                try:
                    ts = pd.to_datetime(row.get("timestamp")).strftime("%H:%M:%S")
                    ts_full = pd.to_datetime(row.get("timestamp")).strftime("%Y-%m-%d")
                except Exception:
                    ts = ""; ts_full = ""
                attack  = row.get("attack_type", "Unknown")
                src     = row.get("source", "unknown")
                sev     = normalize_severity(row.get("severity", ""))
                lab     = row.get("label", "")
                conf    = float(row.get("confidence") or 0.0)
                details = row.get("details", "")
                badge   = severity_badge_html(sev)
                html += f"""
                <div class="alert-item" style="animation-delay:{i*0.04}s">
                  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                      <span style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;color:#7c8ba0;">{ts_full}</span>
                      <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:#7c6fa0;font-weight:600;">{ts}</span>
                      <span style="font-size:0.78rem;font-weight:800;text-transform:uppercase;letter-spacing:0.06em;color:#a78bfa;">{attack}</span>
                    </div>
                    <div style="display:flex;align-items:center;gap:6px;">{badge}</div>
                  </div>
                  <div style="font-size:0.73rem;color:#6b6490;">
                    <span style="color:#a09ac0;">src</span> <span style="font-family:'JetBrains Mono',monospace;color:#06b6d4;">{src}</span>
                    &nbsp;·&nbsp; <span style="color:#a09ac0;">{lab}</span>
                    &nbsp;·&nbsp; <span style="color:#6b6490;">conf {conf:.2f}</span>
                  </div>
                  <div style="font-size:0.7rem;color:#8ecfd8;margin-top:2px;font-family:'JetBrains Mono',monospace;">{details}</div>
                </div>"""
            html += "</div>"
            st.markdown(html, unsafe_allow_html=True)

    st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:24px 0;'></div>", unsafe_allow_html=True)

    # Charts row
    a, b = st.columns([1.6, 1.4])
    with a:
        section_header("Threat Distribution", "📊")
        if logs_df.empty:
            df_dist = pd.DataFrame({"attack": ["Phishing","Intrusion","Ransomware","Insider"], "count": [0,0,0,0]})
            fig = px.pie(df_dist, names="attack", values="count", hole=0.7)
        else:
            df_dist = logs_df.groupby("attack_type").size().reset_index(name="count")
            fig = px.pie(df_dist, names="attack_type", values="count", hole=0.7,
                         color_discrete_sequence=["#06b6d4", "#8b5cf6", "#ec4899", "#f97316", "#22c55e", "#eab308"])
        
        fig.update_traces(
            textinfo="percent", 
            textfont=dict(color="#f1f0ff", size=12, family="Inter"),
            hoverinfo="label+percent+value",
            marker=dict(line=dict(color='#0d0d18', width=3)),
            pull=[0.02] * len(df_dist),
            rotation=45
        )
        fig.add_annotation(text="ATTACKS", x=0.5, y=0.5, font=dict(size=12, color="#6b6490", family="Inter", weight="bold"), showarrow=False)
        fig = styled_chart_layout(fig, 320)
        st.plotly_chart(fig, use_container_width=True)

    with b:
        section_header("Attack Trend (24h)", "📈")
        trend_df = daily_attack_trend(logs_df_full, period='H')
        if trend_df.empty:
            hours = [datetime.utcnow() - timedelta(hours=i) for i in range(23, -1, -1)]
            trend_df = pd.DataFrame({"time_bucket": hours, "count": [0]*24})
        
        fig2 = go.Figure()
        # Glow effect
        fig2.add_trace(go.Scatter(
            x=trend_df['time_bucket'], y=trend_df['count'],
            mode='lines', line=dict(color='rgba(124,58,237,0.3)', width=8, shape='spline'), showlegend=False, hoverinfo='skip'
        ))
        # Main line and fill
        fig2.add_trace(go.Scatter(
            x=trend_df['time_bucket'], y=trend_df['count'],
            mode='lines+markers', line=dict(color='#a78bfa', width=3, shape='spline'),
            marker=dict(size=6, color='#0d0d18', line=dict(width=2, color='#a78bfa')),
            fill='tozeroy', fillcolor='rgba(124,58,237,0.15)', name='Volume'
        ))
        fig2 = styled_chart_layout(fig2, 320)
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:24px 0;'></div>", unsafe_allow_html=True)

    # Global Attack Map
    render_attack_map(logs_df_full.head(400))

    st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:24px 0;'></div>", unsafe_allow_html=True)

    # Critical Incident Timeline
    section_header("Critical Incident Timeline", "🚨")
    if logs_df_full.empty:
        st.info("No timeline events yet. Trigger detections to populate the timeline.")
    else:
        high_logs = logs_df_full[logs_df_full['severity'].str.upper() == "HIGH"]
        if high_logs.empty:
            st.success("No critical incidents detected recently. System is secure.")
        else:
            timeline_html = "<div class='timeline'>"
            recent_tl = high_logs.sort_values("timestamp", ascending=False).head(20)
        for idx_t, (_, r) in enumerate(recent_tl.iterrows()):
            ts = pd.to_datetime(r.get("timestamp"))
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if not pd.isna(ts) else ""
            attack  = r.get("attack_type", "")
            src     = r.get("source", "unknown")
            sev     = normalize_severity(r.get("severity", ""))
            details = r.get("details", "")
            badge   = severity_badge_html(sev)
            timeline_html += f"""<div class='timeline-item' style='animation-delay:{idx_t*0.05}s'>
              <span class='ts'>{ts_str}</span><span class='type'>{attack}</span>{badge}
              <div class='details'>{src} — {details}</div>
            </div>"""
        timeline_html += "</div>"
        st.markdown(timeline_html, unsafe_allow_html=True)

    st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:24px 0;'></div>", unsafe_allow_html=True)

    # Bottom row
    left_col, right_col = st.columns([1.3, 2])
    with left_col:
        section_header("Asset Risk Scoring", "🎯")
        if logs_df.empty:
            ip_df = pd.DataFrame({"IP Address":["45.33.12.1","103.5.11.9","192.168.5.2"], "Hits":[1402,930,412], "Score":[98,85,62]})
            st.table(ip_df)
        else:
            asset_df = compute_asset_risk_scores(logs_df, top_n=10)
            if asset_df.empty:
                st.info("No assets to score yet.")
            else:
                st.dataframe(asset_df, use_container_width=True)

    with right_col:
        section_header("Confusion Matrix", "🧮")
        metrics = compute_metrics_from_labels(logs_df)
        if metrics and "confusion_matrix" in metrics:
            z = np.array(metrics["confusion_matrix"])
            st.markdown(f"<div style='font-size:0.75rem;color:#a09ac0;margin:-5px 0 10px 0;'>Based on {metrics['labeled_count']} analyst-reviewed incidents</div>", unsafe_allow_html=True)
        else:
            z = np.array([[88, 12], [5, 95]])
            st.markdown("<div style='font-size:0.75rem;color:#a09ac0;margin:-5px 0 10px 0;'>Simulated metrics (Label incidents in logs to see real data)</div>", unsafe_allow_html=True)
            
        figc = px.imshow(z, text_auto=".0f", 
                         labels=dict(x="AI Prediction", y="Actual Label", color="Count"),
                         x=["Safe", "Threat"], y=["Safe", "Threat"],
                         color_continuous_scale=[[0,"rgba(6,182,212,0.15)"], [1,"rgba(6,182,212,0.95)"]])
        figc.update_traces(textfont=dict(color="#ffffff", size=18, family="Inter"))
        figc = styled_chart_layout(figc, 260)
        # Increase left margin so labels aren't cut off
        figc.update_layout(margin=dict(l=60, r=20, t=30, b=50))
        st.plotly_chart(figc, use_container_width=True)

# ═══════════════════════════════════════════════════════════════
# PHISHING DETECTION — LIVE
# ═══════════════════════════════════════════════════════════════
elif page == "Phishing Detection":
    section_header("Live Phishing Detection", "🎣")
    st.markdown("<div style='color:#6b6490;font-size:0.82rem;margin-bottom:20px;'>Auto-generates realistic phishing & benign email samples, feeds into detector in real-time, and ranks by severity.</div>", unsafe_allow_html=True)

    backend_url = st.text_input("Backend URL", value=BACKEND_URL_DEFAULT, key="phishing_backend")
    c1, c2 = st.columns([1, 1])
    with c1:
        ph_count = st.slider("Samples per batch", 5, 30, 12, key="ph_count")
    with c2:
        ph_ratio = st.slider("Phishing ratio", 0.1, 1.0, 0.55, step=0.05, key="ph_ratio")

    run_phishing = st.button("⚡ Generate & Detect Live", type="primary", key="run_phishing")
    if "phishing_results" not in st.session_state:
        st.session_state.phishing_results = []
    if run_phishing or (not st.session_state.phishing_results):
        st.session_state.phishing_results = []
        feed_placeholder = st.empty()
        kpi_placeholder = st.empty()
        try:
            with st.spinner("🔄 Generating phishing samples and running live detection..."):
                results = simulate_phishing_workflow(backend_url=backend_url, count=ph_count, phishing_ratio=ph_ratio)
            st.session_state.phishing_results = results
        except Exception as e:
            st.error(f"Backend error: {e}")
            results = []

    results = st.session_state.phishing_results
    if results:
        high = sum(1 for r in results if r['severity'] == 'HIGH')
        med  = sum(1 for r in results if r['severity'] == 'MEDIUM')
        low  = sum(1 for r in results if r['severity'] == 'LOW')
        k1, k2, k3, k4 = st.columns(4)
        k1.markdown(metric_card("Total Processed", len(results), "card card-total"), unsafe_allow_html=True)
        k2.markdown(metric_card("HIGH Severity", high, "card card-high"), unsafe_allow_html=True)
        k3.markdown(metric_card("MEDIUM Severity", med, "card card-med"), unsafe_allow_html=True)
        k4.markdown(metric_card("LOW / Benign", low, "card card-safe"), unsafe_allow_html=True)
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.78rem;font-weight:700;color:#a78bfa;margin-bottom:10px;letter-spacing:0.06em;text-transform:uppercase;'>📡 Live Detection Feed</div>", unsafe_allow_html=True)
        feed_html = "<div>"
        for i, r in enumerate(results):
            sev = r['severity']
            badge = severity_badge_html(sev)
            border = "#ef4444" if sev == "HIGH" else ("#f97316" if sev == "MEDIUM" else "#22c55e")
            bg = "rgba(239,68,68,0.06)" if sev == "HIGH" else ("rgba(249,115,22,0.06)" if sev == "MEDIUM" else "rgba(34,197,94,0.04)")
            feed_html += f"""
            <div class="alert-item" style="border-left:3px solid {border};background:{bg};animation-delay:{i*0.04}s">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#4a4470;">{r['timestamp'][:19]}</span>
                  <span style="font-size:0.8rem;font-weight:800;color:#a78bfa;text-transform:uppercase;">{r['prediction']}</span>
                  <span style="font-size:0.72rem;color:#06b6d4;font-family:'JetBrains Mono',monospace;">{r['source']}</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px;">{badge}<span style="font-size:0.7rem;color:#6b6490;">conf {r['confidence']:.1%}</span></div>
              </div>
              <div style="font-size:0.7rem;color:#8ecfd8;font-family:'JetBrains Mono',monospace;">→ {r['recipient']} · {r['subject'][:55]}</div>
            </div>"""
        feed_html += "</div>"
        st.markdown(feed_html, unsafe_allow_html=True)
        
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        
        # Selectbox to pick which incident to investigate
        section_header("AI Threat Investigation", "🔍")
        ph_labels = [f"#{i+1} [{r['severity']}] {r['prediction']} — {r['source']} (conf {r['confidence']:.0%})" for i, r in enumerate(results)]
        ph_sel = st.selectbox("Select an alert to investigate:", ph_labels, key="ph_focus_sel")
        ph_idx = ph_labels.index(ph_sel)
        focus = results[ph_idx]
        render_ai_investigation(focus['prediction'], source=focus['source'], details=focus['details'], severity=focus['severity'], confidence=focus['confidence'])
        render_mitre_mapping("Phishing")

# ═══════════════════════════════════════════════════════════════
# RANSOMWARE DETECTION — LIVE
# ═══════════════════════════════════════════════════════════════
elif page == "Ransomware Detection":
    section_header("Live Ransomware Detection", "💀")
    st.markdown("<div style='color:#6b6490;font-size:0.82rem;margin-bottom:20px;'>Auto-generates ransomware & benign file samples, feeds into detector in real-time, and ranks by severity.</div>", unsafe_allow_html=True)

    backend_url = st.text_input("Backend URL", value=BACKEND_URL_DEFAULT, key="rw_backend")
    c1, c2 = st.columns([1, 1])
    with c1:
        rw_count = st.slider("Samples per batch", 5, 30, 15, key="rw_count")

    run_rw = st.button("⚡ Generate & Detect Live", type="primary", key="run_rw")
    if "rw_results" not in st.session_state:
        st.session_state.rw_results = []
    if run_rw or (not st.session_state.rw_results):
        try:
            with st.spinner("🔄 Generating ransomware samples and running live detection..."):
                results = simulate_ransomware_workflow(backend_url=backend_url, count=rw_count)
            st.session_state.rw_results = results
        except Exception as e:
            st.error(f"Backend error: {e}")
            results = []

    results = st.session_state.rw_results
    if results:
        high = sum(1 for r in results if r['severity'] == 'HIGH')
        med  = sum(1 for r in results if r['severity'] == 'MEDIUM')
        low  = sum(1 for r in results if r['severity'] == 'LOW')
        k1, k2, k3, k4 = st.columns(4)
        k1.markdown(metric_card("Total Processed", len(results), "card card-total"), unsafe_allow_html=True)
        k2.markdown(metric_card("HIGH Severity", high, "card card-high"), unsafe_allow_html=True)
        k3.markdown(metric_card("MEDIUM Severity", med, "card card-med"), unsafe_allow_html=True)
        k4.markdown(metric_card("LOW / Benign", low, "card card-safe"), unsafe_allow_html=True)
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.78rem;font-weight:700;color:#a78bfa;margin-bottom:10px;letter-spacing:0.06em;text-transform:uppercase;'>📡 Live Detection Feed</div>", unsafe_allow_html=True)
        feed_html = "<div>"
        for i, r in enumerate(results):
            sev = r['severity']
            badge = severity_badge_html(sev)
            border = "#ef4444" if sev == "HIGH" else ("#f97316" if sev == "MEDIUM" else "#22c55e")
            bg = "rgba(239,68,68,0.06)" if sev == "HIGH" else ("rgba(249,115,22,0.06)" if sev == "MEDIUM" else "rgba(34,197,94,0.04)")
            feed_html += f"""
            <div class="alert-item" style="border-left:3px solid {border};background:{bg};animation-delay:{i*0.04}s">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#4a4470;">{r['timestamp'][:19]}</span>
                  <span style="font-size:0.8rem;font-weight:800;color:#a78bfa;text-transform:uppercase;">{r['prediction']}</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px;">{badge}<span style="font-size:0.7rem;color:#6b6490;">conf {r['confidence']:.1%}</span></div>
              </div>
              <div style="font-size:0.7rem;color:#8ecfd8;font-family:'JetBrains Mono',monospace;">📁 {r['file_name']} · {r['details'][:70]}</div>
            </div>"""
        feed_html += "</div>"
        st.markdown(feed_html, unsafe_allow_html=True)
        
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        
        section_header("AI Threat Investigation", "🔍")
        rw_labels = [f"#{i+1} [{r['severity']}] {r['prediction']} — {r['file_name']} (conf {r['confidence']:.0%})" for i, r in enumerate(results)]
        rw_sel = st.selectbox("Select an alert to investigate:", rw_labels, key="rw_focus_sel")
        rw_idx = rw_labels.index(rw_sel)
        focus = results[rw_idx]
        render_ai_investigation(focus['prediction'], source=focus['source'], details=focus['details'], severity=focus['severity'], confidence=focus['confidence'])
        render_mitre_mapping("Ransomware")

# ═══════════════════════════════════════════════════════════════
# INTRUSION DETECTION — LIVE
# ═══════════════════════════════════════════════════════════════
elif page == "Intrusion Detection":
    section_header("Live Intrusion Detection", "🔒")
    st.markdown("<div style='color:#6b6490;font-size:0.82rem;margin-bottom:20px;'>Auto-generates network flow samples, runs detection in real-time, and auto-blocks malicious IPs.</div>", unsafe_allow_html=True)

    backend_url = st.text_input("Backend URL", value=BACKEND_URL_DEFAULT, key="int_backend")
    c1, c2 = st.columns([1, 1])
    with c1:
        int_count = st.slider("Samples per batch", 5, 40, 15, key="int_count")
    with c2:
        malicious_bias = st.slider("Malicious traffic ratio", 0.0, 1.0, 0.5, step=0.05, key="int_bias")

    run_int = st.button("⚡ Generate & Detect Live", type="primary", key="run_int")
    if "int_results" not in st.session_state:
        st.session_state.int_results = []
    if run_int or (not st.session_state.int_results):
        try:
            with st.spinner("🔄 Generating network flows and running live detection..."):
                results = simulate_intrusion_workflow(backend_url=backend_url, count=int_count, malicious_bias=malicious_bias)
            st.session_state.int_results = results
        except Exception as e:
            st.error(f"Backend error: {e}")
            results = []

    results = st.session_state.int_results
    if results:
        high = sum(1 for r in results if r['severity'] == 'HIGH')
        med  = sum(1 for r in results if r['severity'] == 'MEDIUM')
        low  = sum(1 for r in results if r['severity'] == 'LOW')
        blocked_cnt = sum(1 for r in results if r.get('blocked'))
        k1, k2, k3, k4 = st.columns(4)
        k1.markdown(metric_card("Total Processed", len(results), "card card-total"), unsafe_allow_html=True)
        k2.markdown(metric_card("HIGH Severity", high, "card card-high"), unsafe_allow_html=True)
        k3.markdown(metric_card("MEDIUM Severity", med, "card card-med"), unsafe_allow_html=True)
        k4.markdown(metric_card("IPs Blocked", blocked_cnt, "card card-safe"), unsafe_allow_html=True)
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.78rem;font-weight:700;color:#a78bfa;margin-bottom:10px;letter-spacing:0.06em;text-transform:uppercase;'>📡 Live Detection Feed</div>", unsafe_allow_html=True)
        feed_html = "<div>"
        for i, r in enumerate(results):
            sev = r['severity']
            badge = severity_badge_html(sev)
            border = "#ef4444" if sev == "HIGH" else ("#f97316" if sev == "MEDIUM" else "#22c55e")
            bg = "rgba(239,68,68,0.06)" if sev == "HIGH" else ("rgba(249,115,22,0.06)" if sev == "MEDIUM" else "rgba(34,197,94,0.04)")
            blocked_tag = " 🚫 BLOCKED" if r.get('blocked') else ""
            feed_html += f"""
            <div class="alert-item" style="border-left:3px solid {border};background:{bg};animation-delay:{i*0.04}s">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#4a4470;">{r['timestamp'][:19]}</span>
                  <span style="font-size:0.8rem;font-weight:800;color:#a78bfa;text-transform:uppercase;">{r['prediction']}{blocked_tag}</span>
                  <span style="font-size:0.72rem;color:#06b6d4;font-family:'JetBrains Mono',monospace;">{r['source']}</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px;">{badge}<span style="font-size:0.7rem;color:#6b6490;">conf {r['confidence']:.1%}</span></div>
              </div>
              <div style="font-size:0.7rem;color:#8ecfd8;font-family:'JetBrains Mono',monospace;">→ {r.get('dst_ip','')} · {r.get('protocol','')} · port {r.get('port','')} · {r.get('service','')}</div>
            </div>"""
        feed_html += "</div>"
        st.markdown(feed_html, unsafe_allow_html=True)
        # Blocked IPs table
        try:
            blocked_registry = fetch_blocked_ips(backend_url)
            if blocked_registry:
                st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(239,68,68,0.25),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
                st.markdown("<div style='font-size:0.78rem;font-weight:700;color:#ef4444;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em;'>🚫 Blocked IP Registry</div>", unsafe_allow_html=True)
                st.dataframe(pd.DataFrame([{"ip": ip, **meta} for ip, meta in blocked_registry.items()]), use_container_width=True, height=200)
        except Exception:
            pass
        
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        
        section_header("AI Threat Investigation", "🔍")
        int_labels = [f"#{i+1} [{r['severity']}] {r['prediction']} — {r['source']}→{r.get('dst_ip','')} (conf {r['confidence']:.0%})" for i, r in enumerate(results)]
        int_sel = st.selectbox("Select an alert to investigate:", int_labels, key="int_focus_sel")
        int_idx = int_labels.index(int_sel)
        focus = results[int_idx]
        render_ai_investigation(focus['prediction'], source=focus['source'], details=focus['details'], severity=focus['severity'], confidence=focus['confidence'])
        render_mitre_mapping("Intrusion")

# ═══════════════════════════════════════════════════════════════
# INSIDER THREAT — LIVE
# ═══════════════════════════════════════════════════════════════
elif page == "Insider Threat Detection":
    section_header("Live Insider Threat Detection", "👁️")
    st.markdown("<div style='color:#6b6490;font-size:0.82rem;margin-bottom:20px;'>Auto-generates user behaviour logs (login time, file accesses, activity score) and detects insider threats in real-time.</div>", unsafe_allow_html=True)

    backend_url = st.text_input("Backend URL", value=BACKEND_URL_DEFAULT, key="ins_backend")
    c1, c2 = st.columns([1, 1])
    with c1:
        ins_count = st.slider("Samples per batch", 5, 30, 12, key="ins_count")
    with c2:
        ins_ratio = st.slider("Threat ratio", 0.1, 1.0, 0.4, step=0.05, key="ins_ratio")

    run_ins = st.button("⚡ Generate & Detect Live", type="primary", key="run_ins")
    if "ins_results" not in st.session_state:
        st.session_state.ins_results = []
    if run_ins or (not st.session_state.ins_results):
        try:
            with st.spinner("🔄 Generating user behaviour logs and running live detection..."):
                results = simulate_insider_workflow(backend_url=backend_url, count=ins_count, threat_ratio=ins_ratio)
            st.session_state.ins_results = results
        except Exception as e:
            st.error(f"Backend error: {e}")
            results = []

    results = st.session_state.ins_results
    if results:
        high = sum(1 for r in results if r['severity'] == 'HIGH')
        med  = sum(1 for r in results if r['severity'] == 'MEDIUM')
        low  = sum(1 for r in results if r['severity'] == 'LOW')
        k1, k2, k3, k4 = st.columns(4)
        k1.markdown(metric_card("Total Processed", len(results), "card card-total"), unsafe_allow_html=True)
        k2.markdown(metric_card("HIGH Severity", high, "card card-high"), unsafe_allow_html=True)
        k3.markdown(metric_card("MEDIUM Severity", med, "card card-med"), unsafe_allow_html=True)
        k4.markdown(metric_card("LOW / Normal", low, "card card-safe"), unsafe_allow_html=True)
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.3),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        st.markdown("<div style='font-size:0.78rem;font-weight:700;color:#a78bfa;margin-bottom:10px;letter-spacing:0.06em;text-transform:uppercase;'>📡 Live Detection Feed</div>", unsafe_allow_html=True)
        feed_html = "<div>"
        for i, r in enumerate(results):
            sev = r['severity']
            badge = severity_badge_html(sev)
            border = "#ef4444" if sev == "HIGH" else ("#f97316" if sev == "MEDIUM" else "#22c55e")
            bg = "rgba(239,68,68,0.06)" if sev == "HIGH" else ("rgba(249,115,22,0.06)" if sev == "MEDIUM" else "rgba(34,197,94,0.04)")
            feed_html += f"""
            <div class="alert-item" style="border-left:3px solid {border};background:{bg};animation-delay:{i*0.04}s">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <span style="font-size:0.68rem;font-family:'JetBrains Mono',monospace;color:#4a4470;">{r['timestamp'][:19]}</span>
                  <span style="font-size:0.8rem;font-weight:800;color:#a78bfa;text-transform:uppercase;">{r['prediction']}</span>
                  <span style="font-size:0.72rem;color:#06b6d4;font-family:'JetBrains Mono',monospace;">{r['source']}</span>
                </div>
                <div style="display:flex;align-items:center;gap:6px;">{badge}<span style="font-size:0.7rem;color:#6b6490;">conf {r['confidence']:.1%}</span></div>
              </div>
              <div style="font-size:0.7rem;color:#8ecfd8;font-family:'JetBrains Mono',monospace;">🕒 login:{r.get('login_hour','?')}:00 · 📂 files:{r.get('file_access_count',0)} · 📊 activity:{r.get('activity_score',0)} · {r.get('department','')}</div>
            </div>"""
        feed_html += "</div>"
        st.markdown(feed_html, unsafe_allow_html=True)
        
        st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:20px 0;'></div>", unsafe_allow_html=True)
        
        section_header("AI Threat Investigation", "🔍")
        ins_labels = [f"#{i+1} [{r['severity']}] {r['prediction']} — {r['source']} login:{r.get('login_hour','?')}h (conf {r['confidence']:.0%})" for i, r in enumerate(results)]
        ins_sel = st.selectbox("Select an alert to investigate:", ins_labels, key="ins_focus_sel")
        ins_idx = ins_labels.index(ins_sel)
        focus = results[ins_idx]
        render_ai_investigation(focus['prediction'], source=focus['source'], details=focus['details'], severity=focus['severity'], confidence=focus['confidence'])
        render_mitre_mapping("Insider Threat")

# ═══════════════════════════════════════════════════════════════
# INCIDENT LOGS
# ═══════════════════════════════════════════════════════════════
elif page == "Incident Logs":
    section_header("Incident Logs", "📋")
    st.markdown("<div style='color:#6b6490;font-size:0.82rem;margin-bottom:20px;'>Review incidents and mark as True Positive / False Positive for model evaluation.</div>", unsafe_allow_html=True)

    logs_path = os.path.join("logs", "attack_logs.csv")
    if not os.path.exists(logs_path):
        st.info("No logs found yet. Trigger some detections first to generate incidents.")
    else:
        # Robust CSV Loading
        try:
            # We enforce usecols and on_bad_lines='skip' to avoid broken rows
            expected_cols = ["timestamp", "attack_type", "source", "severity", "label", "confidence", "details", "true_label"]
            # Read first to check what columns exist
            df_check = pd.read_csv(logs_path, nrows=0)
            available_cols = [c for c in expected_cols if c in df_check.columns]
            if "true_label" not in available_cols:
                # If true_label hasn't been added yet, just fall back to the standard columns
                available_cols = ["timestamp", "attack_type", "source", "severity", "label", "confidence", "details"]

            df_raw = pd.read_csv(logs_path, usecols=lambda c: c in available_cols, on_bad_lines='skip', keep_default_na=False)
            
            # Ensure all expected columns exist even if empty
            for col in expected_cols:
                if col not in df_raw.columns:
                    df_raw[col] = ""
                    
            # Reorder strictly
            df_raw = df_raw[expected_cols]
        except Exception as e:
            df_raw = pd.DataFrame(columns=["timestamp", "attack_type", "source", "severity", "label", "confidence", "details", "true_label"])

        if df_raw.empty:
            st.info("No valid incidents logged yet.")
        else:
            # Add an original file index mapping so that updates point to the correct row in the CSV
            try:
                # We need the real file index, but pd.read_csv(on_bad_lines='skip') loses 1:1 mapping with the raw file.
                # Re-read fully without usecols just to get the true length for labelling
                df_full = pd.read_csv(logs_path, on_bad_lines='skip', keep_default_na=False)
                df_raw["file_index"] = df_full.index
            except Exception:
                 df_raw = df_raw.reset_index().rename(columns={"index": "file_index"})

            df_display = df_raw.copy()
            df_display["timestamp"] = pd.to_datetime(df_display["timestamp"], errors="coerce")
            df_display = df_display.sort_values("timestamp", ascending=False).reset_index(drop=True)

            with st.expander("📄 Generate Attack Evidence & Reports", expanded=False):
                st.markdown("<div style='font-size:0.8rem;color:#a09ac0;margin-bottom:12px;'>Download structured AI Evidence exports or aggregated attack summaries.</div>", unsafe_allow_html=True)
                rc1, rc2 = st.columns(2)
                with rc1:
                    report_type = st.selectbox("Report Type:", [
                        "Pending Review (High/Med)", 
                        "Attack Evidence Export (All Models)",
                        "Attack Summary"
                    ])
                
                def extract_evidence(row):
                    attack = str(row.get('attack_type', ''))
                    details = str(row.get('details', ''))
                    source = str(row.get('source', ''))
                    if "Phishing" in attack:
                        parts = details.split('·')
                        recip = parts[0].replace('→','').strip() if len(parts)>0 else ""
                        sub = "".join(parts[1:]).strip() if len(parts)>1 else ""
                        return f"[Evidence: Sender IP={source}, Recipient={recip}, Email Subject='{sub}']"
                    elif "Insider" in attack:
                        clean = details.replace('🕒','').replace('📂','').replace('📊','').strip()
                        return f"[Evidence: User={source}, {clean}]"
                    elif "Ransomware" in attack:
                        parts = details.split('·')
                        file = parts[0].replace('📁','').strip() if len(parts)>0 else ""
                        info = "".join(parts[1:]).strip() if len(parts)>1 else ""
                        return f"[Evidence: Machine={source}, Target File={file}, Characteristics={info}]"
                    elif "Intrusion" in attack:
                        parts = details.split('·')
                        dst = parts[0].replace('→','').strip() if len(parts)>0 else ""
                        proto = parts[1].strip() if len(parts)>1 else ""
                        port = parts[2].replace('port','').strip() if len(parts)>2 else ""
                        return f"[Evidence: Src IP={source}, Dst IP={dst}, Protocol={proto}, Port={port}]"
                    return f"[Evidence: Source={source}, Details={details}]"

                if "Pending" in report_type or "Evidence" in report_type:
                    if "Pending" in report_type:
                        df_out = df_raw[df_raw['severity'].isin(["HIGH", "MEDIUM", "High", "Medium"]) & (df_raw['true_label'].isna() | (df_raw['true_label'] == ""))].copy()
                    else:
                        df_out = df_raw.copy()
                        
                    if not df_out.empty:
                        df_out['prediction_evidence'] = df_out.apply(extract_evidence, axis=1)
                        df_out = df_out.drop(columns=['details', 'source'], errors='ignore')
                elif "Summary" in report_type:
                    df_out = df_raw.groupby(['attack_type', 'severity']).size().reset_index(name='incident_count')
                else:
                    df_out = df_raw.copy()
                
                if 'file_index' in df_out.columns:
                    df_out = df_out.drop(columns=['file_index'])
                    
                csv_data = df_out.to_csv(index=False).encode('utf-8')
                
                with rc2:
                    st.markdown("<div style='margin-bottom:28px;'></div>", unsafe_allow_html=True)
                    st.download_button(
                        label="⬇️ Download CSV Report",
                        data=csv_data,
                        file_name=f"soc_report_{report_type.split()[0].lower()}.csv",
                        mime="text/csv",
                        use_container_width=True,
                        type="primary"
                    )
                st.markdown(f"<div style='font-size:0.75rem;color:#6b6490;text-align:right;'>{len(df_out)} records ready for export</div>", unsafe_allow_html=True)
            
            st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:16px 0;'></div>", unsafe_allow_html=True)

            # Filtering Section
            c1, c2 = st.columns(2)
            with c1:
                types = ["All"] + sorted([str(x) for x in df_display["attack_type"].unique() if x])
                sel_type = st.selectbox("Filter by Attack Type:", types)
            with c2:
                # Normalise severities in the dropdown
                unique_sevs = sorted({normalize_severity(str(x)) for x in df_display["severity"].unique() if x})
                sevs = ["All"] + unique_sevs
                sel_sev = st.selectbox("Filter by Severity:", sevs)

            if sel_type != "All":
                df_display = df_display[df_display["attack_type"].astype(str) == sel_type]
            if sel_sev != "All":
                df_display = df_display[df_display["severity"].apply(lambda x: normalize_severity(str(x))) == sel_sev]

            st.markdown(f"<div style='font-size:0.8rem;color:#6b6490;margin-bottom:10px;'>Showing {len(df_display)} incidents</div>", unsafe_allow_html=True)

            # Pagination
            page_size = 50
            total_pages = max(1, len(df_display) // page_size + (1 if len(df_display) % page_size > 0 else 0))
            
            if "log_page" not in st.session_state:
                st.session_state.log_page = 1
                
            pc1, pc2, pc3 = st.columns([1, 2, 1])
            with pc1:
                if st.button("⬅️ Previous", disabled=(st.session_state.log_page <= 1)):
                    st.session_state.log_page -= 1
                    st.rerun()
            with pc2:
                st.markdown(f"<div style='text-align:center;font-size:0.85rem;color:#a78bfa;line-height:2.5;'>Page {st.session_state.log_page} of {total_pages}</div>", unsafe_allow_html=True)
            with pc3:
                if st.button("Next ➡️", disabled=(st.session_state.log_page >= total_pages)):
                    st.session_state.log_page += 1
                    st.rerun()

            # Fix bounds on page state if filters changed
            if st.session_state.log_page > total_pages:
                st.session_state.log_page = total_pages

            start_idx = (st.session_state.log_page - 1) * page_size
            end_idx = start_idx + page_size
            
            df_page = df_display.iloc[start_idx:end_idx].copy()
            df_page["timestamp"] = df_page["timestamp"].astype(str) # format nicely for grid

            # Show strict readable dataframe
            st.dataframe(
                df_page[["file_index", "timestamp", "attack_type", "severity", "source", "label", "confidence", "details", "true_label"]], 
                height=500, 
                use_container_width=True, 
                hide_index=True
            )

            st.markdown("<div style='height:1px;background:linear-gradient(90deg,transparent,rgba(139,92,246,0.25),transparent);margin:16px 0;'></div>", unsafe_allow_html=True)
            st.markdown("<div style='font-size:0.85rem;font-weight:700;color:#a78bfa;margin-bottom:10px;'>Label an Incident</div>", unsafe_allow_html=True)

            idx = st.number_input("File row index (from table above)", 
                                  min_value=0, 
                                  max_value=max(0, len(df_raw)-1), 
                                  value=int(df_page.iloc[0]["file_index"]) if not df_page.empty else 0)
                                  
            sel_row = df_raw[df_raw['file_index'] == int(idx)]
            if sel_row.empty:
                st.warning("Selected index not found.")
            else:
                sel = sel_row.iloc[0].to_dict()
                try:
                    conf_val = float(sel.get("confidence")) if sel.get("confidence") not in (None,"","nan") else None
                    render_ai_investigation(
                        sel.get("attack_type",""), 
                        source=sel.get("source",""),
                        details=sel.get("details",""),
                        severity=normalize_severity(str(sel.get("severity",""))),
                        confidence=conf_val,
                        show_confidence=True
                    )
                    render_mitre_mapping(sel.get("attack_type",""))
                except Exception:
                    pass

                label_choice = st.selectbox("Mark incident as:", ["Select","True Positive","False Positive","Clear Label"])
                if st.button("✅ Submit Label"):
                    try:
                        df_file = pd.read_csv(logs_path, on_bad_lines='skip', keep_default_na=False)
                        file_idx = int(idx)
                        if file_idx < 0 or file_idx >= len(df_file):
                            st.error("File index out of range.")
                        else:
                            if "true_label" not in df_file.columns:
                                df_file["true_label"] = ""
                            if label_choice == "Clear Label":        df_file.at[file_idx,"true_label"] = ""
                            elif label_choice == "True Positive":    df_file.at[file_idx,"true_label"] = "1"
                            elif label_choice == "False Positive":   df_file.at[file_idx,"true_label"] = "0"
                            else: st.error("Please select a valid label."); st.stop()
                            df_file.to_csv(logs_path, index=False)
                            st.success("✅ Label saved to logs file.")
                    except Exception as e:
                        st.error("Failed to save label: " + str(e))

            st.markdown("<hr>", unsafe_allow_html=True)

# ── Footer ──
st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)
