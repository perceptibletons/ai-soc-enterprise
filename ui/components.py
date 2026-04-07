import streamlit as st
import pandas as pd
import plotly.express as px

from config.settings import attack_analysis, mitre_mapping
from utils.scoring import normalize_severity
from utils.geo import geolocate_ip

def severity_badge_html(sev):
    sev = normalize_severity(sev)
    if sev == "HIGH":
        cls = "badge-high"
    elif sev == "MEDIUM":
        cls = "badge-med"
    else:
        cls = "badge-low"
    return f"<span class='{cls}'>{sev}</span>"

def _build_dynamic_analysis(attack_label, details, severity, source):
    """Generate a rich, evidence-driven analysis paragraph from the raw details string."""
    sev = normalize_severity(str(severity))
    sev_reason = {"HIGH": "critical threat indicators exceeded risk threshold", "MEDIUM": "moderate risk indicators were detected", "LOW": "activity pattern appears largely benign"}.get(sev, "risk indicators were evaluated")
    d = str(details)
    src = str(source)

    if "Phishing" in attack_label:
        parts = d.split("·")
        recip = parts[0].replace("→","").strip() if parts else src
        subject = "".join(parts[1:]).strip() if len(parts) > 1 else "unknown"
        return (f"Email from <b>{src}</b> to <b>{recip}</b> flagged as <b>{sev}</b> because {sev_reason}. "
                f"Subject line '{subject[:80]}' contains patterns consistent with credential harvesting or urgent-action lures. "
                f"Sender IP reputation, header anomalies, and embedded link entropy were scored by the classifier.")
    elif "Insider" in attack_label:
        clean = d.replace("🕒","login_hour:").replace("📂","file_access:").replace("📊","activity:").strip()
        return (f"User <b>{src}</b> flagged as <b>{sev}</b> insider threat because {sev_reason}. "
                f"Behavioural telemetry: {clean}. "
                f"The model detected deviation from the department baseline — unusual login hours and elevated file access volume are primary indicators of privilege misuse or data exfiltration.")
    elif "Ransomware" in attack_label:
        parts = d.split("·")
        fname = parts[0].replace("📁","").strip() if parts else "unknown"
        characteristics = "".join(parts[1:]).strip() if len(parts) > 1 else "high entropy binary"
        return (f"File <b>{fname}</b> on host <b>{src}</b> flagged as <b>{sev}</b> because {sev_reason}. "
                f"Detected characteristics: {characteristics}. "
                f"High file entropy, presence of packer signatures, and abnormal process injection API call sequences are consistent with ransomware pre-encryption staging.")
    elif "Intrusion" in attack_label:
        parts = d.split("·")
        dst = parts[0].replace("→","").strip() if parts else ""
        proto = parts[1].strip() if len(parts) > 1 else ""
        port = parts[2].replace("port","").strip() if len(parts) > 2 else ""
        svc = parts[3].strip() if len(parts) > 3 else ""
        return (f"Network flow from <b>{src}</b> → <b>{dst}</b> flagged as <b>{sev}</b> because {sev_reason}. "
                f"Traffic on {proto} port <b>{port}</b> ({svc}) showed anomalous packet rates, unusual payload sizes, or known malicious signature patterns. "
                f"This is consistent with lateral movement, exploitation attempts, or command-and-control beaconing.")
    else:
        return f"Event from <b>{src}</b> classified as <b>{sev}</b> because {sev_reason}. Raw data: {d[:200]}"


def render_ai_investigation(attack_label, source=None, details=None, severity=None, confidence=None, show_confidence=True):
    if not attack_label:
        return

    # Try to match the attack label with available config keys (handle case mismatch)
    from config.settings import attack_analysis as _aa, mitre_mapping as _mm
    matched_key = next((k for k in _aa if k.lower() in str(attack_label).lower() or str(attack_label).lower() in k.lower()), None)
    info = _aa.get(matched_key or attack_label, {})
    response_text = info.get("response", "Isolate the affected asset, capture forensic evidence, and escalate to a senior SOC analyst for further investigation.")

    # Build rich dynamic analysis
    dynamic_analysis = _build_dynamic_analysis(attack_label, details or "", severity or "", source or "")

    sev_badge = severity_badge_html(severity) if severity else ""

    conf_pct = ""
    if show_confidence and confidence is not None:
        try:
            pct = int(float(confidence) * 100)
            bar_color = "#ef4444" if pct >= 75 else ("#f97316" if pct >= 45 else "#22c55e")
            conf_pct = f"""
            <div style="margin-top:16px;">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <span class="inv-label">Model Confidence</span>
                <span style="font-size:0.85rem;font-weight:700;color:#a78bfa;">{pct}%</span>
              </div>
              <div style="background:rgba(255,255,255,0.06);border-radius:99px;height:6px;overflow:hidden;">
                <div class="conf-bar-fill" style="height:100%;width:{pct}%;background:linear-gradient(90deg,{bar_color},{bar_color}88);border-radius:99px;transform-origin:left;"></div>
              </div>
            </div>
            """
        except Exception:
            pass

    source_html = f'<div class="inv-label">Source / Asset</div><div class="inv-value mono">{source}</div>' if source else ""

    html = f"""
    <div class="investigation-panel">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <div style="width:3px;height:24px;background:#4361ee;border-radius:2px;"></div>
          <div>
            <div class="inv-label" style="margin-bottom:2px;">🔍 AI Threat Investigation — Selected Incident</div>
            <div style="font-size:1.05rem;font-weight:800;color:#1a1d2e;letter-spacing:-0.02em;">{attack_label}</div>
          </div>
        </div>
        <div>{sev_badge}</div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;">
        <div style="background:#f8f9fd;border:1px solid rgba(67,97,238,0.12);border-radius:10px;padding:14px;">
          <div class="inv-label">🤖 AI Evidence Analysis</div>
          <div class="inv-value" style="line-height:1.6;">{dynamic_analysis}</div>
        </div>
        <div style="background:#f8f9fd;border:1px solid rgba(67,97,238,0.12);border-radius:10px;padding:14px;">
          <div class="inv-label">⚡ Recommended Response</div>
          <div class="inv-value">{response_text}</div>
        </div>
      </div>

      {source_html}
      {conf_pct}
    </div>
    """

    if hasattr(st, "html"):
        st.html(html)
    else:
        st.markdown(html, unsafe_allow_html=True)


def render_mitre_mapping(attack_label):
    if not attack_label:
        return
    mapping = mitre_mapping.get(attack_label)
    if not mapping:
        return

    technique = mapping.get("technique", "N/A")
    mitre_id  = mapping.get("mitre_id", "N/A")
    tactic    = mapping.get("tactic", "N/A")

    html = f"""
    <div class="mitre-panel">
      <div style="margin-bottom:2px;">
        <div style="font-size:0.6rem;font-weight:700;letter-spacing:0.12em;text-transform:uppercase;color:#4361ee;margin-bottom:6px;">⚡ MITRE ATT&amp;CK</div>
      </div>
      <div class="mitre-chip">
        <span class="chip-label">Technique</span>
        <span class="chip-value">{technique}</span>
      </div>
      <div class="mitre-chip" style="border-color:rgba(67,97,238,0.2);">
        <span class="chip-label">MITRE ID</span>
        <span class="chip-value" style="font-family:'JetBrains Mono',monospace;color:#4361ee;">{mitre_id}</span>
      </div>
      <div class="mitre-chip">
        <span class="chip-label">Tactic</span>
        <span class="chip-value">{tactic}</span>
      </div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)

def render_attack_map(logs_df):
    section_header("Global Cyber Attack Map", "🌐")

    if logs_df.empty:
        st.info("No attack data available for the map.")
        return

    map_data = []
    # Cap processing to the most recent 150 unique IPs to keep dashboard responsive
    unique_ips = pd.unique(logs_df['source'].fillna("").astype(str))
    
    # Process only the last 150 to ensure we see the newest attacks quickly
    for ip in unique_ips[-150:]:
        ip = ip.strip()
        if not ip:
            continue
        geo = geolocate_ip(ip)
        if geo:
            rows = logs_df[logs_df['source'].astype(str) == ip]
            attacks = ", ".join(rows['attack_type'].dropna().unique().astype(str))
            severities = ", ".join(sorted({normalize_severity(s) for s in rows['severity'].dropna().astype(str)}))
            map_data.append({
                "lat": geo["lat"],
                "lon": geo["lon"],
                "attack": attacks,
                "severity": severities,
                "ip": ip
            })

    if not map_data:
        st.info("No mapped IP locations found.")
        return

    map_df = pd.DataFrame(map_data)

    colour_map = {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#22c55e"}

    fig = px.scatter_geo(
        map_df,
        lat="lat",
        lon="lon",
        color="severity",
        color_discrete_map=colour_map,
        hover_name="ip",
        hover_data=["attack"],
        title="",
        projection="orthographic",
        size_max=18
    )

    fig.update_traces(marker=dict(size=10, opacity=0.85, line=dict(width=1, color='rgba(255,255,255,0.2)')))

    fig.update_layout(
        height=600,
        autosize=True,
        geo=dict(
            showland=True,
            landcolor="#2f2b4a",
            oceancolor="#100d23",
            showocean=True,
            countrycolor="#5c538c",
            showcountries=True,
            bgcolor="rgba(0,0,0,0)",
            showframe=False,
        ),
        margin={"r": 0, "t": 0, "l": 0, "b": 0},
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(
            bgcolor="rgba(10,10,20,0.8)",
            bordercolor="rgba(139,92,246,0.2)",
            borderwidth=1,
            font=dict(color="#a09ac0", size=11)
        )
    )

    import streamlit.components.v1 as components
    
    html_content = fig.to_html(include_plotlyjs="cdn", full_html=False, div_id="global_attack_map", config={"displayModeBar": False, "scrollZoom": True})
    
    js_inject = """
    <script>
    setTimeout(function() {
        var gd = document.getElementById('global_attack_map');
        if(!gd) return;
        var isInteracting = false;
        
        gd.addEventListener('mousedown', function() { isInteracting = true; });
        gd.addEventListener('mouseup', function() { isInteracting = false; });
        gd.addEventListener('mouseleave', function() { isInteracting = false; });
        gd.addEventListener('touchstart', function() { isInteracting = true; });
        gd.addEventListener('touchend', function() { isInteracting = false; });

        function rotateMap() {
            if (!isInteracting && gd.layout && gd.layout.geo) {
                var currentLon = 0;
                if (gd.layout.geo.projection && gd.layout.geo.projection.rotation) {
                    currentLon = gd.layout.geo.projection.rotation.lon || 0;
                }
                var lon = (currentLon + 0.3) % 360;
                Plotly.relayout(gd, {'geo.projection.rotation.lon': lon});
            }
        }
        setInterval(rotateMap, 60);
    }, 500);
    </script>
    <style>
        body { margin: 0; padding: 0; background: #f8f9fd !important; overflow: hidden; display: flex; align-items: center; justify-content: center; width: 100vw; height: 100vh; }
        #global_attack_map { width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; }
    </style>
    """
    
    components.html(html_content + js_inject, height=600)

# ── Helper: section header ──
def section_header(title, icon=""):
    st.markdown(f"""
    <div class="section-header" style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
      <div style="width:3px;height:18px;background:#4361ee;border-radius:2px;flex-shrink:0;"></div>
      <h2 style="font-size:0.82rem;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;color:#1a1d2e;margin:0;">{icon} {title}</h2>
    </div>
    """, unsafe_allow_html=True)

# ── Helper: metric card ──
def metric_card(title, value, card_class="card"):
    return f"""
    <div class='{card_class}' style='transition:all 0.3s ease;'>
      <h4>{title}</h4>
      <h2>{value}</h2>
    </div>
    """
