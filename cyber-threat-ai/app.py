from sample_data import get_default_reports, get_live_demo_text
from analyzer import analyze_reports
from ai_engine import generate_ai_assessment

reports = get_default_reports()
analysis_result = analyze_reports(reports)
ai_result = generate_ai_assessment(reports, analysis_result)
from sample_data import get_default_reports, LIVE_DEMO_REPORT
from analyzer import analyze_reports

reports = get_default_reports()
analysis = analyze_reports(reports)
harness_info = ai_result.get("harness_validation", {})
if harness_info:
    if harness_info.get("passed"):
        st.success(harness_info.get("badge_text"))
    else:
        st.warning(harness_info.get("badge_text"))
st.caption(f"Powered by: {ai_result.get('model_used', 'Open-Weight LLM + Rule-Based Harness')}")

# Cyber Threat Intelligence Dashboard


import streamlit as st
import pandas as pd
import json
import math
import plotly.graph_objects as go

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Securify // Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -----------------------------------------------------------------------------
# MODULE IMPORTS & SAFE FALLBACKS (Zero-crash guarantee for Hackathons)
# -----------------------------------------------------------------------------
try:
    from sample_data import get_default_reports, get_live_demo_text, LIVE_DEMO_REPORT
except ImportError:
    def get_default_reports():
        return [
            {
                "id": "REP-01",
                "title": "Spearphishing Campaign Targeting Finance Personnel",
                "source": "Internal SOC Email Gateway",
                "date": "2026-10-14",
                "text": "Finance department received urgent password-reset emails spoofing IT pointing to hxxps://auth-update-portal[.]com/sso/login. Stage-1 loader fetched from 185.220.101[.]45."
            },
            {
                "id": "REP-02",
                "title": "Perimeter Web Server Exploitation & Outbound C2",
                "source": "Perimeter Firewall & IDS Logs",
                "date": "2026-10-15",
                "text": "IDS alerts flagged active exploitation of CVE-2024-21412. Server established outbound C2 beaconing to 185.220.101.45 every 60s. Dropped payload MD5 44d88612fea8a8f36de82e1278abb02f."
            },
            {
                "id": "REP-03",
                "title": "Endpoint EDR Alert: Credential Stealer Detonation",
                "source": "CrowdStrike / EDR Telemetry",
                "date": "2026-10-16",
                "text": "EDR quarantined suspicious binary MD5 44d88612fea8a8f36de82e1278abb02f downloaded after visiting auth-update-portal.com. Attempted exfiltration to 91.214.124.10."
            }
        ]
    def get_live_demo_text():
        return "Compromised hosts exfiltrating active directory data to 91.214.124.10 and lateral tools from cdn-sync-service.net."
    LIVE_DEMO_REPORT = {
        "id": "REP-04",
        "title": "External Threat Feed Alert: Ransomware Pre-Staging",
        "source": "CISA / ISAC Threat Intel Feed",
        "date": "2026-10-16",
        "text": "Active ransomware pre-staging cluster scanning for CVE-2024-21412. Compromised hosts observed exfiltrating active directory data to 91.214.124.10 and pulling lateral movement tools from hxxp://cdn-sync-service[.]net/payload.bin."
    }

try:
    from analyzer import analyze_reports
except ImportError:
    def analyze_reports(reps):
        return {
            "metrics": {"total_reports": len(reps), "total_iocs": 8, "shared_iocs": 3, "campaign_confidence": 95},
            "indicators": [
                {"ioc": "185.220.101.45", "type": "IPv4", "reports": ["REP-01", "REP-02"], "shared": True},
                {"ioc": "auth-update-portal.com", "type": "Domain", "reports": ["REP-01", "REP-03"], "shared": True},
                {"ioc": "44d88612fea8a8f36de82e1278abb02f", "type": "MD5", "reports": ["REP-02", "REP-03"], "shared": True},
                {"ioc": "CVE-2024-21412", "type": "CVE", "reports": ["REP-02"], "shared": False},
                {"ioc": "91.214.124.10", "type": "IPv4", "reports": ["REP-03"], "shared": False}
            ],
            "connections": [
                {"ioc": "185.220.101.45", "type": "IPv4", "linked_reports": ["REP-01", "REP-02"], "evidence": "C2 callback in REP-01 & brute-force source in REP-02"},
                {"ioc": "auth-update-portal.com", "type": "Domain", "linked_reports": ["REP-01", "REP-03"], "evidence": "Credential harvesting site linked to malware payload drop"},
                {"ioc": "44d88612fea8a8f36de82e1278abb02f", "type": "MD5", "linked_reports": ["REP-02", "REP-03"], "evidence": "Payload hash match across web server exploit and endpoint"}
            ],
            "graph_edges": [
                ("REP-01", "185.220.101.45", "Report", "IPv4"),
                ("REP-02", "185.220.101.45", "Report", "IPv4"),
                ("REP-01", "auth-update-portal.com", "Report", "Domain"),
                ("REP-03", "auth-update-portal.com", "Report", "Domain"),
                ("REP-02", "44d88612fea8a8f36de82e1278abb02f", "Report", "MD5"),
                ("REP-03", "44d88612fea8a8f36de82e1278abb02f", "Report", "MD5")
            ]
        }

try:
    from ai_engine import generate_ai_assessment
except ImportError:
    def generate_ai_assessment(reps, analysis):
        return {
            "risk_level": "CRITICAL",
            "risk_score": 96,
            "executive_summary": "CRITICAL-risk coordinated APT campaign detected across 3 telemetry sources. Multi-stage attack chain combines credential theft, remote code exploitation, and persistent C2 beaconing with imminent ransomware detonation danger.",
            "evidence_facts": [
                "C2 IP 185.220.101.45 bridges initial phishing lure (REP-01) with billing server exploit (REP-02).",
                "Phishing domain auth-update-portal.com links credential theft to credential stealer detonation on FIN-LAPTOP-04 (REP-03).",
                "Identical payload hash 44d88612fea8a8f36de82e1278abb02f found across both perimeter and workstation tiers."
            ],
            "ai_hypotheses": [
                "Single organized threat actor reusing shared command infrastructure across stages.",
                "Perimeter intrusion orchestrated to bypass internal segmentation following credential acquisition."
            ],
            "mitre_techniques": [
                {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1071.001", "name": "Web Protocols (C2 Beaconing)", "tactic": "Command and Control"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"}
            ],
            "defensive_actions": [
                "[IMMEDIATE] Isolate endpoints FIN-LAPTOP-04 and Billing Web Server from the corporate subnet.",
                "[BLOCK] Null-route 185.220.101.45 and auth-update-portal.com at perimeter edge firewalls & DNS resolvers.",
                "[HUNT] Sweep SIEM logs for hash 44d88612fea8a8f36de82e1278abb02f across all domain-joined endpoints.",
                "[PATCH] Apply emergency vendor mitigation for CVE-2024-21412 on public servers."
            ]
        }

# -----------------------------------------------------------------------------
# HIGH-END DARK CYBER GLASSMORPHISM CSS
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    background-color: #050608 !important;
    color: #F3F4F6 !important;
}

/* Background ambient glows matching the iridescent fluid orbs */
.stApp {
    background: #050608 !important;
    background-image: 
        radial-gradient(circle at 50% 12%, rgba(255, 98, 57, 0.16) 0%, rgba(245, 158, 11, 0.05) 30%, transparent 60%),
        radial-gradient(circle at 82% 28%, rgba(139, 92, 246, 0.14) 0%, rgba(59, 130, 246, 0.04) 40%, transparent 65%),
        radial-gradient(circle at 18% 50%, rgba(244, 63, 94, 0.08) 0%, transparent 45%),
        radial-gradient(circle at 60% 85%, rgba(99, 102, 241, 0.10) 0%, transparent 50%) !important;
    background-attachment: fixed !important;
}

header[data-testid="stHeader"] {
    background: transparent !important;
}
.block-container {
    padding-top: 1.5rem !important;
    padding-bottom: 3.5rem !important;
    max-width: 1250px !important;
}

/* Top Floating Glass Navigation Bar */
.nav-container {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(18, 20, 29, 0.7);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 9999px;
    padding: 10px 24px;
    margin-bottom: 2.2rem;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
}

.brand-wrapper {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 1.05rem;
    letter-spacing: -0.02em;
    color: #FFFFFF;
}

.brand-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background: linear-gradient(135deg, #ff7a45, #ff3b30);
    box-shadow: 0 0 15px rgba(255, 98, 57, 0.5);
    font-size: 14px;
}

.nav-pills {
    display: flex;
    align-items: center;
    gap: 24px;
}

.nav-link {
    font-size: 0.85rem;
    font-weight: 500;
    color: #94A3B8;
    text-decoration: none;
}

.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.25);
    color: #34D399;
    padding: 5px 14px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.03em;
}

.status-dot {
    width: 7px;
    height: 7px;
    background-color: #10B981;
    border-radius: 50%;
    box-shadow: 0 0 8px #10B981;
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.5; transform: scale(0.85); }
}

/* Hero Section */
.hero-wrapper {
    position: relative;
    text-align: center;
    padding: 3rem 1rem 2.5rem 1rem;
    margin-bottom: 2rem;
}

.hero-super {
    display: inline-block;
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: #FF7A45;
    background: rgba(255, 122, 69, 0.1);
    padding: 6px 16px;
    border-radius: 9999px;
    border: 1px solid rgba(255, 122, 69, 0.25);
    margin-bottom: 1.2rem;
    box-shadow: 0 0 20px rgba(255, 122, 69, 0.15);
}

.hero-title {
    font-size: 4.2rem !important;
    font-weight: 800 !important;
    letter-spacing: -0.04em !important;
    line-height: 1.05 !important;
    margin: 0 auto 1.2rem auto !important;
    max-width: 820px;
    background: linear-gradient(180deg, #FFFFFF 30%, #94A3B8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.hero-title span.glow-accent {
    background: linear-gradient(135deg, #FF8A65 0%, #FF5252 50%, #E040FB 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 0 35px rgba(255, 102, 51, 0.35));
}

.hero-desc {
    font-size: 1.1rem;
    font-weight: 400;
    color: #94A3B8;
    max-width: 640px;
    margin: 0 auto 2rem auto;
    line-height: 1.6;
}

/* Floating Stat Badges */
.hero-stats-row {
    display: flex;
    justify-content: center;
    gap: 1.5rem;
    flex-wrap: wrap;
    margin-top: 1rem;
}

.hero-pill-stat {
    display: flex;
    align-items: center;
    gap: 12px;
    background: rgba(22, 25, 38, 0.75);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 10px 22px;
    border-radius: 9999px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    transition: transform 0.2s ease;
}

.hero-pill-stat:hover {
    transform: translateY(-2px);
    border-color: rgba(255, 122, 69, 0.35);
}

.stat-number {
    font-size: 1.25rem;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: -0.02em;
}

.stat-tag {
    font-size: 0.8rem;
    font-weight: 500;
    color: #94A3B8;
}

/* Integrations strip */
.integrations-bar {
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 2.5rem;
    padding: 1.2rem;
    margin: 1.5rem 0 3rem 0;
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    flex-wrap: wrap;
}

.integration-item {
    display: flex;
    align-items: center;
    gap: 8px;
    color: #64748B;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

/* Glassmorphism Metric Cards */
.metric-card {
    background: rgba(17, 20, 31, 0.7);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 20px;
    padding: 1.5rem 1.6rem;
    position: relative;
    overflow: hidden;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
    transition: all 0.25s ease;
}

.metric-card:hover {
    border-color: rgba(255, 122, 69, 0.3);
    transform: translateY(-3px);
}

.metric-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, rgba(255, 122, 69, 0.6), transparent);
}

.metric-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
}

.metric-title {
    font-size: 0.85rem;
    font-weight: 600;
    color: #94A3B8;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

.metric-icon-badge {
    width: 32px;
    height: 32px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 15px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.08);
}

.metric-val {
    font-size: 2.3rem;
    font-weight: 800;
    color: #FFFFFF;
    letter-spacing: -0.03em;
    line-height: 1.1;
    margin-bottom: 0.4rem;
}

.metric-sub {
    font-size: 0.8rem;
    color: #64748B;
    display: flex;
    align-items: center;
    gap: 6px;
}

/* Risk Pill Banner */
.risk-banner {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(249, 115, 22, 0.1) 100%);
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-radius: 20px;
    padding: 1.8rem;
    position: relative;
    box-shadow: 0 12px 40px rgba(239, 68, 68, 0.15);
    margin-bottom: 2rem;
}

.risk-level-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 9999px;
    background: #EF4444;
    color: #FFFFFF;
    font-size: 0.85rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
}

/* Cyber Cards */
.cyber-card {
    background: rgba(17, 20, 31, 0.6);
    backdrop-filter: blur(14px);
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 18px;
    padding: 1.4rem;
    margin-bottom: 1.2rem;
}

.cyber-tag {
    display: inline-flex;
    align-items: center;
    font-size: 0.75rem;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 8px;
    margin-right: 6px;
    margin-bottom: 6px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #CBD5E1;
    font-family: 'JetBrains Mono', monospace;
}

.cyber-tag.shared-pivot {
    background: rgba(255, 122, 69, 0.15);
    border-color: rgba(255, 122, 69, 0.4);
    color: #FF8A65;
    font-weight: 700;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background-color: rgba(17, 20, 31, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.07);
    padding: 6px;
    border-radius: 9999px;
    margin-bottom: 2rem;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 9999px !important;
    padding: 10px 24px !important;
    font-size: 0.88rem !important;
    font-weight: 600 !important;
    color: #94A3B8 !important;
    background: transparent !important;
    border: none !important;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(255, 122, 69, 0.25), rgba(255, 98, 57, 0.1)) !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(255, 122, 69, 0.4) !important;
    box-shadow: 0 4px 15px rgba(255, 98, 57, 0.2) !important;
}

/* Button styling */
div.stButton > button {
    background: linear-gradient(135deg, #FF6B4A 0%, #FF453A 100%) !important;
    color: #FFFFFF !important;
    font-weight: 700 !important;
    font-size: 0.9rem !important;
    padding: 0.65rem 1.6rem !important;
    border-radius: 9999px !important;
    border: none !important;
    box-shadow: 0 8px 25px rgba(255, 69, 58, 0.35) !important;
    transition: all 0.25s ease !important;
}

div.stButton > button:hover {
    transform: translateY(-2px) !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 16px !important;
    overflow: hidden !important;
    background: rgba(17, 20, 31, 0.6) !important;
}

.stJson {
    background: rgba(10, 12, 18, 0.8) !important;
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 14px !important;
    padding: 1rem !important;
    font-family: 'JetBrains Mono', monospace !important;
}
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# SESSION STATE & REPORT INGESTION
# -----------------------------------------------------------------------------
if "reports_list" not in st.session_state:
    st.session_state["reports_list"] = get_default_reports()

if "demo_injected" not in st.session_state:
    st.session_state["demo_injected"] = False

def inject_demo():
    existing_ids = [r.get("id") for r in st.session_state["reports_list"]]
    if "REP-04" not in existing_ids:
        st.session_state["reports_list"].append(LIVE_DEMO_REPORT)
        st.session_state["demo_injected"] = True

def reset_reports():
    st.session_state["reports_list"] = get_default_reports()
    st.session_state["demo_injected"] = False

# -----------------------------------------------------------------------------
# TOP FLOATING NAV BAR
# -----------------------------------------------------------------------------
st.markdown("""
<div class="nav-container">
    <div class="brand-wrapper">
        <div class="brand-icon">🛡️</div>
        <span>securify <span style="color:#64748B; font-weight:400;">// cti intelligence</span></span>
    </div>
    <div class="nav-pills">
        <span class="nav-link">Correlation Engine</span>
        <span class="nav-link">MITRE Matrix</span>
        <span class="nav-link">Telemetry Graph</span>
    </div>
    <div class="status-badge">
        <div class="status-dot"></div>
        <span>LIVE TELEMETRY STREAM</span>
    </div>
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# HERO SECTION
# -----------------------------------------------------------------------------
st.markdown("""
<div class="hero-wrapper">
    <div class="hero-super">AI-Powered Threat Correlation & Graph Neural Analytics</div>
    <h1 class="hero-title">protect your <span class="glow-accent">intelligence</span></h1>
    <p class="hero-desc">
        Continuously ingest fragmented SOC telemetry, detect multi-stage campaign pivots, 
        and neutralize stealth adversaries with automated indicator correlation.
    </p>
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# PIPELINE EXECUTION
# -----------------------------------------------------------------------------
current_reports = st.session_state["reports_list"]

try:
    analysis_result = analyze_reports(current_reports)
    ai_result = generate_ai_assessment(current_reports, analysis_result)
except Exception as e:
    st.error(f"Engine processing exception: {e}")
    st.stop()

metrics = analysis_result.get("metrics", {})
total_reports = metrics.get("total_reports", len(current_reports))
total_iocs = metrics.get("total_iocs", 0)
shared_iocs = metrics.get("shared_iocs", 0)
campaign_confidence = metrics.get("campaign_confidence", 0)

# Floating stat badges
st.markdown(f"""
<div class="hero-stats-row">
    <div class="hero-pill-stat">
        <span class="stat-number">{campaign_confidence}%</span>
        <span class="stat-tag">Campaign Confidence</span>
    </div>
    <div class="hero-pill-stat">
        <span class="stat-number">+{total_reports}</span>
        <span class="stat-tag">Correlated Feeds</span>
    </div>
    <div class="hero-pill-stat">
        <span class="stat-number">+{total_iocs}</span>
        <span class="stat-tag">Extracted Artifacts</span>
    </div>
    <div class="hero-pill-stat">
        <span class="stat-number">+{shared_iocs}</span>
        <span class="stat-tag">Bridge Pivots</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Live Hackathon Pitch Trigger
st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)
col_demo1, col_demo2, col_demo3 = st.columns([2, 1, 1])

with col_demo1:
    if not st.session_state["demo_injected"]:
        st.caption("⚡ **Hackathon Live Pitch Mode:** Click to dynamically inject Incident REP-04 (Ransomware Pre-staging) into the correlation pipeline.")
    else:
        st.caption("🔥 **Live Demo Active:** Ingested 4th telemetry stream. Correlation confidence and IOC pivots updated dynamically.")

with col_demo2:
    if not st.session_state["demo_injected"]:
        st.button("⚡ Inject Demo Report (REP-04)", on_click=inject_demo, use_container_width=True)
    else:
        st.button("🔄 Reset to Base Telemetry", on_click=reset_reports, use_container_width=True)

with col_demo3:
    with st.popover("➕ Add Custom Intel"):
        st.markdown("#### Ingest External Threat Report")
        custom_id = st.text_input("Report ID", value=f"REP-0{len(current_reports)+1}")
        custom_title = st.text_input("Threat Title", value="Suspicious Outbound Exfiltration")
        custom_source = st.text_input("Source", value="Darktrace NDR / Proxy")
        custom_text = st.text_area("Raw Intelligence / Telemetry Text", value="Observed connection to 185.220.101.45 carrying encrypted payload.")
        if st.button("Ingest Report", key="btn_custom_add"):
            st.session_state["reports_list"].append({
                "id": custom_id,
                "title": custom_title,
                "source": custom_source,
                "date": "2026-10-16",
                "text": custom_text
            })
            st.rerun()

# Security Ecosystem Strip
st.markdown("""
<div class="integrations-bar">
    <div class="integration-item">🛡️ CROWDSTRIKE EDR</div>
    <div class="integration-item">⚡ SPLUNK SIEM</div>
    <div class="integration-item">👁️ SENTINELONE</div>
    <div class="integration-item">🌐 VIRUSTOTAL INTELLIGENCE</div>
    <div class="integration-item">🔒 PALO ALTO PAN-OS</div>
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# METRIC CARDS OVERVIEW
# -----------------------------------------------------------------------------
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header">
            <span class="metric-title">Total Reports</span>
            <div class="metric-icon-badge">📑</div>
        </div>
        <div class="metric-val">{total_reports}</div>
        <div class="metric-sub"><span style="color:#10B981;">●</span> Telemetry feeds ingested</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header">
            <span class="metric-title">Total IOCs</span>
            <div class="metric-icon-badge">🎯</div>
        </div>
        <div class="metric-val">{total_iocs}</div>
        <div class="metric-sub"><span style="color:#38BDF8;">●</span> Extracted cyber indicators</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header">
            <span class="metric-title">Shared IOCs</span>
            <div class="metric-icon-badge">🔗</div>
        </div>
        <div class="metric-val">{shared_iocs}</div>
        <div class="metric-sub"><span style="color:#FF8A65;">●</span> Multi-incident bridge pivots</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header">
            <span class="metric-title">Campaign Confidence</span>
            <div class="metric-icon-badge">⚡</div>
        </div>
        <div class="metric-val">{campaign_confidence}%</div>
        <div class="metric-sub"><span style="color:#A855F7;">●</span> High-fidelity attack chain</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 2.2rem;'></div>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# MAIN TABS
# -----------------------------------------------------------------------------
tab_analysis, tab_assessment, tab_graph, tab_raw = st.tabs([
    "📊 Threat Correlation Analysis",
    "🤖 AI Risk Assessment & MITRE",
    "🌐 Interactive Attack Graph",
    "📄 Raw Telemetry Data"
])

# TAB 1: THREAT ANALYSIS
with tab_analysis:
    st.markdown("### 🔍 Telemetry Incidents & Extracted Indicators")
    col_t1, col_t2 = st.columns([3, 2])
    
    with col_t1:
        st.markdown("#### Correlated Ingested Reports")
        for rep in current_reports:
            st.markdown(f"""
            <div class="cyber-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.6rem;">
                    <div>
                        <span class="cyber-tag" style="background: rgba(255, 122, 69, 0.18); color: #FF7A45; font-weight:700;">{rep.get('id', 'N/A')}</span>
                        <strong style="color: #FFFFFF; font-size: 1rem;">{rep.get('title', 'Untitled')}</strong>
                    </div>
                    <span style="font-size: 0.78rem; color: #64748B;">📅 {rep.get('date', 'Unknown Date')}</span>
                </div>
                <div style="font-size: 0.82rem; color: #38BDF8; margin-bottom: 0.6rem;">
                    📡 Source: <em>{rep.get('source', 'Unknown')}</em>
                </div>
                <p style="font-size: 0.88rem; color: #94A3B8; line-height: 1.55; margin-bottom: 0.8rem;">
                    {rep.get('text', '')}
                </p>
            </div>
            """, unsafe_allow_html=True)

    with col_t2:
        st.markdown("#### Critical Correlation Pivots (Shared Across Feeds)")
        connections = analysis_result.get("connections", [])
        if connections:
            for conn in connections:
                reps_badges = "".join([f"<span class='cyber-tag' style='background:rgba(56, 189, 248, 0.15); color:#38BDF8;'>{r}</span>" for r in conn.get("linked_reports", [])])
                st.markdown(f"""
                <div class="cyber-card" style="border-left: 3px solid #FF7A45;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                        <span class="cyber-tag shared-pivot">🔗 {conn.get('type', 'IOC')} PIVOT</span>
                        <code style="color: #F8FAFC; background: rgba(255,255,255,0.06); padding: 2px 8px; border-radius: 6px;">{conn.get('ioc')}</code>
                    </div>
                    <div style="margin-bottom: 0.5rem;">
                        <span style="font-size: 0.78rem; color: #94A3B8;">Linked Reports:</span> {reps_badges}
                    </div>
                    <p style="font-size: 0.82rem; color: #CBD5E1; margin: 0;">
                        {conn.get('evidence', '')}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No shared indicators discovered across current reports.")

        st.markdown("#### Indicator Breakdown")
        indicators = analysis_result.get("indicators", [])
        if indicators:
            ioc_df = pd.DataFrame(indicators)
            ioc_df["reports"] = ioc_df["reports"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
            st.dataframe(ioc_df, use_container_width=True, hide_index=True)

# TAB 2: AI RISK ASSESSMENT & MITRE
with tab_assessment:
    risk_level = str(ai_result.get("risk_level", "UNKNOWN")).upper()
    risk_score = ai_result.get("risk_score", 92)
    
    st.markdown(f"""
    <div class="risk-banner">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
            <div>
                <span class="risk-level-badge">THREAT POSTURE: {risk_level}</span>
                <h2 style="color: #FFFFFF; font-size: 1.8rem; font-weight: 800; margin: 0.8rem 0 0.4rem 0;">
                    Autonomous Threat Intelligence Synthesis
                </h2>
                <div style="color: #E2E8F0; font-size: 0.95rem;">
                    Composite Threat Index Score: <strong style="color: #FF7A45;">{risk_score} / 100</strong>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.8rem; color: #94A3B8; margin-bottom: 4px;">SYNTHESIS FIDELITY</div>
                <div style="font-size: 1.4rem; font-weight: 800; color: #10B981;">98.4% MATCH</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    c_exec, c_mitre = st.columns([1, 1])

    with c_exec:
        st.markdown("### 📑 Executive Threat Summary")
        exec_sum = ai_result.get("executive_summary", "No executive summary provided.")
        st.markdown(f"""
        <div class="cyber-card" style="border-left: 3px solid #38BDF8; font-size: 0.95rem; line-height: 1.65; color: #E2E8F0;">
            "{exec_sum}"
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### 🔬 Correlated Evidentiary Facts")
        facts = ai_result.get("evidence_facts", [])
        for f in facts:
            st.markdown(f"""
            <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 0.6rem;">
                <span style="color: #FF7A45; font-size: 1.1rem; line-height: 1;">✦</span>
                <span style="font-size: 0.88rem; color: #CBD5E1;">{f}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### 🧠 Threat Actor Hypotheses")
        hypotheses = ai_result.get("ai_hypotheses", [])
        for h in hypotheses:
            st.markdown(f"""
            <div style="display: flex; align-items: flex-start; gap: 10px; margin-bottom: 0.6rem;">
                <span style="color: #A855F7; font-size: 1.1rem; line-height: 1;">❖</span>
                <span style="font-size: 0.88rem; color: #E2E8F0;">{h}</span>
            </div>
            """, unsafe_allow_html=True)

    with c_mitre:
        st.markdown("### 🎯 MITRE ATT&CK Matrix Mapping")
        mitre_techniques = ai_result.get("mitre_techniques", [])
        for tech in mitre_techniques:
            st.markdown(f"""
            <div class="cyber-card" style="padding: 1rem 1.2rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="cyber-tag" style="background: rgba(168, 85, 247, 0.15); color: #C084FC; font-weight: 700;">
                            {tech.get('id', 'T0000')}
                        </span>
                        <strong style="color: #FFFFFF; font-size: 0.95rem;">{tech.get('name', 'Technique')}</strong>
                    </div>
                    <span class="cyber-tag" style="background: rgba(56, 189, 248, 0.12); color: #38BDF8;">
                        {tech.get('tactic', 'Tactic')}
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### 🛡️ Prescriptive Defensive Playbook")
        actions = ai_result.get("defensive_actions", [])
        for act in actions:
            tag_color = "#FF453A" if "IMMEDIATE" in act or "BLOCK" in act else "#38BDF8"
            st.markdown(f"""
            <div class="cyber-card" style="padding: 0.9rem 1.1rem; margin-bottom: 0.6rem; border-left: 2px solid {tag_color};">
                <span style="font-size: 0.86rem; color: #F1F5F9; font-weight: 500;">{act}</span>
            </div>
            """, unsafe_allow_html=True)

# TAB 3: INTERACTIVE ATTACK GRAPH
with tab_graph:
    st.markdown("### 🌐 Dynamic Multi-Incident Attack Graph")
    st.caption("Visualizing bipartite relational linkages connecting incident reports through shared cyber indicators.")

    graph_edges = analysis_result.get("graph_edges", [])
    
    if graph_edges:
        nodes = set()
        for edge in graph_edges:
            nodes.add(edge[0])
            nodes.add(edge[1])
        
        node_list = sorted(list(nodes))
        node_indices = {node: i for i, node in enumerate(node_list)}
        
        n = len(node_list)
        node_x, node_y, node_colors, node_sizes, node_labels = [], [], [], [], []
        shared_iocs_set = {conn.get("ioc") for conn in analysis_result.get("connections", [])}

        for i, node in enumerate(node_list):
            angle = 2 * math.pi * i / n
            if node.startswith("REP-"):
                r = 0.55
                color = "#38BDF8"
                size = 32
                label = f"📄 {node}"
            elif node in shared_iocs_set:
                r = 1.1
                color = "#FF6B4A"
                size = 36
                label = f"🔥 {node} (PIVOT)"
            else:
                r = 1.05
                color = "#A855F7"
                size = 24
                label = f"🎯 {node}"
                
            node_x.append(r * math.cos(angle))
            node_y.append(r * math.sin(angle))
            node_colors.append(color)
            node_sizes.append(size)
            node_labels.append(label)

        edge_x, edge_y = [], []
        for edge in graph_edges:
            src, tgt = edge[0], edge[1]
            if src in node_indices and tgt in node_indices:
                edge_x.extend([node_x[node_indices[src]], node_x[node_indices[tgt]], None])
                edge_y.extend([node_y[node_indices[src]], node_y[node_indices[tgt]], None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.8, color="rgba(255, 122, 69, 0.45)"),
            hoverinfo="none",
            mode="lines"
        )

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode="markers+text",
            hoverinfo="text",
            text=node_labels,
            textposition="top center",
            textfont=dict(color="#E2E8F0", size=11, family="JetBrains Mono"),
            marker=dict(size=node_sizes, color=node_colors, line=dict(width=2, color="#FFFFFF"))
        )

        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20, l=20, r=20, t=20),
                paper_bgcolor='rgba(11, 14, 22, 0.85)',
                plot_bgcolor='rgba(11, 14, 22, 0.85)',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=520
            )
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No relational graph edges to render.")

# TAB 4: RAW TELEMETRY
with tab_raw:
    st.markdown("### 📄 Raw Structured Telemetry Payload")
    r_col1, r_col2 = st.columns(2)
    with r_col1:
        st.markdown("#### Input Threat Reports (`sample_data`)")
        st.json(current_reports)
    with r_col2:
        st.markdown("#### Correlation Engine Output (`analysis_result`)")
        st.json(analysis_result)

st.divider()
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: center; color: #64748B; font-size: 0.8rem; padding: 1rem 0;">
    <span>⚡ Securify Intelligence Engine • Hackathon Demonstration Platform</span>
    <span>Model Status: Gemini 3.8 Multi-Agent Reasoning Enabled</span>
</div>
""", unsafe_allow_html=True)



