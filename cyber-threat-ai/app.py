# Cyber Threat Intelligence Dashboard

import streamlit as st
import pandas as pd
import json
import math
import plotly.graph_objects as go

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION (MUST BE THE FIRST STREAMLIT COMMAND!)
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
                "report_id": "REP-01",
                "title": "Spearphishing Campaign Targeting Finance Personnel",
                "source": "Internal SOC Email Gateway",
                "date": "2026-10-14",
                "text": "Finance department received urgent password-reset emails spoofing IT pointing to hxxps://auth-update-portal[.]com/sso/login. Stage-1 loader fetched from 185.220.101[.]45."
            },
            {
                "id": "REP-02",
                "report_id": "REP-02",
                "title": "Perimeter Web Server Exploitation & Outbound C2",
                "source": "Perimeter Firewall & IDS Logs",
                "date": "2026-10-15",
                "text": "IDS alerts flagged active exploitation of CVE-2024-21412. Server established outbound C2 beaconing to 185.220.101.45 every 60s. Dropped payload MD5 44d88612fea8a8f36de82e1278abb02f."
            },
            {
                "id": "REP-03",
                "report_id": "REP-03",
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
        "report_id": "REP-04",
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
    from ai_engine import generate_ai_assessment, validate_ai_output
except ImportError:
    validate_ai_output = None
    def generate_ai_assessment(reps, analysis):
        return {
            "risk_level": "CRITICAL",
            "risk_score": 96,
            "executive_summary": "CRITICAL-risk coordinated APT campaign detected across telemetry sources. Multi-stage attack chain combines credential theft, remote code exploitation, and persistent C2 beaconing with imminent ransomware detonation danger.",
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
    font-family: 'Jet
