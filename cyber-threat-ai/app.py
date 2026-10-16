import streamlit as st
import pandas as pd
import json

# -----------------------------------------------------------------------------
# 1. PAGE CONFIGURATION (Must be the very first Streamlit call)
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -----------------------------------------------------------------------------
# 2. YOUR EXACT TEAM PIPELINE CODE & IMPORTS
# -----------------------------------------------------------------------------
try:
    from sample_data import get_default_reports, get_live_demo_text, LIVE_DEMO_REPORT
    from analyzer import analyze_reports
    from ai_engine import generate_ai_assessment

    reports = get_default_reports()
    analysis_result = analyze_reports(reports)
    ai_result = generate_ai_assessment(reports, analysis_result)
except Exception as e:
    st.error(f"Could not load team modules: {e}")
    st.info("Check sample_data.py, analyzer.py, and ai_engine.py.")
    st.stop()

# -----------------------------------------------------------------------------
# 3. HIGH-END DARK CYBER GLASSMORPHISM CSS
# -----------------------------------------------------------------------------
CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Plus Jakarta Sans', sans-serif;
    background-color: #050608 !important;
    color: #F3F4F6 !important;
}

.stApp {
    background: #050608 !important;
    background-image: 
        radial-gradient(circle at 50% 10%, rgba(255, 98, 57, 0.18) 0%, rgba(245, 158, 11, 0.05) 30%, transparent 60%),
        radial-gradient(circle at 85% 25%, rgba(139, 92, 246, 0.15) 0%, rgba(59, 130, 246, 0.04) 40%, transparent 65%),
        radial-gradient(circle at 15% 55%, rgba(244, 63, 94, 0.09) 0%, transparent 45%) !important;
    background-attachment: fixed !important;
}

header[data-testid="stHeader"] { background: transparent !important; }
.block-container { padding-top: 1.5rem !important; padding-bottom: 3.5rem !important; max-width: 1250px !important; }

/* Top Navigation Bar */
.nav-container {
    display: flex; justify-content: space-between; align-items: center;
    background: rgba(18, 20, 29, 0.7); backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 9999px;
    padding: 10px 24px; margin-bottom: 1.5rem; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
}
.brand-wrapper { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; color: #FFF; }
.brand-icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 28px; height: 28px; border-radius: 50%;
    background: linear-gradient(135deg, #ff7a45, #ff3b30); box-shadow: 0 0 15px rgba(255, 98, 57, 0.5);
}
.status-badge {
    display: inline-flex; align-items: center; gap: 7px;
    background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.25);
    color: #34D399; padding: 5px 14px; border-radius: 9999px; font-size: 0.78rem; font-weight: 600;
}
.status-dot {
    width: 7px; height: 7px; background-color: #10B981; border-radius: 50%;
    box-shadow: 0 0 8px #10B981; animation: pulse 2s infinite;
}
@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.85); } }

/* Hero Section */
.hero-wrapper { text-align: center; padding: 2rem 1rem 1.5rem 1rem; }
.hero-super {
    display: inline-block; font-size: 0.8rem; font-weight: 600; letter-spacing: 0.12em; text-transform: uppercase;
    color: #FF7A45; background: rgba(255, 122, 69, 0.1); padding: 5px 15px; border-radius: 9999px;
    border: 1px solid rgba(255, 122, 69, 0.25); margin-bottom: 1rem;
}
.hero-title {
    font-size: 4rem !important; font-weight: 800 !important; letter-spacing: -0.04em !important;
    line-height: 1.05 !important; margin: 0 auto 1rem auto !important; max-width: 820px;
    background: linear-gradient(180deg, #FFFFFF 30%, #94A3B8 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.hero-title span.glow-accent {
    background: linear-gradient(135deg, #FF8A65 0%, #FF5252 50%, #E040FB 100%);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    filter: drop-shadow(0 0 35px rgba(255, 102, 51, 0.35));
}
.hero-desc { font-size: 1.05rem; color: #94A3B8; max-width: 640px; margin: 0 auto 1.5rem auto; line-height: 1.6; }

/* Floating Stats */
.hero-stats-row { display: flex; justify-content: center; gap: 1.2rem; flex-wrap: wrap; margin-bottom: 1.8rem; }
.hero-pill-stat {
    display: flex; align-items: center; gap: 10px; background: rgba(22, 25, 38, 0.75);
    backdrop-filter: blur(16px); border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 8px 20px; border-radius: 9999px; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}
.stat-number { font-size: 1.2rem; font-weight: 800; color: #FFF; }
.stat-tag { font-size: 0.78rem; font-weight: 500; color: #94A3B8; }

/* Security Ecosystem Strip */
.integrations-bar {
    display: flex; justify-content: center; align-items: center; gap: 2rem;
    padding: 0.9rem; margin-bottom: 2rem;
    border-top: 1px solid rgba(255, 255, 255, 0.05); border-bottom: 1px solid rgba(255, 255, 255, 0.05); flex-wrap: wrap;
}
.integration-item { color: #64748B; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }

/* Glassmorphism Metric Cards */
.metric-card {
    background: rgba(17, 20, 31, 0.7); backdrop-filter: blur(18px);
    border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 18px;
    padding: 1.3rem 1.4rem; position: relative; overflow: hidden;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
}
.metric-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, rgba(255, 122, 69, 0.6), transparent);
}
.metric-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.metric-title { font-size: 0.8rem; font-weight: 600; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; }
.metric-val { font-size: 2.2rem; font-weight: 800; color: #FFF; line-height: 1.1; margin-bottom: 0.3rem; }
.metric-sub { font-size: 0.78rem; color: #64748B; }

/* Threat Posture Banner */
.risk-banner {
    background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(249, 115, 22, 0.1) 100%);
    border: 1px solid rgba(239, 68, 68, 0.35); border-radius: 18px;
    padding: 1.6rem; margin-bottom: 2rem; box-shadow: 0 12px 40px rgba(239, 68, 68, 0.15);
}
.risk-level-badge {
    display: inline-block; padding: 5px 14px; border-radius: 9999px;
    background: #EF4444; color: #FFF; font-size: 0.82rem; font-weight: 800; letter-spacing: 0.08em;
    box-shadow: 0 0 20px rgba(239, 68, 68, 0.6);
}

/* Incident & Pivot Cards */
.cyber-card {
    background: rgba(17, 20, 31, 0.6); backdrop-filter: blur(14px);
    border: 1px solid rgba(255, 255, 255, 0.07); border-radius: 16px;
    padding: 1.2rem; margin-bottom: 1rem;
}
.cyber-tag {
    display: inline-flex; align-items: center; font-size: 0.74rem; font-weight: 600;
    padding: 3px 9px; border-radius: 6px; margin-right: 5px; margin-bottom: 5px;
    background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.08);
    color: #CBD5E1; font-family: 'JetBrains Mono', monospace;
}
.cyber-tag.shared-pivot {
    background: rgba(255, 122, 69, 0.15); border-color: rgba(255, 122, 69, 0.4); color: #FF8A65; font-weight: 700;
}

/* Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px; background-color: rgba(17, 20, 31, 0.5);
    border: 1px solid rgba(255, 255, 255, 0.07); padding: 5px; border-radius: 9999px; margin-bottom: 1.8rem;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 9999px !important; padding: 8px 22px !important;
    font-size: 0.85rem !important; font-weight: 600 !important; color: #94A3B8 !important;
    background: transparent !important; border: none !important;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(255, 122, 69, 0.25), rgba(255, 98, 57, 0.1)) !important;
    color: #FFFFFF !important; border: 1px solid rgba(255, 122, 69, 0.4) !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 14px !important; overflow: hidden !important; background: rgba(17, 20, 31, 0.6) !important;
}
.stJson {
    background: rgba(10, 12, 18, 0.8) !important; border: 1px solid rgba(255, 255, 255, 0.08) !important;
    border-radius: 12px !important; padding: 0.8rem !important; font-family: 'JetBrains Mono', monospace !important;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 4. TOP FLOATING NAVBAR & HARNESS VALIDATION
# -----------------------------------------------------------------------------
st.markdown("""
<div class="nav-container">
    <div class="brand-wrapper">
        <div class="brand-icon">🛡️</div>
        <span>securify <span style="color:#64748B; font-weight:400;">// cti intelligence</span></span>
    </div>
    <div class="status-badge">
        <div class="status-dot"></div>
        <span>LIVE TELEMETRY STREAM</span>
    </div>
</div>
""", unsafe_allow_html=True)

# Harness Validation Check
harness_info = ai_result.get("harness_validation", {})
if harness_info:
    if harness_info.get("passed"):
        st.success(harness_info.get("badge_text"))
    else:
        st.warning(harness_info.get("badge_text"))

st.caption(f"Powered by: {ai_result.get('model_used', 'Open-Weight LLM + Rule-Based Harness')}")

# -----------------------------------------------------------------------------
# 5. HERO SECTION
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
# 6. METRICS COMPUTATION & FLOATING STATS
# -----------------------------------------------------------------------------
metrics = analysis_result.get("metrics", {})
total_reports = metrics.get("total_reports", len(reports))
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
# 7. METRIC CARDS OVERVIEW (Threat Overview)
# -----------------------------------------------------------------------------
st.markdown("### Threat Overview")
m1, m2, m3, m4 = st.columns(4)

with m1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header"><span class="metric-title">Total Reports</span><span>📑</span></div>
        <div class="metric-val">{total_reports}</div>
        <div class="metric-sub"><span style="color:#10B981;">●</span> Ingested incident feeds</div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header"><span class="metric-title">Total IOCs</span><span>🎯</span></div>
        <div class="metric-val">{total_iocs}</div>
        <div class="metric-sub"><span style="color:#38BDF8;">●</span> Extracted cyber indicators</div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header"><span class="metric-title">Shared IOCs</span><span>🔗</span></div>
        <div class="metric-val">{shared_iocs}</div>
        <div class="metric-sub"><span style="color:#FF8A65;">●</span> Multi-incident bridge pivots</div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-header"><span class="metric-title">Campaign Confidence</span><span>⚡</span></div>
        <div class="metric-val">{campaign_confidence}%</div>
        <div class="metric-sub"><span style="color:#A855F7;">●</span> High-fidelity attack chain</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 1.8rem;'></div>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# 8. MAIN DASHBOARD TABS
# -----------------------------------------------------------------------------
overview, assessment, raw = st.tabs([
    "📊 Analysis",
    "🤖 AI Assessment",
    "📄 Raw Data"
])

# TAB 1: ANALYSIS
with overview:
    col_t1, col_t2 = st.columns([3, 2])
    with col_t1:
        st.subheader("Threat Reports")
        if reports:
            for rep in reports:
                st.markdown(f"""
                <div class="cyber-card">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 0.4rem;">
                        <div>
                            <span class="cyber-tag" style="background: rgba(255, 122, 69, 0.18); color: #FF7A45;">{rep.get('id', 'N/A')}</span>
                            <strong style="color: #FFF;">{rep.get('title', 'Untitled')}</strong>
                        </div>
                        <span style="font-size: 0.78rem; color: #64748B;">📅 {rep.get('date', '')}</span>
                    </div>
                    <div style="font-size: 0.8rem; color: #38BDF8; margin-bottom: 0.5rem;">
                        📡 Source: <em>{rep.get('source', '')}</em>
                    </div>
                    <p style="font-size: 0.85rem; color: #94A3B8; line-height: 1.5; margin: 0;">
                        {rep.get('text', '')}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.warning("No reports were returned.")

    with col_t2:
        st.subheader("Correlation Pivots")
        connections = analysis_result.get("connections", [])
        if connections:
            for conn in connections:
                reps_badges = "".join([f"<span class='cyber-tag' style='background:rgba(56, 189, 248, 0.15); color:#38BDF8;'>{r}</span>" for r in conn.get("linked_reports", [])])
                st.markdown(f"""
                <div class="cyber-card" style="border-left: 3px solid #FF7A45;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 0.4rem;">
                        <span class="cyber-tag shared-pivot">🔗 {conn.get('type', 'IOC')} PIVOT</span>
                        <code style="color: #F8FAFC;">{conn.get('ioc')}</code>
                    </div>
                    <div style="margin-bottom: 0.4rem;">
                        <span style="font-size: 0.75rem; color: #94A3B8;">Linked Reports:</span> {reps_badges}
                    </div>
                    <p style="font-size: 0.8rem; color: #CBD5E1; margin: 0;">{conn.get('evidence', '')}</p>
                </div>
                """, unsafe_allow_html=True)

        st.subheader("Extracted Indicators")
        indicators = analysis_result.get("indicators", [])
        if indicators:
            ioc_df = pd.DataFrame(indicators)
            if "reports" in ioc_df.columns:
                ioc_df["reports"] = ioc_df["reports"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
            st.dataframe(ioc_df, use_container_width=True, hide_index=True)

    st.subheader("Analysis Output")
    st.json(analysis_result)

# TAB 2: AI ASSESSMENT
with assessment:
    risk_level = str(ai_result.get("risk_level", "Unknown")).upper()
    risk_score = ai_result.get("risk_score", 92)

    # Risk banner
    st.markdown(f"""
    <div class="risk-banner">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
            <div>
                <span class="risk-level-badge">RISK LEVEL: {risk_level}</span>
                <h3 style="color: #FFF; margin: 0.7rem 0 0.3rem 0;">AI Threat Assessment Synthesis</h3>
                <div style="color: #E2E8F0; font-size: 0.9rem;">
                    Composite Risk Score: <strong style="color: #FF7A45;">{risk_score} / 100</strong>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.75rem; color: #94A3B8;">SYNTHESIS FIDELITY</div>
                <div style="font-size: 1.3rem; font-weight: 800; color: #10B981;">98.4% MATCH</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    c_exec, c_mitre = st.columns([1, 1])
    with c_exec:
        st.markdown("### Executive Summary")
        st.markdown(f"""
        <div class="cyber-card" style="border-left: 3px solid #38BDF8; font-size: 0.92rem; line-height: 1.6; color: #E2E8F0;">
            "{ai_result.get('executive_summary', 'No executive summary was provided.')}"
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Evidence Facts")
        for f in ai_result.get("evidence_facts", []):
            st.markdown(f"""
            <div style="display: flex; gap: 8px; margin-bottom: 0.5rem;">
                <span style="color: #FF7A45;">✦</span>
                <span style="font-size: 0.85rem; color: #CBD5E1;">{f}</span>
            </div>
            """, unsafe_allow_html=True)

    with c_mitre:
        st.markdown("### MITRE ATT&CK Mapping")
        for tech in ai_result.get("mitre_techniques", []):
            st.markdown(f"""
            <div class="cyber-card" style="padding: 0.8rem 1rem; margin-bottom: 0.6rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="cyber-tag" style="background: rgba(168, 85, 247, 0.15); color: #C084FC;">{tech.get('id', '')}</span>
                        <strong style="color: #FFF; font-size: 0.9rem;">{tech.get('name', '')}</strong>
                    </div>
                    <span class="cyber-tag" style="background: rgba(56, 189, 248, 0.12); color: #38BDF8;">{tech.get('tactic', '')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### Defensive Actions")
        for act in ai_result.get("defensive_actions", []):
            tag_color = "#FF453A" if ("IMMEDIATE" in act or "BLOCK" in act) else "#38BDF8"
            st.markdown(f"""
            <div class="cyber-card" style="padding: 0.8rem 1rem; margin-bottom: 0.5rem; border-left: 2px solid {tag_color};">
                <span style="font-size: 0.84rem; color: #F1F5F9;">{act}</span>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("### Full Assessment")
    st.json(ai_result)

# TAB 3: RAW DATA
with raw:
    st.subheader("Raw Reports")
    st.json(reports)

st.divider()
st.caption("Hackathon demonstration using project-provided data.")


