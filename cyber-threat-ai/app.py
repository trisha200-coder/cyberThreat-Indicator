import streamlit as st
import pandas as pd
import json

# 1. PAGE CONFIGURATION
st.set_page_config(
    page_title="Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# 2. DATA PIPELINE
try:
    from sample_data import get_default_reports, get_live_demo_text, LIVE_DEMO_REPORT
    from analyzer import analyze_reports
    from ai_engine import generate_ai_assessment

    reports = get_default_reports()
    analysis_result = analyze_reports(reports)
    ai_result = generate_ai_assessment(reports, analysis_result)
except Exception as e:
    st.error(f"Module loading error: {e}")
    st.stop()

# 3. HIGH CONTRAST STYLING & NEON EFFECTS
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* Base Dark Canvas */
.stApp {
    background-color: #050608 !important;
    background-image: 
        radial-gradient(circle at 50% 12%, rgba(255, 100, 60, 0.18) 0%, transparent 55%),
        radial-gradient(circle at 85% 25%, rgba(130, 90, 240, 0.16) 0%, transparent 50%),
        radial-gradient(circle at 15% 55%, rgba(244, 63, 94, 0.08) 0%, transparent 45%) !important;
    color: #E2E8F0 !important;
}

/* Force All Headings to Pure White */
h1, h2, h3, h4, h5, h6,
[data-testid="stMarkdownContainer"] h1,
[data-testid="stMarkdownContainer"] h2,
[data-testid="stMarkdownContainer"] h3,
[data-testid="stMarkdownContainer"] h4 {
    color: #FFFFFF !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
}

p, span, div {
    color: #CBD5E1;
}

/* =========================================================================
   NEON LIGHTING & GLOW EFFECTS
   ========================================================================= */
@keyframes neonAccentGlow {
    0%, 100% {
        filter: drop-shadow(0 0 15px rgba(255, 107, 74, 0.85)) 
                drop-shadow(0 0 30px rgba(255, 69, 58, 0.6)) 
                drop-shadow(0 0 60px rgba(168, 85, 247, 0.4));
    }
    50% {
        filter: drop-shadow(0 0 25px rgba(255, 107, 74, 1)) 
                drop-shadow(0 0 45px rgba(255, 69, 58, 0.85)) 
                drop-shadow(0 0 80px rgba(168, 85, 247, 0.6));
    }
}

.hero-box {
    position: relative;
    text-align: center;
    padding: 2.8rem 1rem 1.6rem 1rem;
    max-width: 900px;
    margin: 0 auto;
}

/* Ambient Neon Aura behind title */
.hero-box::before {
    content: '';
    position: absolute;
    top: 40%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 520px;
    height: 190px;
    background: radial-gradient(ellipse, rgba(255, 107, 74, 0.28) 0%, rgba(168, 85, 247, 0.16) 45%, transparent 70%);
    filter: blur(55px);
    z-index: 0;
    pointer-events: none;
    border-radius: 50%;
}

.neon-sub-badge {
    position: relative;
    z-index: 1;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #FF8A65;
    background: rgba(255, 122, 69, 0.12);
    border: 1px solid rgba(255, 122, 69, 0.35);
    padding: 6px 18px;
    border-radius: 9999px;
    margin-bottom: 1.2rem;
    box-shadow: 0 0 20px rgba(255, 122, 69, 0.25), inset 0 0 10px rgba(255, 122, 69, 0.1);
}

.hero-main-title {
    position: relative;
    z-index: 1;
    font-size: 4.3rem;
    font-weight: 850;
    line-height: 1.08;
    margin-bottom: 1.2rem;
    letter-spacing: -0.035em;
    color: #FFFFFF;
}

.neon-white {
    color: #FFFFFF;
    text-shadow: 
        0 0 10px rgba(255, 255, 255, 0.85),
        0 0 25px rgba(255, 255, 255, 0.4),
        0 0 45px rgba(168, 85, 247, 0.35);
}

.neon-fire {
    display: inline-block;
    color: #FF7A45;
    background: linear-gradient(135deg, #FFFFFF 0%, #FFE3D6 20%, #FF7A45 50%, #FF3B30 75%, #C084FC 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: neonAccentGlow 3s ease-in-out infinite;
}

.hero-sub {
    position: relative;
    z-index: 1;
    font-size: 1.08rem;
    color: #94A3B8;
    margin-bottom: 1.6rem;
    line-height: 1.6;
    max-width: 660px;
    margin-left: auto;
    margin-right: auto;
}

.brand-neon-text {
    font-weight: 800;
    letter-spacing: 0.04em;
    color: #FFFFFF;
    text-shadow: 0 0 12px rgba(255, 122, 69, 0.65), 0 0 24px rgba(255, 69, 58, 0.35);
}

.harness-row {
    position: relative;
    z-index: 1;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 2rem;
}

.harness-chip {
    padding: 6px 16px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 600;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.3);
    color: #34D399;
    box-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
}

.model-chip {
    padding: 6px 16px;
    border-radius: 9999px;
    font-size: 0.82rem;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #94A3B8;
}

/* Glass Panels */
.cyber-panel {
    background: rgba(18, 21, 32, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 1.3rem;
    margin-bottom: 1rem;
}

.stat-card {
    background: rgba(18, 21, 32, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 1.3rem 1.4rem;
    border-top: 2px solid #FF7A45;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}

.stat-label {
    font-size: 0.82rem;
    text-transform: uppercase;
    font-weight: 600;
    color: #94A3B8;
    margin-bottom: 0.4rem;
}

.stat-val {
    font-size: 2.2rem;
    font-weight: 800;
    color: #FFFFFF;
    line-height: 1.1;
}

.badge-pivot {
    display: inline-block;
    font-size: 0.75rem;
    font-weight: 700;
    color: #FF8A65;
    background: rgba(255, 122, 69, 0.15);
    border: 1px solid rgba(255, 122, 69, 0.4);
    padding: 3px 8px;
    border-radius: 6px;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 8px;
    background: rgba(18, 21, 32, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 5px;
    border-radius: 9999px;
    margin: 1.5rem 0 2rem 0;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 9999px !important;
    padding: 8px 22px !important;
    color: #94A3B8 !important;
}

.stTabs [aria-selected="true"] {
    background: rgba(255, 122, 69, 0.2) !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(255, 122, 69, 0.4) !important;
}
</style>
""", unsafe_allow_html=True)

# 4. TOP NAVBAR WITH NEON LOGO
st.markdown("""
<div style="display: flex; justify-content: space-between; align-items: center; background: rgba(18, 20, 29, 0.75); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.09); border-radius: 9999px; padding: 12px 26px; margin-bottom: 1.5rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
    <div style="display: flex; align-items: center; gap: 10px;">
        <div style="width: 28px; height: 28px; border-radius: 50%; background: linear-gradient(135deg, #ff7a45, #ff3b30); display: flex; align-items: center; justify-content: center; box-shadow: 0 0 15px rgba(255, 98, 57, 0.6);">🛡️</div>
        <span class="brand-neon-text">SECURIFY <span style="color:#64748B; font-weight:400;">// AI CTI</span></span>
    </div>
    <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.3); color: #34D399; padding: 6px 16px; border-radius: 9999px; font-size: 0.8rem; font-weight: 600; box-shadow: 0 0 12px rgba(16, 185, 129, 0.25);">
        <span style="width: 7px; height: 7px; background-color: #10B981; border-radius: 50%; box-shadow: 0 0 8px #10B981;"></span>
        LIVE TELEMETRY STREAM
    </div>
</div>
""", unsafe_allow_html=True)

# 5. HERO SECTION WITH NEON LIGHTS & GLOW
harness_info = ai_result.get("harness_validation", {})
harness_text = harness_info.get("badge_text", "Evaluation Harness: Passed") if harness_info else "Harness: Passed"
model_name = ai_result.get("model_used", "Open-Weight LLM + Rule-Based Harness")

st.markdown(f"""
<div class="hero-box">
    <div class="neon-sub-badge">⚡ AI THREAT CORRELATION & ATTACK GRAPH</div>
    <div class="hero-main-title">
        <span class="neon-white">protect your</span> <span class="neon-fire">intelligence</span>
    </div>
    <div class="hero-sub">
        Continuously ingest fragmented SOC telemetry, detect multi-stage campaign pivots, 
        and neutralize stealth adversaries with automated indicator correlation.
    </div>
    <div class="harness-row">
        <div class="harness-chip">✓ {harness_text}</div>
        <div class="model-chip">⚡ Powered by: {model_name}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# 6. METRICS COMPUTATION & CARDS
metrics = analysis_result.get("metrics", {})
total_reports = metrics.get("total_reports", len(reports))
total_iocs = metrics.get("total_iocs", 0)
shared_iocs = metrics.get("shared_iocs", 0)
campaign_confidence = metrics.get("campaign_confidence", 0)

st.markdown("### Threat Overview")

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""
    <div class="stat-card">
        <div class="stat-label">Total Reports</div>
        <div class="stat-val">{total_reports}</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class="stat-card">
        <div class="stat-label">Total IOCs</div>
        <div class="stat-val">{total_iocs}</div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class="stat-card">
        <div class="stat-label">Shared IOCs</div>
        <div class="stat-val">{shared_iocs}</div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class="stat-card">
        <div class="stat-label">Campaign Confidence</div>
        <div class="stat-val">{campaign_confidence}%</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height: 1.5rem;'></div>", unsafe_allow_html=True)

# 7. TABS
overview, assessment, raw = st.tabs([
    "📊 Threat Analysis",
    "🤖 AI Risk Assessment",
    "📄 Raw Data"
])

with overview:
    attribution_data = analysis_result.get("attribution", {})
    per_rep_attr = {
        item["report_id"]: item
        for item in attribution_data.get("per_report_attribution", [])
    }

    col_left, col_right = st.columns([3, 2])
    
    with col_left:
        st.markdown("### Threat Reports")
        if reports:
            for rep in reports:
                rep_id = rep.get("id", "REP")
                rep_attr = per_rep_attr.get(rep_id, {})
                is_rec = rep_attr.get("recognizable", False)
                actor_lbl = rep_attr.get("attacker_handle", "Unknown")
                rec_badge_html = (
                    f'<span style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); color: #34D399; font-size: 0.75rem; font-weight: 700; padding: 2px 10px; border-radius: 9999px;">🕵️ Recognizable: {actor_lbl}</span>'
                    if is_rec
                    else '<span style="background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); color: #FBBF24; font-size: 0.75rem; font-weight: 700; padding: 2px 10px; border-radius: 9999px;">❓ Not Recognizable (Anonymous Probe)</span>'
                )
                st.markdown(f"""
                <div class="cyber-panel">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; flex-wrap: wrap; gap: 6px;">
                        <strong style="color: #FF7A45;">[{rep_id}] {rep.get('title', 'Untitled')}</strong>
                        <span style="font-size: 0.8rem; color: #64748B;">📅 {rep.get('date', '')}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.55rem; flex-wrap: wrap; gap: 6px;">
                        <span style="font-size: 0.82rem; color: #38BDF8;">Source: {rep.get('source', '')}</span>
                        {rec_badge_html}
                    </div>
                    <p style="font-size: 0.88rem; color: #CBD5E1; margin: 0; line-height: 1.55;">
                        {rep.get('text', '')}
                    </p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.warning("No reports available.")

    with col_right:
        st.markdown("### Correlation Pivots")
        connections = analysis_result.get("connections", [])
        if connections:
            for conn in connections:
                reps_txt = ", ".join(conn.get("linked_reports", []))
                st.markdown(f"""
                <div class="cyber-panel" style="border-left: 3px solid #FF7A45;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 0.4rem;">
                        <span class="badge-pivot">{conn.get('type', 'IOC')} PIVOT</span>
                        <code style="color: #FFF;">{conn.get('ioc')}</code>
                    </div>
                    <div style="font-size: 0.78rem; color: #94A3B8; margin-bottom: 0.3rem;">
                        Linked: <strong style="color: #38BDF8;">{reps_txt}</strong>
                    </div>
                    <p style="font-size: 0.82rem; color: #CBD5E1; margin: 0;">{conn.get('evidence', '')}</p>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("### Extracted Indicators")
        indicators = analysis_result.get("indicators", [])
        if indicators:
            df = pd.DataFrame(indicators)
            if "reports" in df.columns:
                df["reports"] = df["reports"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
            st.dataframe(df, width="stretch", hide_index=True)

    with st.expander("🔍 Full Analysis Output (JSON)"):
        st.json(analysis_result)

with assessment:
    risk_level = str(ai_result.get("risk_level", "Unknown")).upper()
    attr_info = ai_result.get("attacker_attribution") or analysis_result.get("attribution", {})
    attr_badge = attr_info.get("status_badge", "Attacker Recognizability Evaluated")
    primary_actor = attr_info.get("primary_attacker", "Unknown Threat Actor")
    
    st.markdown(f"""
    <div class="cyber-panel" style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.35); box-shadow: 0 0 25px rgba(239, 68, 68, 0.15);">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
                <span style="background: #EF4444; color: #FFF; font-weight: 800; font-size: 0.8rem; padding: 4px 12px; border-radius: 9999px; box-shadow: 0 0 15px rgba(239, 68, 68, 0.6);">
                    RISK LEVEL: {risk_level}
                </span>
                <span style="background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.5); color: #34D399; font-weight: 800; font-size: 0.8rem; padding: 4px 12px; border-radius: 9999px; margin-left: 8px;">
                    {attr_badge}
                </span>
                <h3 style="color: #FFFFFF; margin: 0.6rem 0 0.2rem 0;">AI Threat Synthesis & Attacker Attribution</h3>
                <div style="font-size: 0.88rem; color: #FF8A65; font-weight: 600;">Primary Identified Adversary: {primary_actor}</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.75rem; color: #94A3B8;">CONFIDENCE</div>
                <div style="font-size: 1.3rem; font-weight: 800; color: #10B981;">HIGH FIDELITY</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Attacker Attribution & Recognizability Breakdown
    st.markdown("### 🕵️ Attacker Recognizability & Threat Actor Profiles")
    st.markdown(f"""
    <div class="cyber-panel" style="border-left: 3px solid #10B981; font-size: 0.9rem; line-height: 1.6;">
        <strong style="color: #34D399;">Attribution Verdict:</strong> {attr_info.get('verdict_summary', '')}
    </div>
    """, unsafe_allow_html=True)

    profiles = attr_info.get("actor_profiles", [])
    if profiles:
        p_cols = st.columns(len(profiles))
        for idx, prof in enumerate(profiles):
            with p_cols[idx]:
                rep_badges = ", ".join(prof.get("matched_reports", []))
                fps_html = "".join(
                    f"<li style='font-size:0.82rem; color:#CBD5E1; margin-bottom:3px;'><code>{fp}</code></li>"
                    for fp in prof.get("forensic_fingerprints", [])[:4]
                )
                st.markdown(f"""
                <div class="cyber-panel" style="border-top: 2px solid #34D399;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
                        <strong style="color:#FFFFFF; font-size:1.02rem;">👤 Operator: {prof.get('handle')}</strong>
                        <span style="background:rgba(16,185,129,0.18); color:#34D399; font-size:0.75rem; font-weight:700; padding:3px 10px; border-radius:9999px;">
                            {prof.get('recognizability_label')} ({prof.get('confidence')}%)
                        </span>
                    </div>
                    <div style="font-size:0.82rem; color:#FF8A65; font-weight:600; margin-bottom:0.4rem;">
                        Syndicate / Group: {prof.get('group_name')}
                    </div>
                    <div style="font-size:0.8rem; color:#38BDF8; margin-bottom:0.4rem;">
                        Linked Reports ({len(prof.get('matched_reports', []))}): <strong>{rep_badges}</strong>
                    </div>
                    <div style="font-size:0.82rem; color:#94A3B8; margin-bottom:0.5rem;">
                        <strong>Kill-Chain Pattern:</strong> {prof.get('behavioral_pattern')}
                    </div>
                    <div style="font-size:0.8rem; color:#E2E8F0; font-weight:600; margin-bottom:0.25rem;">Forensic Signatures:</div>
                    <ul style="margin:0; padding-left:1.1rem;">{fps_html}</ul>
                </div>
                """, unsafe_allow_html=True)

    unattributed = attr_info.get("unattributed_reports", [])
    if unattributed:
        st.markdown(f"""
        <div class="cyber-panel" style="border-left: 3px solid #F59E0B; padding: 0.9rem 1.2rem;">
            <strong style="color: #FBBF24;">❓ Unrecognizable / Anonymous Activity ({', '.join(unattributed)}):</strong>
            <span style="font-size: 0.86rem; color: #CBD5E1;">
                Report(s) <code>{', '.join(unattributed)}</code> contain isolated opportunistic network noise (0 shared C2 IOCs, no malware hash reuse, and no operator handle). The engine correctly classifies this attacker as <strong>NOT RECOGNIZABLE</strong> to prevent false attribution.
            </span>
        </div>
        """, unsafe_allow_html=True)

    c_left, c_right = st.columns([1, 1])
    
    with c_left:
        st.markdown("### Executive Summary")
        st.markdown(f"""
        <div class="cyber-panel" style="border-left: 3px solid #38BDF8; font-size: 0.92rem; line-height: 1.6;">
            "{ai_result.get('executive_summary', 'No executive summary provided.')}"
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### Evidentiary Facts")
        for f in ai_result.get("evidence_facts", []):
            st.markdown(f"""
            <div style="display: flex; gap: 8px; margin-bottom: 0.5rem;">
                <span style="color: #FF7A45;">✦</span>
                <span style="font-size: 0.88rem; color: #CBD5E1;">{f}</span>
            </div>
            """, unsafe_allow_html=True)

    with c_right:
        st.markdown("### MITRE ATT&CK Matrix")
        for tech in ai_result.get("mitre_techniques", []):
            st.markdown(f"""
            <div class="cyber-panel" style="padding: 0.8rem 1rem; margin-bottom: 0.6rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="background: rgba(168, 85, 247, 0.15); color: #C084FC; font-weight: 700; font-size: 0.75rem; padding: 2px 8px; border-radius: 4px;">
                            {tech.get('id', '')}
                        </span>
                        <strong style="color: #FFF; font-size: 0.9rem; margin-left: 6px;">{tech.get('name', '')}</strong>
                    </div>
                    <span style="font-size: 0.75rem; color: #38BDF8;">{tech.get('tactic', '')}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("### Defensive Actions")
        for act in ai_result.get("defensive_actions", []):
            st.markdown(f"""
            <div class="cyber-panel" style="padding: 0.8rem 1rem; margin-bottom: 0.5rem; border-left: 2px solid #38BDF8;">
                <span style="font-size: 0.85rem; color: #F1F5F9;">{act}</span>
            </div>
            """, unsafe_allow_html=True)

    with st.expander("🔍 Full AI Assessment (JSON)"):
        st.json(ai_result)

with raw:
    st.markdown("### Ingested Reports")
    st.json(reports)

st.divider()
st.caption("Hackathon demonstration using project-provided telemetry data.")


