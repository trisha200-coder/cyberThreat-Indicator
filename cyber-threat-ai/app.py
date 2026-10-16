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
# Cyber Threat Intelligence Dashboard

import streamlit as st
import pandas as pd

from sample_data import get_default_reports
from analyzer import analyze_reports
from ai_engine import generate_ai_assessment

st.set_page_config(
    page_title="Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Cyber Threat Intelligence Dashboard")
st.caption("AI-powered threat correlation and indicator analysis")

try:
    reports = get_default_reports()
    analysis_result = analyze_reports(reports)
    ai_result = generate_ai_assessment(reports, analysis_result)

except Exception as e:
    st.error(f"Could not load the team modules: {e}")
    st.info(
        "Check the function names and arguments in "
        "sample_data.py, analyzer.py, and ai_engine.py."
    )
    st.stop()

metrics = analysis_result.get("metrics", {})

st.header("Threat Overview")
c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Reports", metrics.get("total_reports", len(reports)))
c2.metric("Total IOCs", metrics.get("total_iocs", 0))
c3.metric("Shared IOCs", metrics.get("shared_iocs", 0))
c4.metric(
    "Campaign Confidence",
    f"{metrics.get('campaign_confidence', 0)}%"
)

overview, assessment, raw = st.tabs([
    "📊 Analysis",
    "🤖 AI Assessment",
    "📄 Raw Data"
])

with overview:
    st.subheader("Threat Reports")

    if reports:
        st.dataframe(
            pd.json_normalize(reports),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.warning("No reports were returned.")

    st.subheader("Analysis Output")
    st.json(analysis_result)

with assessment:
    st.subheader("AI Risk Assessment")

    st.metric(
        "Risk Level",
        str(ai_result.get("risk_level", "Unknown")).upper()
    )

    st.markdown("### Executive Summary")
    st.write(
        ai_result.get(
            "executive_summary",
            "No executive summary was provided."
        )
    )

    st.markdown("### Full Assessment")
    st.json(ai_result)

with raw:
    st.json(reports)

st.divider()
st.caption("Hackathon demonstration using project-provided data.")


