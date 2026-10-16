from sample_data import get_default_reports, get_live_demo_text
from analyzer import analyze_reports
from ai_engine import generate_ai_assessment

reports = get_default_reports()
analysis_result = analyze_reports(reports)
ai_result = generate_ai_assessment(reports, analysis_result)

import streamlit as st
import pandas as pd
import plotly.express as px

from sample_data import get_default_reports
from analyzer import analyze_reports
from ai_engine import generate_ai_assessment

st.set_page_config(
    page_title="Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Powered Cyber Threat Intelligence")
st.caption("Threat correlation | IOC analysis | AI risk assessment")

# Load and analyze the team's sample data
try:
    reports = get_default_reports()
    analysis_result = analyze_reports(reports)
    ai_result = generate_ai_assessment(reports, analysis_result)

    st.success("Threat intelligence data loaded successfully")

except Exception as e:
    st.error("Integration error: " + str(e))
    st.info(
        "Check that sample_data.py, analyzer.py, and "
        "ai_engine.py contain the expected functions."
    )
    st.stop()

# Overview metrics
st.header("📊 Threat Overview")

metrics = analysis_result.get("metrics", {})

col1, col2, col3, col4 = st.columns(4)

col1.metric("Threat Reports", metrics.get("total_reports", len(reports)))
col2.metric("Indicators (IOCs)", metrics.get("total_iocs", 0))
col3.metric("Shared Indicators", metrics.get("shared_iocs", 0))
col4.metric("Campaign Confidence", f'{metrics.get("campaign_confidence", 0)}%')

st.divider()

# Main dashboard sections
overview_tab, indicators_tab, ai_tab, raw_tab = st.tabs([
    "📈 Overview",
    "🔎 Indicators",
    "🤖 AI Assessment",
    "📄 Raw Reports"
])

with overview_tab:
    st.subheader("Threat Report Overview")

    st.write("Reports analyzed:", len(reports))

    if isinstance(reports, list) and reports:
        st.dataframe(
            pd.json_normalize(reports),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No report records are available to display.")

    st.subheader("Analysis Results")
    st.json(analysis_result)

with indicators_tab:
    st.subheader("Indicators of Compromise")

    # Look for common IOC field names in report dictionaries
    ioc_rows = []

    if isinstance(reports, list):
        for report in reports:
            if not isinstance(report, dict):
                continue

            for key in ("iocs", "indicators", "indicators_of_compromise"):
                values = report.get(key, [])
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, dict):
                            ioc_rows.append(value)
                        else:
                            ioc_rows.append({
                                "indicator": str(value),
                                "source": report.get("title", "Unknown report")
                            })

    if ioc_rows:
        ioc_df = pd.json_normalize(ioc_rows)
        st.dataframe(ioc_df, use_container_width=True, hide_index=True)
        st.download_button(
            "Download IOC data as CSV",
            ioc_df.to_csv(index=False),
            file_name="threat_indicators.csv",
            mime="text/csv"
        )
    else:
        st.info(
            "IOC fields were not found in the sample reports. "
            "Check the report structure in sample_data.py."
        )

with ai_tab:
    st.subheader("🤖 AI Threat Assessment")

    risk = ai_result.get("risk_level", "Unknown")
    st.metric("Risk Level", str(risk).upper())

    summary = ai_result.get("executive_summary", "")
    if summary:
        st.markdown("### Executive Summary")
        st.write(summary)

    st.markdown("### Full AI Assessment")
    st.json(ai_result)

with raw_tab:
    st.subheader("Raw Threat Data")
    st.json(reports)

st.divider()
st.caption(
    "Hackathon demo — verify findings against trusted sources "
    "before using them for operational security decisions."
)


