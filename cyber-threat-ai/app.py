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


