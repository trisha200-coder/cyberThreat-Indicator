

# =============================================================================
# SECTION 5 — HALLUCINATION GUARDRAIL  (Phase 3 judge-winning feature)
# =============================================================================

def validate_ai_output(ai_result: dict, valid_iocs: list[str]) -> dict:
    """
    Scan the AI's text output for IOC-like strings and check each one
    against the list of IOCs actually extracted by analyzer.py.

    Args:
        ai_result:  the dict returned by generate_ai_assessment()
        valid_iocs: list of IOC strings from analysis_result["indicators"]
                    e.g. ["185.220.101.45", "auth-update-portal.com", ...]

    Returns:
        {
          "passed":           True/False,
          "hallucinated_iocs": [...],  # IOCs the LLM invented
          "badge_text":       "✅ Hallucination Check Passed ..."
                              OR "⚠️ Hallucination Warning: ..."
        }
    """
    # Patterns that look like IOCs
    _ip_re     = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    _domain_re = re.compile(r'\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|gov|edu|ru|cn|info|xyz|top|site)\b', re.I)
    _cve_re    = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.I)
    _hash_re   = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)

    valid_lower = {v.lower() for v in valid_iocs}

    # Collect all text fields from the AI result
    text_fields = []
    for key in ("executive_summary", "evidence_facts", "ai_hypotheses", "defensive_actions"):
        val = ai_result.get(key, "")
        if isinstance(val, list):
            text_fields.extend(val)
        else:
            text_fields.append(str(val))

    combined_text = " ".join(text_fields)

    # Extract all IOC-like strings from the AI's output
    found_iocs = set()
    for pattern in (_ip_re, _domain_re, _cve_re, _hash_re):
        found_iocs.update(m.lower() for m in pattern.findall(combined_text))

    # Hallucinated = AI mentioned it but extractor never found it
    hallucinated = [ioc for ioc in found_iocs if ioc not in valid_lower]

    if not hallucinated:
        return {
            "passed": True,
            "hallucinated_iocs": [],
            "badge_text": (
                "✅ Hallucination Check Passed — "
                "All cited indicators verified against source reports."
            ),
        }
    else:
        return {
            "passed": False,
            "hallucinated_iocs": hallucinated,
            "badge_text": (
                f"⚠️ Hallucination Warning — {len(hallucinated)} unverified "
                f"indicator(s) cited by AI: {', '.join(hallucinated[:5])}"
            ),
        }


# =============================================================================
# QUICK LOCAL TEST  —  run: python ai_engine.py
# =============================================================================
if __name__ == "__main__":
    from contracts import MOCK_ANALYSIS_RESULT

    # Simulate what Person 1's analyzer.py will pass in
    sample_reports = [
        {"report_id": "REP-01", "text": "Spearphishing email contained link to hxxps://auth-update-portal[.]com. Callback to 185.220.101[.]45 observed."},
        {"report_id": "REP-02", "text": "Brute-force from 185.220.101.45. CVE-2024-21412 exploited on web server."},
        {"report_id": "REP-03", "text": "Malware hash 44d88612fea8a8f36de82e1278abb02f dropped payload. C2 domain auth-update-portal.com contacted."},
    ]

    print("=" * 60)
    print("Testing rule-based components (works without an API key)...")
    print("=" * 60)

    # Test risk scorer
    score, level = calculate_risk(MOCK_ANALYSIS_RESULT)
    print(f"\n[RISK SCORE]  {score}/100  →  {level}")

    # Test MITRE mapper
    all_text = " ".join(r["text"] for r in sample_reports)
    techniques = map_mitre_techniques(all_text)
    print(f"\n[MITRE TECHNIQUES]")
    for t in techniques:
        print(f"  {t['id']}  {t['name']}  ({t['tactic']})")

    # Test full fallback (no LLM)
    fallback = _build_fallback_result(MOCK_ANALYSIS_RESULT, sample_reports)
    print(f"\n[FALLBACK RESULT]")
    print(f"  Risk:    {fallback['risk_level']} ({fallback['risk_score']})")
    print(f"  Summary: {fallback['executive_summary']}")
    print(f"  Actions: {fallback['defensive_actions']}")

    # Test hallucination checker
    valid_iocs = [i["ioc"] for i in MOCK_ANALYSIS_RESULT["indicators"]]
    validation = validate_ai_output(fallback, valid_iocs)
    print(f"\n[HALLUCINATION CHECK]  {validation['badge_text']}")
