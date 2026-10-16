"""
analyzer.py
Owned by: Person 1 (Data & Correlation Module)
Purpose:
  1. Refangs obfuscated indicators (e.g., 185.220.101[.]45 -> 185.220.101.45, hxxps -> https)
  2. Extracts IPv4, Domain, URL, MD5, SHA256, and CVE indicators using regex
  3. Deduplicates indicators per report and captures sentence-level evidence
  4. Correlates shared indicators across reports and builds graph edges for NetworkX/Plotly
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple
from sample_data import get_default_reports, LIVE_DEMO_REPORT

# =====================================================================
# 1. REGEX PATTERNS FOR THREAT INDICATORS (IOCs)
# =====================================================================
IOC_PATTERNS = {
    "CVE": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "URL": re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE),
    "SHA256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "MD5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "IPv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "Domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|org|net|io|gov|edu|mil|co|us|uk|de|ru|cn|xyz|info|biz|me|tv|cc|ai)\b",
        re.IGNORECASE,
    ),
}


# =====================================================================
# 2. TEXT NORMALIZATION ("REFANGING")
# =====================================================================
def refang_text(text: str) -> str:
    """
    Converts defanged indicators commonly found in threat reports back into
    standard format so regexes and cross-report correlation match accurately.
    Examples:
      hxxps://auth-update-portal[.]com -> https://auth-update-portal.com
      185.220.101[.]45 -> 185.220.101.45
    """
    if not text:
        return ""
    cleaned = text
    cleaned = re.sub(r"hxxps://", "https://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"hxxp://", "http://", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    cleaned = cleaned.replace("[:]", ":").replace("(:)", ":")
    cleaned = cleaned.replace("[/]", "/")
    return cleaned


def split_into_sentences(text: str) -> List[str]:
    """
    Splits report text into clean sentences so we can attach the exact
    sentence where an IOC appeared as hard evidence.
    """
    # Split on period+space, newline, or semicolon
    raw_parts = re.split(r"(?<=[.!?])\s+|\n+", text.strip())
    return [part.strip() for part in raw_parts if part.strip()]


def normalize_ioc(value: str, ioc_type: str) -> str:
    """
    Cleans trailing punctuation and normalizes casing so identical IOCs
    always match across reports.
    """
    cleaned = value.strip().rstrip(".,;:!?)']\"")
    if ioc_type == "CVE":
        return cleaned.upper()
    if ioc_type in ("Domain", "IPv4", "MD5", "SHA256"):
        return cleaned.lower()
    if ioc_type == "URL":
        return cleaned
    return cleaned


# =====================================================================
# 3. SINGLE-REPORT IOC EXTRACTION
# =====================================================================
def extract_iocs_from_report(report: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Extracts all unique IOCs from a single threat report dictionary along
    with the sentence snippet that serves as evidence.
    """
    report_id = report.get("id", "REP-UNKNOWN")
    report_title = report.get("title", "Untitled Report")
    raw_text = report.get("text", "")

    refanged_full = refang_text(raw_text)
    sentences = split_into_sentences(refanged_full)

    # Track (ioc_value, ioc_type) -> first evidence sentence in this report
    found_in_report: Dict[Tuple[str, str], str] = {}

    for sentence in sentences:
        # 1. Extract URLs first (and also extract their underlying hostname as a Domain!)
        for match in IOC_PATTERNS["URL"].findall(sentence):
            url_val = normalize_ioc(match, "URL")
            found_in_report.setdefault((url_val, "URL"), sentence)

            # Extract the base domain inside the URL so URLs and plain Domains correlate!
            parsed = urlparse(url_val)
            if parsed.hostname:
                host = normalize_ioc(parsed.hostname, "Domain")
                if IOC_PATTERNS["Domain"].fullmatch(host):
                    found_in_report.setdefault((host, "Domain"), sentence)

        # 2. Extract CVEs
        for match in IOC_PATTERNS["CVE"].findall(sentence):
            cve_val = normalize_ioc(match, "CVE")
            found_in_report.setdefault((cve_val, "CVE"), sentence)

        # 3. Extract SHA256 hashes (64 hex chars)
        sha256_matches = set()
        for match in IOC_PATTERNS["SHA256"].findall(sentence):
            sha_val = normalize_ioc(match, "SHA256")
            sha256_matches.add(sha_val)
            found_in_report.setdefault((sha_val, "SHA256"), sentence)

        # 4. Extract MD5 hashes (32 hex chars, ensuring we don't slice inside a SHA256)
        for match in IOC_PATTERNS["MD5"].findall(sentence):
            md5_val = normalize_ioc(match, "MD5")
            if not any(md5_val in sha for sha in sha256_matches):
                found_in_report.setdefault((md5_val, "MD5"), sentence)

        # 5. Extract IPv4 addresses
        for match in IOC_PATTERNS["IPv4"].findall(sentence):
            ip_val = normalize_ioc(match, "IPv4")
            found_in_report.setdefault((ip_val, "IPv4"), sentence)

        # 6. Extract standalone Domain names
        for match in IOC_PATTERNS["Domain"].findall(sentence):
            dom_val = normalize_ioc(match, "Domain")
            found_in_report.setdefault((dom_val, "Domain"), sentence)

    # Convert to list of structured records
    results = []
    for (ioc_val, ioc_type), evidence_sentence in found_in_report.items():
        results.append(
            {
                "ioc": ioc_val,
                "value": ioc_val,          # Alias for teammate compatibility
                "type": ioc_type,
                "report_id": report_id,
                "source": report_id,       # Alias for teammate compatibility
                "report_title": report_title,
                "evidence": evidence_sentence,
            }
        )
    return results


# =====================================================================
# 4. CROSS-REPORT CORRELATION & GRAPH BUILDER (Main Entry Point)
# =====================================================================
def analyze_reports(reports: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    Main pipeline function called by Person 2 (ai_engine.py) and Person 3 (app.py).
    Accepts a list of report dicts and returns:
      - metrics: summary counts and campaign confidence score
      - indicators: deduplicated list of IOCs with all reports they appear in
      - raw_occurrences: flat per-report list (if someone wants 1 row per report-IOC pair)
      - connections: shared IOCs that link 2+ reports together with evidence
      - graph_edges: (report_id, ioc, "Report", ioc_type) tuples for NetworkX/Plotly
    """
    raw_occurrences: List[Dict[str, str]] = []
    for report in reports:
        raw_occurrences.extend(extract_iocs_from_report(report))

    # Group occurrences by (ioc, type)
    grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for item in raw_occurrences:
        key = (item["ioc"], item["type"])
        if key not in grouped:
            grouped[key] = {
                "ioc": item["ioc"],
                "value": item["ioc"],  # Alias for compatibility
                "type": item["type"],
                "reports": [],
                "evidence_by_report": {},
            }
        rep_id = item["report_id"]
        if rep_id not in grouped[key]["reports"]:
            grouped[key]["reports"].append(rep_id)
            grouped[key]["evidence_by_report"][rep_id] = item["evidence"]

    indicators: List[Dict[str, Any]] = []
    connections: List[Dict[str, Any]] = []
    graph_edges: List[Tuple[str, str, str, str]] = []

    for (ioc_val, ioc_type), data in grouped.items():
        rep_list = data["reports"]
        is_shared = len(rep_list) > 1

        indicator_record = {
            "ioc": ioc_val,
            "value": ioc_val,                  # Alias if teammate uses 'value'
            "type": ioc_type,
            "reports": rep_list,               # e.g. ["REP-01", "REP-02"]
            "source": ", ".join(rep_list),     # String alias for simple table display
            "shared": is_shared,
            "count": len(rep_list),
            "evidence_by_report": data["evidence_by_report"],
        }
        indicators.append(indicator_record)

        # Build graph edges connecting each report to this IOC
        for rep_id in rep_list:
            graph_edges.append((rep_id, ioc_val, "Report", ioc_type))

        # If shared across 2+ reports, record it as a verified correlation connection
        if is_shared:
            evidence_summary = " | ".join(
                f"[{r}] {data['evidence_by_report'][r]}" for r in rep_list
            )
            connections.append(
                {
                    "ioc": ioc_val,
                    "value": ioc_val,
                    "type": ioc_type,
                    "linked_reports": rep_list,
                    "reports": rep_list,
                    "evidence_by_report": data["evidence_by_report"],
                    "evidence": evidence_summary,
                }
            )

    # Sort indicators so shared IOCs appear at the top of the table
    indicators.sort(key=lambda x: (-x["count"], x["type"], x["ioc"]))
    connections.sort(key=lambda x: (-len(x["linked_reports"]), x["type"], x["ioc"]))

    # Calculate deterministic campaign correlation confidence (0 - 100)
    shared_count = len(connections)
    total_iocs = len(indicators)
    if shared_count == 0:
        campaign_confidence = 15
    else:
        campaign_confidence = min(95, 45 + (shared_count * 18))

    return {
        "reports": reports,
        "metrics": {
            "total_reports": len(reports),
            "total_iocs": total_iocs,
            "shared_iocs": shared_count,
            "campaign_confidence": campaign_confidence,
        },
        "indicators": indicators,
        "raw_occurrences": raw_occurrences,
        "connections": connections,
        "graph_edges": graph_edges,
    }


# =====================================================================
# 5. SELF-TEST BLOCK (Run `python3 analyzer.py` to verify)
# =====================================================================
if __name__ == "__main__":
    sample_reports = get_default_reports()
    result = analyze_reports(sample_reports)

    print("=" * 65)
    print("🔍 ANALYZER SELF-TEST RESULTS (3 BUILT-IN REPORTS)")
    print("=" * 65)
    m = result["metrics"]
    print(
        f"Reports: {m['total_reports']} | Unique IOCs: {m['total_iocs']} | "
        f"Shared (Bridges): {m['shared_iocs']} | Campaign Confidence: {m['campaign_confidence']}%"
    )

    print("\n📌 EXTRACTED INDICATORS (Shared first):")
    for ind in result["indicators"]:
        shared_badge = "🔗 SHARED" if ind["shared"] else "   single"
        print(f"  {shared_badge} | [{ind['type']:6}] {ind['ioc']:35} <- {ind['reports']}")

    print("\n🕸️ CORRELATED CONNECTIONS (Cross-Report Bridges):")
    for conn in result["connections"]:
        print(f"  🔥 {conn['ioc']} ({conn['type']}) connects {conn['linked_reports']}")
        for rep_id, ev in conn["evidence_by_report"].items():
            print(f"      - {rep_id}: \"{ev}\"")

    # Test adding the 4th Live Demo Report
    print("\n" + "=" * 65)
    print("🚀 TESTING LIVE DEMO INJECTION (+ REP-04)")
    print("=" * 65)
    plus_live = sample_reports + [LIVE_DEMO_REPORT]
    live_result = analyze_reports(plus_live)
    lm = live_result["metrics"]
    print(
        f"Reports: {lm['total_reports']} | Unique IOCs: {lm['total_iocs']} | "
        f"Shared (Bridges): {lm['shared_iocs']} | Campaign Confidence: {lm['campaign_confidence']}%"
    )
    for conn in live_result["connections"]:
        print(f"  🔥 {conn['ioc']} ({conn['type']}) connects {conn['linked_reports']}")
