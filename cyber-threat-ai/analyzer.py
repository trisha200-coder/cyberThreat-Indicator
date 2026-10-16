
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
# 4B. THREAT ACTOR ATTRIBUTION & RECOGNIZABILITY ENGINE
# =====================================================================
KNOWN_ACTOR_SIGNATURES = [
    {
        "actor_id": "ACT-01",
        "handle": "k0balt_vortex",
        "group_name": "FIN-SHADOW Syndicate",
        "origin_hint": "UTC+3 Operational Cadence // Financial & Core Infra Targeting",
        "signature_regex": re.compile(r"k0balt_vortex|fin-shadow|shadowloader|shadowbot", re.IGNORECASE),
        "known_iocs": {
            "185.220.101.45",
            "45.155.205.99",
            "91.214.124.10",
            "auth-update-portal.com",
            "login-verification-cloud.net",
            "telemetry-cdn-edge.org",
            "cdn-sync-service.net",
            "44d88612fea8a8f36de82e1278abb02f",
            "8b1a9953c4611296a827abf8c47804d7",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        },
        " behavioral_pattern": (
            "Spearphishing PDF/SSO link -> CVE-2024-21412 & CVE-2024-3400 exploitation -> "
            "Certutil/Mimikatz LSASS dump -> SMB/WMI lateral movement -> C2 exfiltration & ransomware staging"
        ),
        "forensic_fingerprints": [
            "PDF metadata author handle 'k0balt_vortex' (UTC+3)",
            "Hardcoded PDB path: C:\\Users\\k0balt_vortex\\repos\\ShadowLoader\\stage1.pdb",
            "Registry persistence key: HKCU\\Software\\k0balt_vortex",
            "Custom brute-force User-Agent: ShadowBot/3.1 (operator:k0balt_vortex)",
            "TLS certificate subject: CN=k0balt_vortex.fin-shadow.ops",
            "SSH jump-box key comment: k0balt_vortex@fin-shadow.local",
        ],
    },
    {
        "actor_id": "ACT-02",
        "handle": "nightshade_0x",
        "group_name": "VOLT-SPIDER Supply-Chain Group",
        "origin_hint": "CI/CD Supply-Chain & Cloud IAM Token Replay Specialist",
        "signature_regex": re.compile(r"nightshade_0x|volt-spider|api-git-mirror", re.IGNORECASE),
        "known_iocs": {
            "194.26.135.88",
            "api-git-mirror.io",
            "d41d8cd98f00b204e9800998ecf8427e",
        },
        " behavioral_pattern": (
            "Trojanized Git mirror dependency injection -> CVE-2024-21412 exploit reuse -> "
            "AWS IAM role assumption & S3 bucket token replay"
        ),
        "forensic_fingerprints": [
            "Git commit & GPG signature alias: 'nightshade_0x'",
            "Automated cloud exfiltration script tag: 'nightshade_0x'",
            "Reused loader MD5: d41d8cd98f00b204e9800998ecf8427e across CI/CD and AWS logs",
        ],
    },
]


def detect_attacker_attribution(
    reports: List[Dict[str, str]],
    indicators: List[Dict[str, Any]],
    connections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Evaluates all reports, extracted IOCs, and cross-report connections to determine:
      1. Whether the attacker(s) are RECOGNIZABLE or UNRECOGNIZABLE.
      2. Specific Threat Actor Profiles (handles, groups, matched reports, confidence).
      3. Per-report attribution mapping (including flagging isolated/anonymous noise).
    """
    report_ioc_map: Dict[str, set] = {r.get("id", "REP-UNKNOWN"): set() for r in reports}
    for ind in indicators:
        for rep_id in ind.get("reports", []):
            report_ioc_map.setdefault(rep_id, set()).add(ind["ioc"].lower())

    actor_profiles: List[Dict[str, Any]] = []
    attributed_reports: Dict[str, Dict[str, Any]] = {}

    for sig in KNOWN_ACTOR_SIGNATURES:
        matched_reports = []
        matched_iocs = set()
        for rep in reports:
            rep_id = rep.get("id", "REP-UNKNOWN")
            raw_text = rep.get("text", "")
            rep_iocs = report_ioc_map.get(rep_id, set())
            ioc_overlap = rep_iocs.intersection(sig["known_iocs"])
            text_match = bool(sig["signature_regex"].search(raw_text))

            if text_match or ioc_overlap:
                matched_reports.append(rep_id)
                matched_iocs.update(ioc_overlap)

        if matched_reports:
            # Recognizable if seen across >=2 reports OR has explicit operator signature + IOCs
            is_actor_recognizable = len(matched_reports) >= 2 or len(matched_iocs) >= 2
            conf = min(98, 55 + (len(matched_reports) * 6) + (len(matched_iocs) * 3))
            profile = {
                "actor_id": sig["actor_id"],
                "handle": sig["handle"],
                "group_name": sig["group_name"],
                "recognizable": is_actor_recognizable,
                "recognizability_label": (
                    "✅ RECOGNIZABLE ATTACKER"
                    if is_actor_recognizable
                    else "⚠️ PARTIAL / LOW CONFIDENCE"
                ),
                "confidence": conf,
                "matched_reports": matched_reports,
                "matched_ioc_count": len(matched_iocs),
                "matched_iocs": sorted(matched_iocs),
                "origin_hint": sig["origin_hint"],
                "behavioral_pattern": sig[" behavioral_pattern"],
                "forensic_fingerprints": sig["forensic_fingerprints"],
            }
            actor_profiles.append(profile)
            for r_id in matched_reports:
                attributed_reports[r_id] = {
                    "report_id": r_id,
                    "recognizable": is_actor_recognizable,
                    "attacker_handle": f"{sig['handle']} ({sig['group_name']})",
                    "confidence": f"{conf}%",
                    "verdict": "✅ Recognizable (Matched Operator & Infrastructure Pattern)",
                }

    # Check for any reports that did NOT match a recognizable pattern (e.g., REP-10)
    unattributed_report_ids = []
    for rep in reports:
        rep_id = rep.get("id", "REP-UNKNOWN")
        if rep_id not in attributed_reports:
            unattributed_report_ids.append(rep_id)
            attributed_reports[rep_id] = {
                "report_id": rep_id,
                "recognizable": False,
                "attacker_handle": "Unknown / Anonymous Actor",
                "confidence": "12%",
                "verdict": "❌ Not Recognizable (Isolated probe with 0 shared IOCs & no operator signature)",
            }

    actor_profiles.sort(key=lambda x: (-len(x["matched_reports"]), -x["confidence"]))

    overall_recognizable = any(p["recognizable"] for p in actor_profiles) or len(connections) >= 2
    if actor_profiles:
        primary = actor_profiles[0]
        primary_name = f"Operator '{primary['handle']}' ({primary['group_name']})"
        overall_conf = primary["confidence"]
        verdict_summary = (
            f"YES — ATTACKER IS RECOGNIZABLE ({overall_conf}% Confidence). "
            f"Cross-report behavioral and forensic analysis identified {len(actor_profiles)} distinct threat actor persona(s): "
            + "; ".join(
                f"'{p['handle']}' ({p['group_name']}) across {len(p['matched_reports'])} reports ({', '.join(p['matched_reports'])})"
                for p in actor_profiles
            )
            + (
                f". Meanwhile, {', '.join(unattributed_report_ids)} was flagged as NOT RECOGNIZABLE (isolated anonymous noise with 0 shared IOCs)."
                if unattributed_report_ids
                else "."
            )
        )
    else:
        primary_name = "Unidentified / Anonymous Threat Actor"
        overall_conf = 15 if len(connections) == 0 else 55
        verdict_summary = (
            "NO — ATTACKER IS NOT RECOGNIZABLE. Insufficient behavioral repetition, zero known operator handles, "
            "and no recurring C2 infrastructure across reports to attribute the attack to a specific person."
        )

    return {
        "is_recognizable": overall_recognizable,
        "status_badge": (
            f"✅ ATTACKER RECOGNIZABLE ({overall_conf}% Confidence)"
            if overall_recognizable
            else "❌ ATTACKER NOT RECOGNIZABLE (Anonymous / Insufficient Pattern)"
        ),
        "primary_attacker": primary_name,
        "confidence_score": overall_conf,
        "verdict_summary": verdict_summary,
        "actor_profiles": actor_profiles,
        "unattributed_reports": unattributed_report_ids,
        "per_report_attribution": list(attributed_reports.values()),
    }


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
      - attribution: threat actor recognizability verdict and suspect profiles
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

    attribution = detect_attacker_attribution(reports, indicators, connections)

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
        "attribution": attribution,
    }


# =====================================================================
# 5. SELF-TEST BLOCK (Run `python3 analyzer.py` to verify)
# =====================================================================
if __name__ == "__main__":
    sample_reports = get_default_reports()
    result = analyze_reports(sample_reports)

    print("=" * 65)
    print(f"🔍 ANALYZER SELF-TEST RESULTS ({len(sample_reports)} BUILT-IN REPORTS)")
    print("=" * 65)
    m = result["metrics"]
    print(
        f"Reports: {m['total_reports']} | Unique IOCs: {m['total_iocs']} | "
        f"Shared (Bridges): {m['shared_iocs']} | Campaign Confidence: {m['campaign_confidence']}%"
    )

    attr = result["attribution"]
    print(f"\n🕵️ ATTACKER RECOGNIZABILITY VERDICT: {attr['status_badge']}")
    print(f"   Primary Attacker: {attr['primary_attacker']}")
    print(f"   Summary: {attr['verdict_summary']}")

    print("\n📌 EXTRACTED INDICATORS (Shared first):")
    for ind in result["indicators"]:
        shared_badge = "🔗 SHARED" if ind["shared"] else "   single"
        print(f"  {shared_badge} | [{ind['type']:6}] {ind['ioc']:35} <- {ind['reports']}")
