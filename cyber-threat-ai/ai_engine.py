##helloo
# =============================================================================
# ai_engine.py  —  Person 2 owns this file
# Hybrid AI + Rule-Based Risk Scorer, MITRE Mapper, LLM Analyst + Fallback
#
# HOW TO USE YOUR OWN API KEY
# ----------------------------
# Option A  (recommended during hackathon): set an environment variable
#     Windows PowerShell:  $env:OPENAI_API_KEY = "sk-..."
#     Linux/Mac terminal:  export OPENAI_API_KEY="sk-..."
#
# Option B: Create a file called  .env  in the project root with one line:
#     OPENAI_API_KEY=sk-...
#   Then install python-dotenv  (pip install python-dotenv)  and uncomment the
#   two dotenv lines below.
#
# The code works with:
#   • OpenAI  (default, base_url not needed)
#   • Google Gemini OpenAI-compat endpoint  (change base_url + model below)
#   • Groq     (change base_url + model below)
#   • Local Ollama  (change base_url to http://localhost:11434/v1, model to any)
# =============================================================================

import os
import json
import re
import time

# Uncomment these two lines if you are using a .env file for the API key:
# from dotenv import load_dotenv
# load_dotenv()

# ── OpenAI-compatible client ──────────────────────────────────────────────────
try:
    from openai import OpenAI
    _openai_available = True
except ImportError:
    _openai_available = False

# ---------------------------------------------------------------------------
# CONFIGURE YOUR LLM HERE  (change these two lines only)
# ---------------------------------------------------------------------------
LLM_BASE_URL = None          # None = OpenAI default.  Change to Groq/Gemini/Ollama URL if needed.
LLM_MODEL    = "gpt-4o-mini" # Cheap, fast model perfect for hackathon.  Change as needed.
LLM_TIMEOUT  = 20            # seconds before we fall back to rule-based result
# ---------------------------------------------------------------------------


# =============================================================================
# SECTION 1 — MITRE ATT&CK KEYWORD → TECHNIQUE MAPPER
# =============================================================================
# This dictionary maps keywords (found in report text) to MITRE techniques.
# Add more if you have time — judges love seeing MITRE coverage.

MITRE_KEYWORD_MAP = [
    # keyword patterns            technique_id  name                              tactic
    (r"phish|spearphish|credential|harvest",  "T1566", "Phishing",                             "Initial Access"),
    (r"cve-\d{4}-\d+|exploit|vulnerab",       "T1190", "Exploit Public-Facing Application",    "Initial Access"),
    (r"c2|command.and.control|beacon|callback","T1071", "Application Layer Protocol",           "Command and Control"),
    (r"brute.?force|password.?spray",         "T1110", "Brute Force",                          "Credential Access"),
    (r"lateral.?mov|psexec|wmi|smb",          "T1021", "Remote Services",                      "Lateral Movement"),
    (r"ransomwar|encrypt.*file|lock.*file",   "T1486", "Data Encrypted for Impact",            "Impact"),
    (r"exfiltrat|data.?theft|stolen",         "T1041", "Exfiltration Over C2 Channel",         "Exfiltration"),
    (r"persistenc|startup|registry.*run|cron","T1547", "Boot or Logon Autostart Execution",    "Persistence"),
    (r"powershell|wscript|cscript|cmd\.exe",  "T1059", "Command and Scripting Interpreter",    "Execution"),
    (r"dropper|downloader|malware|payload",   "T1105", "Ingress Tool Transfer",                "Command and Control"),
    (r"domain.*front|cdn.*tunnel|tunnel",     "T1090", "Proxy",                               "Command and Control"),
    (r"dns.?tunnel|dns.?query|dns.?resolv",   "T1071", "Application Layer Protocol (DNS)",    "Command and Control"),
    (r"lolbin|living.?off.?land|certutil|bitsadmin", "T1218", "System Binary Proxy Execution","Defense Evasion"),
    (r"mimikatz|lsass|credential.?dump",      "T1003", "OS Credential Dumping",               "Credential Access"),
    (r"spearphish.*attach|malicious.*attach|pdf.*attach", "T1566.001","Spearphishing Attachment","Initial Access"),
]


def map_mitre_techniques(all_text: str) -> list[dict]:
    """
    Scan combined report text with regex patterns and return a deduplicated
    list of matching MITRE ATT&CK techniques.

    Returns a list of dicts: [{"id": "T1566", "name": "...", "tactic": "..."}, ...]
    """
    combined = all_text.lower()
    seen_ids = set()
    techniques = []

    for pattern, tid, name, tactic in MITRE_KEYWORD_MAP:
        if tid not in seen_ids and re.search(pattern, combined):
            techniques.append({"id": tid, "name": name, "tactic": tactic})
            seen_ids.add(tid)

    # Always guarantee at least one technique so the UI never shows an empty list
    if not techniques:
        techniques.append({"id": "T1566", "name": "Phishing", "tactic": "Initial Access"})

    return techniques


# =============================================================================
# SECTION 2 — DETERMINISTIC RISK SCORER
# =============================================================================

def calculate_risk(analysis_result: dict) -> tuple[int, str]:
    """
    Calculate a numeric risk score (0-100) and a risk level label
    based purely on the structured data extracted by analyzer.py.

    This runs WITHOUT an internet connection — it is your demo safety net.

    Scoring rules:
      Base score                        =  20
      Per shared IOC                    = +15  (capped at 45)
      CVE present                       = +20
      Both domain/URL AND hash detected = +10  (multi-stage signal)
      More than 2 reports correlated    = +10

    Returns: (score: int, level: str)
    """
    score = 20  # baseline — something is always worth looking at

    indicators  = analysis_result.get("indicators", [])
    shared_iocs = [i for i in indicators if i.get("shared")]
    all_types   = {i["type"] for i in indicators}

    # Shared IOCs are the strongest signal of coordinated attack
    score += min(len(shared_iocs) * 15, 45)

    # CVE means a known vulnerability is being weaponised
    if any(i["type"] == "CVE" for i in indicators):
        score += 20

    # Domain/URL + Hash together = multi-stage attack (delivery → execution)
    has_domain_or_url = bool({"Domain", "URL"} & all_types)
    has_hash          = bool({"MD5", "SHA256", "SHA1"} & all_types)
    if has_domain_or_url and has_hash:
        score += 10

    # Many correlated reports = wider campaign
    total_reports = analysis_result.get("metrics", {}).get("total_reports", 1)
    if total_reports > 2:
        score += 10

    score = min(score, 100)  # cap at 100

    # Map numeric score → human-readable level
    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


# =============================================================================
# SECTION 3 — RULE-BASED FALLBACK RESPONSE GENERATOR
# =============================================================================

def _build_fallback_result(analysis_result: dict, reports: list[dict]) -> dict:
    """
    Build a complete AI-result dictionary using ONLY rule-based logic —
    no LLM, no internet required. Called automatically when the LLM fails.

    'reports' is a list of dicts: [{"report_id": "REP-01", "text": "..."}, ...]
    """
    score, level   = calculate_risk(analysis_result)
    indicators     = analysis_result.get("indicators", [])
    shared_iocs    = [i for i in indicators if i.get("shared")]
    connections    = analysis_result.get("connections", [])
    total_reports  = analysis_result.get("metrics", {}).get("total_reports", len(reports))

    # Combine all report text for MITRE mapping
    all_text = " ".join(r.get("text", "") for r in reports)
    techniques = map_mitre_techniques(all_text)

    # --- Build evidence facts from actual extracted data ---
    evidence_facts = []
    for conn in connections:
        ioc          = conn.get("ioc", "Unknown IOC")
        linked       = conn.get("linked_reports", [])
        ev           = conn.get("evidence", "observed in multiple reports")
        if linked:
            evidence_facts.append(
                f"{ioc} links {' and '.join(linked)}: {ev}."
            )

    if not evidence_facts:
        # Generic fallback if connections list is empty
        if shared_iocs:
            ioc = shared_iocs[0]["ioc"]
            reps = shared_iocs[0].get("reports", [])
            evidence_facts.append(
                f"{ioc} was observed across {len(reps)} reports ({', '.join(reps)}), "
                f"suggesting shared attacker infrastructure."
            )
        else:
            evidence_facts.append(
                f"Analysis of {total_reports} report(s) identified "
                f"{len(indicators)} indicator(s). No shared IOCs found; "
                f"reports may represent separate incidents."
            )

    # --- Build AI hypotheses from heuristics ---
    hypotheses = []
    if len(shared_iocs) >= 2:
        hypotheses.append(
            "Multiple shared IOCs across reports strongly suggest a single threat actor "
            "reusing infrastructure — typical of organised APT campaigns."
        )
    if any(i["type"] == "CVE" for i in indicators):
        hypotheses.append(
            "CVE exploitation alongside phishing/C2 IOCs is consistent with a "
            "multi-stage intrusion: initial access via phishing → vulnerability exploitation → C2."
        )
    if not hypotheses:
        hypotheses.append(
            "Insufficient overlap between reports to attribute to a single actor with high confidence. "
            "Recommend continued monitoring and correlation against threat intelligence feeds."
        )

    # --- Build defensive actions from actual IOCs ---
    defensive_actions = []
    block_items = [i["ioc"] for i in indicators if i["type"] in ("IPv4", "Domain", "URL")]
    if block_items:
        defensive_actions.append(
            f"[IMMEDIATE] Block the following at perimeter firewall/DNS: {', '.join(block_items[:5])}."
        )

    shared_ips = [i["ioc"] for i in shared_iocs if i["type"] == "IPv4"]
    if shared_ips:
        defensive_actions.append(
            f"[HUNT] Query SIEM for outbound connections to {', '.join(shared_ips)} "
            f"over the past 30 days."
        )

    cves = [i["ioc"] for i in indicators if i["type"] == "CVE"]
    if cves:
        defensive_actions.append(
            f"[PATCH] Prioritise remediation of {', '.join(cves)} on all exposed endpoints."
        )

    hashes = [i["ioc"] for i in indicators if i["type"] in ("MD5", "SHA256", "SHA1")]
    if hashes:
        defensive_actions.append(
            f"[HUNT] Search EDR/AV telemetry for file hashes: {', '.join(hashes[:3])}."
        )

    if not defensive_actions:
        defensive_actions.append(
            "[REVIEW] Escalate reports to Tier-2 analyst for manual triage."
        )

    # --- Executive summary ---
    shared_label = f"{len(shared_iocs)} shared IOC(s)" if shared_iocs else "no shared IOCs"
    exec_summary = (
        f"{level}-risk assessment across {total_reports} correlated report(s) "
        f"with {len(indicators)} extracted indicator(s) and {shared_label}. "
        f"{'Evidence of coordinated campaign activity detected. ' if shared_iocs else ''}"
        f"Rule-based analysis complete — LLM enhancement unavailable."
    )

    return {
        "risk_level":        level,
        "risk_score":        score,
        "executive_summary": exec_summary,
        "evidence_facts":    evidence_facts,
        "ai_hypotheses":     hypotheses,
        "mitre_techniques":  techniques,
        "defensive_actions": defensive_actions,
        "_source":           "rule-based-fallback",   # internal flag; hide in UI
    }


# =============================================================================
# SECTION 4 — LLM ANALYST  (wraps fallback automatically)
# =============================================================================

def _build_llm_prompt(reports: list[dict], analysis_result: dict) -> str:
    """
    Build the prompt we send to the LLM.
    We pass in the pre-extracted IOCs so the LLM doesn't hallucinate new ones.
    """
    indicators = analysis_result.get("indicators", [])
    connections = analysis_result.get("connections", [])

    ioc_block = "\n".join(
        f"  - {i['ioc']} ({i['type']}) — found in {', '.join(i['reports'])}"
        + (" [SHARED]" if i.get("shared") else "")
        for i in indicators
    )

    conn_block = "\n".join(
        f"  - {c['ioc']} links {' ↔ '.join(c['linked_reports'])}: {c.get('evidence','')}"
        for c in connections
    ) or "  - No cross-report connections detected."

    report_block = "\n\n".join(
        f"=== {r.get('report_id','Unknown')} ===\n{r.get('text','')}"
        for r in reports
    )

    prompt = f"""You are an expert cybersecurity analyst writing an incident fusion report.

VERIFIED IOCs (extracted by regex — do NOT cite any IOC not in this list):
{ioc_block}

CROSS-REPORT CONNECTIONS (hard evidence):
{conn_block}

RAW INCIDENT REPORTS:
{report_block}

Your task: Produce a JSON object with EXACTLY these keys (no extras):
{{
  "executive_summary": "<2-3 sentence plain-English summary for a CISO>",
  "evidence_facts": ["<hard fact 1>", "<hard fact 2>", ...],
  "ai_hypotheses": ["<analytical hypothesis 1>", ...],
  "defensive_actions": ["[IMMEDIATE] ...", "[HUNT] ...", "[PATCH] ..."],
  "mitre_techniques": [{{"id": "T1566", "name": "Phishing", "tactic": "Initial Access"}}, ...]
}}

STRICT RULES:
1. Only cite IOCs from the VERIFIED IOCs list above.
2. Separate confirmed facts (evidence_facts) from inferences (ai_hypotheses).
3. Defensive actions must start with [IMMEDIATE], [HUNT], [PATCH], or [MONITOR].
4. Output ONLY the raw JSON object — no markdown, no code fences, no extra text.
"""
    return prompt


def generate_ai_assessment(reports: list[dict], analysis_result: dict) -> dict:
    """
    Main entry point for Person 3 (app.py) to call.

    Args:
        reports:         list of {"report_id": "REP-01", "text": "..."}
        analysis_result: the dict returned by analyzer.analyze_reports()

    Returns:
        A dict matching the MOCK_AI_RESULT structure in contracts.py.
        Always returns something — LLM failure triggers the rule-based fallback.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()

    # ── Skip LLM entirely if no API key ───────────────────────────────────────
    if not api_key or not _openai_available:
        print("[ai_engine] No API key or openai package — using rule-based fallback.")
        result = _build_fallback_result(analysis_result, reports)
        # Still populate risk_score & risk_level from rule-based scorer
        return _attach_risk(result, analysis_result)

    # ── Attempt LLM call with timeout ─────────────────────────────────────────
    try:
        client_kwargs = {"api_key": api_key}
        if LLM_BASE_URL:
            client_kwargs["base_url"] = LLM_BASE_URL

        client = OpenAI(**client_kwargs)
        prompt = _build_llm_prompt(reports, analysis_result)

        start = time.time()
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,      # lower = more deterministic = fewer hallucinations
            max_tokens=1200,
            timeout=LLM_TIMEOUT,
        )
        elapsed = round(time.time() - start, 1)
        print(f"[ai_engine] LLM responded in {elapsed}s.")

        raw_text = response.choices[0].message.content.strip()
        llm_result = json.loads(raw_text)  # may raise if model didn't return valid JSON

        # Merge LLM output with rule-based risk score (more reliable)
        llm_result = _attach_risk(llm_result, analysis_result)
        llm_result["_source"] = "llm"
        return llm_result

    except json.JSONDecodeError as e:
        print(f"[ai_engine] LLM returned invalid JSON ({e}) — falling back.")
    except Exception as e:
        print(f"[ai_engine] LLM call failed ({type(e).__name__}: {e}) — falling back.")

    # ── Fallback ──────────────────────────────────────────────────────────────
    result = _build_fallback_result(analysis_result, reports)
    return _attach_risk(result, analysis_result)


def _attach_risk(result: dict, analysis_result: dict) -> dict:
    """Compute risk_score and risk_level deterministically and attach them."""
    score, level = calculate_risk(analysis_result)
    result["risk_score"] = score
    result["risk_level"] = level
    return result


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
    print("Testing rule-based components (no API key needed)...")
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
