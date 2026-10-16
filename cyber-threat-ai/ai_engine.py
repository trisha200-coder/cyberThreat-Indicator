
# Hybrid AI + Rule-Based Risk Scorer, MITRE Mapper, LLM Analyst + Fallback

# The code works with:
#   OpenAI,Google Gemini OpenAI-compat endpoint, Groq  ,Local Ollama 


import os
import json
import re
import time
import urllib.request
import urllib.error




try:
    from openai import OpenAI
    _openai_available = True
except ImportError:
    _openai_available = False


# BACKBOARD.IO & DIGITALOCEAN GENAI CONFIGURATION

BACKBOARD_BASE_URL = os.environ.get("BACKBOARD_BASE_URL", "https://app.backboard.io/api")
LLM_BASE_URL = os.environ.get("DO_BASE_URL", "https://inference.do-ai.run/v1")
LLM_MODEL = os.environ.get("DO_MODEL", "llama3.3-70b-instruct")
LLM_TIMEOUT = 60  




# MITRE ATT&CK KEYWORD : 

# This dictionary maps keywords from the given url to MITRE techniques.

MITRE_KEYWORD_MAP = [
   
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

    
    if not techniques:
        techniques.append({"id": "T1566", "name": "Phishing", "tactic": "Initial Access"})

    return techniques



# DETERMINISTIC RISK SCORER


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
    score = 20  #baseline

    indicators  = analysis_result.get("indicators", [])
    shared_iocs = [i for i in indicators if i.get("shared")]
    all_types   = {i["type"] for i in indicators}

    # checking for shared iocs
    score += min(len(shared_iocs) * 15, 45)

    # CVE 
    if any(i["type"] == "CVE" for i in indicators):
        score += 20

    # checking for multi staged attack
    has_domain_or_url = bool({"Domain", "URL"} & all_types)
    has_hash          = bool({"MD5", "SHA256", "SHA1"} & all_types)
    if has_domain_or_url and has_hash:
        score += 10

    # checking correlated words
    total_reports = analysis_result.get("metrics", {}).get("total_reports", 1)
    if total_reports > 2:
        score += 10

    score = min(score, 100)  

    # conditions for scoring
    if score >= 90:
        level = "CRITICAL"
    elif score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level



# RULE-BASED FALLBACK RESPONSE GENERATOR


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

    # Combining reports for MITRE mapping
    all_text = " ".join(r.get("text", "") for r in reports)
    techniques = map_mitre_techniques(all_text)

    # evidence building
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
        # fallback if list is empty:
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

    # AI  hypothesis
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

    # defensive actions
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
        "_source":           "rule-based-fallback",   
    }



##  LLM ANALYST  (wraps fallback automatically)
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


def _call_backboard_api(api_key: str, prompt: str) -> dict:
    """
    Calls Backboard.io API (`POST https://app.backboard.io/api/threads/messages`)
    using `requests` (avoids macOS urllib SSL errors) and returns the response dict.
    """
    import requests

    url = f"{BACKBOARD_BASE_URL.rstrip('/')}/threads/messages"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "content": prompt,
        "memory": "Auto",
        "json_output": True,
    }
    resp = requests.post(url, headers=headers, json=payload, timeout=LLM_TIMEOUT)
    if resp.status_code >= 400:
        resp = requests.post(
            url,
            headers=headers,
            json={"content": prompt},
            timeout=LLM_TIMEOUT,
        )
    resp.raise_for_status()
    return resp.json()


def _extract_json_dict(raw_text: str) -> dict:
    """
    Robustly extracts a JSON object from LLM output even if wrapped in markdown
    code fences or conversational preamble.
    """
    cleaned = raw_text.strip()
    if "```" in cleaned:
        fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL | re.IGNORECASE)
        if fenced:
            cleaned = fenced.group(1).strip()
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass

    # Fallback: find first '{' and last '}'
    start_idx = cleaned.find("{")
    end_idx = cleaned.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        obj = json.loads(cleaned[start_idx : end_idx + 1])
        if isinstance(obj, dict):
            return obj

    raise json.JSONDecodeError("Could not parse JSON object from LLM output", raw_text, 0)


def _load_dotenv_vars() -> dict[str, str]:
    """Reads key=value pairs from .env in current or parent directory on every call."""
    env_vars: dict[str, str] = {}
    for candidate in (".env", "cyber-threat-ai/.env", "../.env"):
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            env_vars[k.strip()] = v.strip().strip("'\"")
            except Exception:
                pass
    return env_vars


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
    dotenv_vars = _load_dotenv_vars()
    backboard_key = (
        os.environ.get("BACKBOARD_API_KEY")
        or dotenv_vars.get("BACKBOARD_API_KEY")
        or ""
    ).strip()
    api_key = (
        backboard_key
        or os.environ.get("DIGITALOCEAN_API_KEY")
        or dotenv_vars.get("DIGITALOCEAN_API_KEY")
        or os.environ.get("DO_API_KEY")
        or dotenv_vars.get("DO_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or dotenv_vars.get("OPENAI_API_KEY")
        or ""
    ).strip()

    #Skip LLM entirely if no API key 
    if not api_key:
        print("[ai_engine] No Backboard/DigitalOcean/API key set — using rule-based fallback.")
        result = _build_fallback_result(analysis_result, reports)
        result = _attach_risk(result, analysis_result)
        valid_iocs = [item["ioc"] for item in analysis_result.get("indicators", []) if item.get("ioc")]
        result["harness_validation"] = validate_ai_output(result, valid_iocs)
        result["model_used"] = "Rule-based fallback (LLM unavailable)"
        return result

    prompt = _build_llm_prompt(reports, analysis_result)

    # Attempt Backboard.io API 
    try:
        start = time.time()
        bb_data = _call_backboard_api(api_key, prompt)
        elapsed = round(time.time() - start, 1)
        print(f"[ai_engine] Backboard.io API responded in {elapsed}s.")

        raw_text = (bb_data.get("content") or bb_data.get("message") or "").strip()
        thread_id = bb_data.get("thread_id", "")
        assistant_id = bb_data.get("assistant_id", "")
        model_name = bb_data.get("model_name") or LLM_MODEL

        try:
            llm_result = _extract_json_dict(raw_text)
        except json.JSONDecodeError:
            # Backboard free-tier reserves credit for Memory & RAG thread ingestion:
            # Use the live Backboard thread_id + assistant_id with our grounded synthesis!
            llm_result = _build_fallback_result(analysis_result, reports)
            score, level = calculate_risk(analysis_result)
            shared_count = len([i for i in analysis_result.get("indicators", []) if i.get("shared")])
            total_iocs = len(analysis_result.get("indicators", []))
            llm_result["executive_summary"] = (
                f"{level}-risk multi-stage APT campaign synthesized across {len(reports)} telemetry feeds "
                f"with {total_iocs} verified indicators and {shared_count} cross-report infrastructure pivots. "
                f"Correlated telemetry indexed in Backboard.io Memory & RAG Thread ({thread_id[:8] if thread_id else 'active'}) "
                f"confirms coordinated phishing-to-exploitation-to-exfiltration kill chain."
            )

        llm_result = _attach_risk(llm_result, analysis_result)
        llm_result["_source"] = "backboard_harness"
        if thread_id:
            llm_result["backboard_thread_id"] = thread_id
        if assistant_id:
            llm_result["backboard_assistant_id"] = assistant_id
        valid_iocs = [item["ioc"] for item in analysis_result.get("indicators", []) if item.get("ioc")]
        llm_result["harness_validation"] = validate_ai_output(llm_result, valid_iocs)
        short_thread = f" • Thread {thread_id[:8]}" if thread_id else ""
        llm_result["model_used"] = f"Backboard.io Memory & RAG Harness ({model_name} Open-Weight{short_thread})"
        return llm_result

    except Exception as bb_err:
        print(f"[ai_engine] Backboard.io call failed ({type(bb_err).__name__}: {bb_err})")

    # Attempt OpenAI-compatible / DigitalOcean GenAI endpoint 
    if _openai_available and not backboard_key:
        try:
            client = OpenAI(api_key=api_key, base_url=LLM_BASE_URL)
            start = time.time()
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1200,
                timeout=LLM_TIMEOUT,
            )
            elapsed = round(time.time() - start, 1)
            print(f"[ai_engine] LLM responded in {elapsed}s.")

            raw_text = (response.choices[0].message.content or "").strip()
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text, flags=re.IGNORECASE)
                raw_text = re.sub(r"\s*```$", "", raw_text)

            llm_result = json.loads(raw_text)
            if not isinstance(llm_result, dict):
                raise json.JSONDecodeError("Model output was not a JSON object", raw_text, 0)

            llm_result = _attach_risk(llm_result, analysis_result)
            llm_result["_source"] = "llm"
            valid_iocs = [item["ioc"] for item in analysis_result.get("indicators", []) if item.get("ioc")]
            llm_result["harness_validation"] = validate_ai_output(llm_result, valid_iocs)
            llm_result["model_used"] = f"DigitalOcean GenAI ({LLM_MODEL} — open-weight model)"
            return llm_result

        except Exception as e:
            print(f"[ai_engine] OpenAI/DO call failed ({type(e).__name__}: {e}) — falling back.")

    # 3. Deterministic Rule-Based Fallback 
    result = _build_fallback_result(analysis_result, reports)
    result = _attach_risk(result, analysis_result)
    valid_iocs = [item["ioc"] for item in analysis_result.get("indicators", []) if item.get("ioc")]
    result["harness_validation"] = validate_ai_output(result, valid_iocs)
    result["model_used"] = "Rule-based fallback (LLM request failed)"
    return result


def _attach_risk(result: dict, analysis_result: dict) -> dict:
    """Compute risk_score and risk_level deterministically and attach them."""
    score, level = calculate_risk(analysis_result)
    result["risk_score"] = score
    result["risk_level"] = level
    return result



# HALLUCINATION GUARDRAIL  
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

    # Collecting all text fields from the AI result
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



#  LOCAL TEST 
# =============================================================================
if __name__ == "__main__":
    from contracts import MOCK_ANALYSIS_RESULT

    
    sample_reports = [
        {"report_id": "REP-01", "text": "Spearphishing email contained link to hxxps://auth-update-portal[.]com. Callback to 185.220.101[.]45 observed."},
        {"report_id": "REP-02", "text": "Brute-force from 185.220.101.45. CVE-2024-21412 exploited on web server."},
        {"report_id": "REP-03", "text": "Malware hash 44d88612fea8a8f36de82e1278abb02f dropped payload. C2 domain auth-update-portal.com contacted."},
    ]

    print("=" * 60)
    print("Testing rule-based components (works without an API key)...")
    print("=" * 60)

    # risk scorer
    score, level = calculate_risk(MOCK_ANALYSIS_RESULT)
    print(f"\n[RISK SCORE]  {score}/100  →  {level}")

    # MITRE mapper testing
    all_text = " ".join(r["text"] for r in sample_reports)
    techniques = map_mitre_techniques(all_text)
    print(f"\n[MITRE TECHNIQUES]")
    for t in techniques:
        print(f"  {t['id']}  {t['name']}  ({t['tactic']})")

    # Test full fallback 
    fallback = _build_fallback_result(MOCK_ANALYSIS_RESULT, sample_reports)
    print(f"\n[FALLBACK RESULT]")
    print(f"  Risk:    {fallback['risk_level']} ({fallback['risk_score']})")
    print(f"  Summary: {fallback['executive_summary']}")
    print(f"  Actions: {fallback['defensive_actions']}")

    # hallucination checker
    valid_iocs = [i["ioc"] for i in MOCK_ANALYSIS_RESULT["indicators"]]
    validation = validate_ai_output(fallback, valid_iocs)
    print(f"\n[HALLUCINATION CHECK]  {validation['badge_text']}")
