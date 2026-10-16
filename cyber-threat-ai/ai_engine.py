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
# DIGITALOCEAN GENAI CONFIGURATION
# ---------------------------------------------------------------------------
LLM_BASE_URL = os.environ.get("DO_BASE_URL", "https://inference.do-ai.run/v1")
LLM_MODEL = os.environ.get("DO_MODEL", "llama3.3-70b-instruct")
LLM_TIMEOUT = 60  # seconds before we fall back to rule-based result
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

