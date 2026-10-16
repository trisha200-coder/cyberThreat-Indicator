"""
sample_data.py
Owned by: Person 1 (Data & Correlation Module)
Purpose: Provides synthetic, interconnected threat intelligence reports for the MVP
         and a 4th "Live Demo" report to paste during the final presentation.
"""

from typing import List, Dict

# =====================================================================
# 1. CORE BUILT-IN THREAT REPORTS (Loaded by default on the dashboard)
# =====================================================================
SAMPLE_REPORTS: List[Dict[str, str]] = [
    {
        "id": "REP-01",
        "title": "Spearphishing Campaign Targeting Finance Personnel",
        "source": "Internal SOC Email Gateway",
        "date": "2026-10-14",
        "text": (
            "Multiple employees in the Finance department received urgent password-reset emails "
            "spoofing corporate IT. The email body contained a credential harvesting link pointing to "
            "hxxps://auth-update-portal[.]com/sso/login. Network packet capture shows that after "
            "a user submitted credentials on auth-update-portal[.]com, a secondary script fetched "
            "a stage-1 loader from 185.220.101[.]45 over port 443. The phishing emails originated "
            "from the external mail relay 45.155.205.99."
        ),
    },
    {
        "id": "REP-02",
        "title": "Perimeter Web Server Exploitation & Outbound C2",
        "source": "Perimeter Firewall & IDS Logs",
        "date": "2026-10-15",
        "text": (
            "Intrusion Detection System (IDS) alerts flagged active exploitation of CVE-2024-21412 "
            "against the public-facing billing server. Following successful exploitation of CVE-2024-21412, "
            "the server established persistent outbound Command and Control (C2) beaconing to "
            "185.220.101.45 every 60 seconds. Forensic triage of the web server's temp directory "
            "recovered a dropped payload with MD5 hash 44d88612fea8a8f36de82e1278abb02f and "
            "SHA256 hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
        ),
    },
    {
        "id": "REP-03",
        "title": "Endpoint EDR Alert: Credential Stealer Detonation",
        "source": "CrowdStrike / EDR Telemetry",
        "date": "2026-10-16",
        "text": (
            "Endpoint Detection and Response (EDR) quarantined a suspicious binary executing on "
            "workstation FIN-LAPTOP-04. The binary matches MD5 hash 44d88612fea8a8f36de82e1278abb02f. "
            "Process tree analysis reveals the executable was downloaded after the user visited "
            "auth-update-portal.com via Chrome. Before quarantine, the malware attempted to exfiltrate "
            "browser session tokens to an uncategorized external IP address at 91.214.124.10."
        ),
    },
]

# =====================================================================
# 2. LIVE DEMO REPORT (For pasting into the UI during the 90-sec pitch)
# =====================================================================
LIVE_DEMO_REPORT: Dict[str, str] = {
    "id": "REP-04",
    "title": "External Threat Feed Alert: Ransomware Pre-Staging",
    "source": "CISA / ISAC Threat Intel Feed",
    "date": "2026-10-16",
    "text": (
        "Threat intelligence partners warn of an active ransomware pre-staging cluster scanning "
        "enterprise networks for CVE-2024-21412. Compromised hosts are observed exfiltrating "
        "active directory data to 91.214.124[.]10 and pulling lateral movement tools from "
        "hxxp://cdn-sync-service[.]net/payload.bin."
    ),
}


# =====================================================================
# 3. HELPER FUNCTIONS (Used by analyzer.py and app.py)
# =====================================================================
def get_default_reports() -> List[Dict[str, str]]:
    """
    Returns a fresh copy of the 3 built-in threat reports so the frontend
    can append custom reports without mutating the original list.
    """
    return [report.copy() for report in SAMPLE_REPORTS]


def get_live_demo_text() -> str:
    """
    Returns the raw text of the 4th report so Person 3 can add a quick
    'Fill Demo Report' button or you can copy-paste it live during judging.
    """
    return LIVE_DEMO_REPORT["text"]


# =====================================================================
# 4. SELF-TEST BLOCK (Run `python3 sample_data.py` to verify)
# =====================================================================
if __name__ == "__main__":
    reports = get_default_reports()
    print(f"✅ Successfully loaded {len(reports)} built-in threat reports:")
    for r in reports:
        print(f"  - [{r['id']}] {r['title']} ({r['date']}) | Source: {r['source']}")
    print("\n✅ Live Demo Report ready for presentation:")
    print(f"  - [{LIVE_DEMO_REPORT['id']}] {LIVE_DEMO_REPORT['title']}")
