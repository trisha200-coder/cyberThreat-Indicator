"""
sample_data.py
Owned by: Person 1 (Data & Correlation Module)
Purpose: Provides a rich, realistic 6-stage APT cyber threat intelligence dataset
         with interconnected indicators (IPs, Domains, URLs, MD5/SHA256 hashes, CVEs)
         and MITRE ATT&CK kill-chain telemetry for high-accuracy correlation and AI analysis.
"""

from typing import List, Dict


# 1. BUILT-IN MULTI-STAGE THREAT REPORTS (10 Reports with Attacker Attribution Patterns)

SAMPLE_REPORTS: List[Dict[str, str]] = [
    {
        "id": "REP-01",
        "report_id": "REP-01",
        "title": "Spearphishing Attachment & SSO Credential Harvesting",
        "source": "Proofpoint Email Gateway & SOC Triage",
        "severity": "High",
        "sector": "Financial Services",
        "date": "2026-10-12",
        "text": (
            "Multiple employees in the Finance and Treasury departments received targeted spearphishing "
            "emails carrying a malicious pdf attachment and an urgent password-reset link pointing to "
            "hxxps://auth-update-portal[.]com/sso/login. After a user submitted credentials on "
            "auth-update-portal[.]com, a hidden powershell command executed via cmd.exe and fetched a "
            "stage-1 dropper payload from 185.220.101[.]45 over port 443. Email headers show the "
            "phishing campaign originated from external relay 45.155.205.99 and referenced staging host "
            "login-verification-cloud[.]net. Metadata inside the malicious PDF author field contained the "
            "operator handle 'k0balt_vortex' compiled in timezone UTC+3."
        ),
    },
    {
        "id": "REP-02",
        "report_id": "REP-02",
        "title": "Perimeter Web Server CVE Exploitation & C2 Callback",
        "source": "Palo Alto Perimeter Firewall & Suricata IDS",
        "severity": "Critical",
        "sector": "Financial Services",
        "date": "2026-10-13",
        "text": (
            "Intrusion Detection System (IDS) sensors flagged active vulnerability exploitation of "
            "CVE-2024-21412 and CVE-2023-4966 against the public-facing billing portal. Following "
            "successful exploitation of CVE-2024-21412, the compromised server initiated persistent "
            "outbound Command and Control (C2) beacon callback traffic to 185.220.101.45 every 60 seconds. "
            "Forensic triage of the server recovered a dropper binary with MD5 hash "
            "44d88612fea8a8f36de82e1278abb02f and SHA256 hash "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 containing hardcoded debug "
            "PDB path C:\\Users\\k0balt_vortex\\repos\\ShadowLoader\\stage1.pdb."
        ),
    },
    {
        "id": "REP-03",
        "report_id": "REP-03",
        "title": "Endpoint EDR Alert: LSASS Credential Dumping & Persistence",
        "source": "CrowdStrike Falcon EDR Telemetry",
        "severity": "Critical",
        "sector": "Financial Services",
        "date": "2026-10-14",
        "text": (
            "Endpoint Detection and Response (EDR) quarantined a malicious downloader payload on "
            "workstation FIN-LAPTOP-04 matching MD5 hash 44d88612fea8a8f36de82e1278abb02f. Process tree "
            "telemetry shows the binary was delivered after the user visited auth-update-portal.com. "
            "The malware used certutil as a living off the land lolbin to establish registry run key "
            "persistence under HKCU\\Software\\k0balt_vortex and invoked mimikatz to perform lsass "
            "credential dump activity. Stolen session tokens were staged for outbound transfer to 91.214.124.10."
        ),
    },
    {
        "id": "REP-04",
        "report_id": "REP-04",
        "title": "VPN Gateway Brute Force & Zero-Day Firewall Exploitation",
        "source": "Okta Identity Logs & VPN Concentrator",
        "severity": "High",
        "sector": "Enterprise IT",
        "date": "2026-10-15",
        "text": (
            "Identity telemetry recorded a high-volume password spray and brute force attack against "
            "corporate VPN accounts originating from 45.155.205[.]99 and 185.220.101[.]45 using custom "
            "User-Agent string 'ShadowBot/3.1 (operator:k0balt_vortex)'. Shortly after "
            "the brute force wave, threat actors attempted to exploit CVE-2024-3400 and CVE-2023-4966 "
            "on the edge VPN appliance, invoking wscript to pull a secondary downloader from "
            "hxxps://login-verification-cloud[.]net/stage2/agent.bin with MD5 hash "
            "8b1a9953c4611296a827abf8c47804d7."
        ),
    },
    {
        "id": "REP-05",
        "report_id": "REP-05",
        "title": "Internal Lateral Movement via SMB/WMI & CDN Proxy Tunneling",
        "source": "Core Network NDR & Active Directory Audit",
        "severity": "High",
        "sector": "Core Infrastructure",
        "date": "2026-10-15",
        "text": (
            "Network Detection and Response (NDR) identified lateral movement across internal subnets "
            "using psexec, wmi, and smb from compromised host FIN-LAPTOP-04. The threat actor deployed "
            "a tool matching MD5 hash 8b1a9953c4611296a827abf8c47804d7 and SHA256 hash "
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 to establish a covert "
            "cdn tunnel proxy to telemetry-cdn-edge[.]org and 91.214.124[.]10 using periodic dns query "
            "beaconing signed by TLS certificate subject CN=k0balt_vortex.fin-shadow.ops."
        ),
    },
    {
        "id": "REP-06",
        "report_id": "REP-06",
        "title": "Data Exfiltration Over C2 & Ransomware Pre-Encryption Staging",
        "source": "DLP & Cloud Security Posture Alert",
        "severity": "Critical",
        "sector": "Financial Services",
        "date": "2026-10-16",
        "text": (
            "Data Loss Prevention (DLP) sensors alerted on 4.2 GB of sensitive financial archives being "
            "stolen via exfiltration over C2 channel to 91.214.124.10 and telemetry-cdn-edge.org. "
            "Simultaneously, EDR blocked a ransomware payload (SHA256 "
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae) attempting to encrypt files "
            "and lock file shares across domain controllers after callback verification to "
            "hxxp://cdn-sync-service[.]net/payload.bin. The dropped ransom note was signed by "
            "'k0balt_vortex // FIN-SHADOW Syndicate'."
        ),
    },
    {
        "id": "REP-07",
        "report_id": "REP-07",
        "title": "Dark Web Forum Chatter & Leaked SSH Key Attribution",
        "source": "Recorded Future Dark Web CTI & Threat Hunting",
        "severity": "High",
        "sector": "Threat Intelligence",
        "date": "2026-10-16",
        "text": (
            "Dark web threat intelligence analysts intercepted posts on an exploit market where threat "
            "actor 'k0balt_vortex' (affiliated with FIN-SHADOW Syndicate) advertised access to financial "
            "institutions compromised via CVE-2024-21412 and CVE-2024-3400. An unauthorized SSH key "
            "injected into a compromised jump-box matched comment 'k0balt_vortex@fin-shadow.local' and "
            "initiated reverse tunnel callbacks to 185.220.101[.]45 and cdn-sync-service[.]net."
        ),
    },
    {
        "id": "REP-08",
        "report_id": "REP-08",
        "title": "Supply-Chain Git Mirror Poisoning by Secondary Actor (nightshade_0x)",
        "source": "GitHub Enterprise Audit & DevSecOps Alert",
        "severity": "High",
        "sector": "Technology / DevSecOps",
        "date": "2026-10-16",
        "text": (
            "DevSecOps monitoring detected an unauthorized CI/CD runner pulling a trojanized dependency "
            "from hxxps://api-git-mirror[.]io/v2/update.tar.gz hosted on 194.26.135[.]88. Commit metadata "
            "and GPG signature alias identified secondary threat actor 'nightshade_0x' (VOLT-SPIDER group) "
            "exploiting CVE-2024-21412 and dropping loader MD5 hash d41d8cd98f00b204e9800998ecf8427e."
        ),
    },
    {
        "id": "REP-09",
        "report_id": "REP-09",
        "title": "Cloud IAM Token Replay & S3 Bucket Enumeration (nightshade_0x)",
        "source": "AWS GuardDuty & CloudTrail Security",
        "severity": "High",
        "sector": "Cloud Infrastructure",
        "date": "2026-10-16",
        "text": (
            "AWS GuardDuty flagged anomalous IAM role assumption and stolen credential replay originating "
            "from 194.26.135.88 and callback domain api-git-mirror.io. The attacker executed automated "
            "exfiltration scripts tagged with operator handle 'nightshade_0x' and binary hash "
            "d41d8cd98f00b204e9800998ecf8427e, confirming a recognizable second threat actor pattern "
            "operating in parallel."
        ),
    },
    {
        "id": "REP-10",
        "report_id": "REP-10",
        "title": "Isolated Opportunistic Port Scan (Unattributed / Anonymous Noise)",
        "source": "DMZ Honeypot Sensor",
        "severity": "Low",
        "sector": "Perimeter DMZ",
        "date": "2026-10-16",
        "text": (
            "DMZ honeypot logged a single automated TCP port scan from Tor exit node 103.85.24.11 "
            "With no payload delivery, no shared C2 domains, no file hashes, and no operator signature. "
            "This isolated probe lacks behavioral or infrastructure overlap with known threat actors."
        ),
    },
]


# 2. LIVE DEMO REPORT (Can be injected live during judging)

LIVE_DEMO_REPORT: Dict[str, str] = {
    "id": "REP-11",
    "report_id": "REP-11",
    "title": "CISA Emergency Threat Feed: FIN-SHADOW (k0balt_vortex) Advisory",
    "source": "CISA / FS-ISAC Joint Advisory",
    "severity": "Critical",
    "sector": "Cross-Sector Advisory",
    "date": "2026-10-16",
    "text": (
        "CISA and FS-ISAC warn of an active APT ransomware campaign led by threat actor "
        "'k0balt_vortex' (FIN-SHADOW Syndicate) chaining CVE-2024-21412 and CVE-2024-3400 for initial "
        "access, followed by lateral movement via smb and wmi. Known attacker infrastructure includes "
        "185.220.101[.]45, 91.214.124[.]10, and hxxp://cdn-sync-service[.]net/payload.bin delivering "
        "ransomware loader SHA256 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae."
    ),
}


# 3. HELPER FUNCTIONS

def get_default_reports() -> List[Dict[str, str]]:
    """
    Returns a fresh copy of the built-in threat reports so the frontend
    can append custom reports without mutating the original list.
    """
    return [report.copy() for report in SAMPLE_REPORTS]


def get_live_demo_text() -> str:
    """
    Returns the raw text of the live demo report so Person 3 can add a quick
    'Fill Demo Report' button or copy-paste it live during judging.
    """
    return LIVE_DEMO_REPORT["text"]


# 4. SELF-TEST BLOCK

if __name__ == "__main__":
    reports = get_default_reports()
    print(f"✅ Successfully loaded {len(reports)} built-in threat reports:")
    for r in reports:
        print(
            f"  - [{r['id']}] ({r['severity']}) {r['title']} ({r['date']}) | Source: {r['source']}"
        )
    print("\n✅ Live Demo Report ready for presentation:")
    print(f"  - [{LIVE_DEMO_REPORT['id']}] {LIVE_DEMO_REPORT['title']}")
