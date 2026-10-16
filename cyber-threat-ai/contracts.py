# Shared data contract for the cyber threat intelligence project

# contracts.py — DO NOT CHANGE KEYS WITHOUT TELLING THE TEAM
MOCK_ANALYSIS_RESULT = {
    "metrics": {
        "total_reports": 3,
        "total_iocs": 7,
        "shared_iocs": 2,
        "campaign_confidence": 85  # 0-100 score
    },
    "indicators": [
        {"ioc": "185.220.101.45", "type": "IPv4", "reports": ["REP-01", "REP-02"], "shared": True},
        {"ioc": "auth-update-portal.com", "type": "Domain", "reports": ["REP-01", "REP-03"], "shared": True},
        {"ioc": "CVE-2024-21412", "type": "CVE", "reports": ["REP-02"], "shared": False},
        {"ioc": "44d88612fea8a8f36de82e1278abb02f", "type": "MD5", "reports": ["REP-03"], "shared": False},
    ],
    "connections": [
        {
            "ioc": "185.220.101.45",
            "type": "IPv4",
            "linked_reports": ["REP-01", "REP-02"],
            "evidence": "Used as C2 callback in REP-01 and brute-force source in REP-02"
        }
    ],
    "graph_edges": [
        # (source_node, target_node, node_type_source, node_type_target)
        ("REP-01", "185.220.101.45", "Report", "IPv4"),
        ("REP-02", "185.220.101.45", "Report", "IPv4"),
        ("REP-01", "auth-update-portal.com", "Report", "Domain"),
        ("REP-03", "auth-update-portal.com", "Report", "Domain"),
    ]
}

MOCK_AI_RESULT = {
    "risk_level": "HIGH",  # LOW, MEDIUM, HIGH, CRITICAL
    "risk_score": 82,
    "executive_summary": "High-confidence correlation between 3 incidents indicates a coordinated phishing-to-C2 campaign sharing infrastructure.",
    "evidence_facts": [
        "IP 185.220.101.45 bridges Phishing Report (REP-01) and Exploitation Report (REP-02).",
        "Domain auth-update-portal.com links initial access in REP-01 to payload delivery in REP-03."
    ],
    "ai_hypotheses": [
        "Likely single threat actor reusing C2 infrastructure across staging and execution phases.",
        "Possible credential harvesting preceding CVE-2024-21412 exploitation."
    ],
    "mitre_techniques": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
    ],
    "defensive_actions": [
        "[IMMEDIATE] Block IP 185.220.101.45 and domain auth-update-portal.com at perimeter firewall/DNS.",
        "[HUNT] Query SIEM logs over last 30 days for outbound connections to 185.220.101.45.",
        "[PATCH] Remediate CVE-2024-21412 on exposed endpoints referenced in REP-02."
    ]
}
