"""
evaluate_accuracy.py
Purpose: Quantitatively benchmarks the accuracy of the Securify AI Threat Intelligence
         Fusion Engine & Model Harness across 4 core dimensions:
           1. IOC Extraction Precision, Recall, and F1-Score (Ground Truth vs. analyzer.py)
           2. Cross-Report Correlation Accuracy (Ground Truth Bridges vs. Detected Bridges)
           3. MITRE ATT&CK Technique Mapping Recall (14 Kill-Chain Techniques)
           4. AI Hallucination Guardrail Rate (Verified IOCs vs. Unverified/Invented IOCs)
"""

from sample_data import get_default_reports
from analyzer import analyze_reports
from ai_engine import generate_ai_assessment, validate_ai_output, calculate_risk, map_mitre_techniques

# 1. Ground-Truth IOCs planted across REP-01 through REP-10 (22 Unique IOCs)
GROUND_TRUTH_IOCS = {
    "185.220.101.45",
    "45.155.205.99",
    "91.214.124.10",
    "194.26.135.88",
    "103.85.24.11",
    "auth-update-portal.com",
    "login-verification-cloud.net",
    "telemetry-cdn-edge.org",
    "cdn-sync-service.net",
    "api-git-mirror.io",
    "https://auth-update-portal.com/sso/login",
    "https://login-verification-cloud.net/stage2/agent.bin",
    "http://cdn-sync-service.net/payload.bin",
    "https://api-git-mirror.io/v2/update.tar.gz",
    "44d88612fea8a8f36de82e1278abb02f",
    "8b1a9953c4611296a827abf8c47804d7",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "CVE-2024-21412",
    "CVE-2023-4966",
    "CVE-2024-3400",
}

# 2. Ground-Truth Shared Pivot IOCs (appearing in >= 2 reports: 16 Bridges)
GROUND_TRUTH_SHARED = {
    "185.220.101.45",
    "91.214.124.10",
    "45.155.205.99",
    "194.26.135.88",
    "CVE-2024-21412",
    "CVE-2023-4966",
    "CVE-2024-3400",
    "auth-update-portal.com",
    "login-verification-cloud.net",
    "telemetry-cdn-edge.org",
    "cdn-sync-service.net",
    "api-git-mirror.io",
    "44d88612fea8a8f36de82e1278abb02f",
    "8b1a9953c4611296a827abf8c47804d7",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# 3. Ground-Truth MITRE ATT&CK Technique IDs planted in REP-01..REP-10
GROUND_TRUTH_MITRE = {
    "T1566", "T1190", "T1071", "T1110", "T1021", "T1486", "T1041",
    "T1547", "T1059", "T1105", "T1090", "T1218", "T1003", "T1566.001"
}

# 4. Ground-Truth Per-Report Attacker Recognizability (True = Recognizable, False = Not Recognizable)
GROUND_TRUTH_RECOGNIZABILITY = {
    "REP-01": (True, "k0balt_vortex"),
    "REP-02": (True, "k0balt_vortex"),
    "REP-03": (True, "k0balt_vortex"),
    "REP-04": (True, "k0balt_vortex"),
    "REP-05": (True, "k0balt_vortex"),
    "REP-06": (True, "k0balt_vortex"),
    "REP-07": (True, "k0balt_vortex"),
    "REP-08": (True, "nightshade_0x"),
    "REP-09": (True, "nightshade_0x"),
    "REP-10": (False, "Unknown"),
}


def run_benchmark():
    reports = get_default_reports()
    analysis = analyze_reports(reports)
    ai_result = generate_ai_assessment(reports, analysis)

    extracted_iocs = {i["ioc"] for i in analysis["indicators"]}
    detected_shared = {c["ioc"] for c in analysis["connections"]}

    # Precision, Recall, F1 for IOC Extraction
    tp = len(GROUND_TRUTH_IOCS & extracted_iocs)
    fp = len(extracted_iocs - GROUND_TRUTH_IOCS)
    fn = len(GROUND_TRUTH_IOCS - extracted_iocs)

    precision = (tp / (tp + fp)) * 100 if (tp + fp) else 0.0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    # Correlation Bridge Accuracy
    shared_tp = len(GROUND_TRUTH_SHARED & detected_shared)
    corr_accuracy = (shared_tp / len(GROUND_TRUTH_SHARED)) * 100

    # MITRE ATT&CK Mapping Coverage
    all_text = " ".join(r.get("text", "") for r in reports)
    mapped_mitre = {t["id"] for t in map_mitre_techniques(all_text)}
    mitre_recall = (len(GROUND_TRUTH_MITRE & mapped_mitre) / len(GROUND_TRUTH_MITRE)) * 100

    # Attacker Recognizability & Attribution Accuracy
    attr_list = analysis.get("attribution", {}).get("per_report_attribution", [])
    attr_correct = 0
    for item in attr_list:
        r_id = item["report_id"]
        if r_id in GROUND_TRUTH_RECOGNIZABILITY:
            exp_rec, exp_actor = GROUND_TRUTH_RECOGNIZABILITY[r_id]
            if item["recognizable"] == exp_rec and exp_actor in item["attacker_handle"]:
                attr_correct += 1
    attr_accuracy = (attr_correct / len(GROUND_TRUTH_RECOGNIZABILITY)) * 100

    # Hallucination Guardrail Audit
    validation = validate_ai_output(ai_result, list(extracted_iocs))
    hallucination_rate = (len(validation["hallucinated_iocs"]) / max(1, len(extracted_iocs))) * 100

    print("=" * 74)
    print("📊 SECURIFY AI THREAT INTELLIGENCE — MODEL & HARNESS ACCURACY REPORT")
    print("=" * 74)
    print(f"1. IOC Extraction Precision   : {precision:6.2f}%  (True Positives: {tp}/{len(extracted_iocs)}, False Positives: {fp})")
    print(f"2. IOC Extraction Recall      : {recall:6.2f}%  (Detected: {tp}/{len(GROUND_TRUTH_IOCS)} Ground-Truth IOCs)")
    print(f"3. IOC Extraction F1-Score    : {f1:6.2f}%")
    print(f"4. Cross-Report Correlation   : {corr_accuracy:6.2f}%  (Bridges Matched: {shared_tp}/{len(GROUND_TRUTH_SHARED)})")
    print(f"5. MITRE ATT&CK Coverage      : {mitre_recall:6.2f}%  (Techniques Mapped: {len(mapped_mitre)}/{len(GROUND_TRUTH_MITRE)})")
    print(f"6. Attacker Attribution Acc.  : {attr_accuracy:6.2f}%  (Reports Correctly Attributed: {attr_correct}/{len(GROUND_TRUTH_RECOGNIZABILITY)})")
    print(f"7. AI Hallucination Rate      : {hallucination_rate:6.2f}%  ({validation['badge_text']})")
    print(f"8. Active Model Harness       : {ai_result.get('model_used')}")
    print("=" * 74)


if __name__ == "__main__":
    run_benchmark()
