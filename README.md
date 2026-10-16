# 🛡️ Securify // AI Threat Intelligence Fusion Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AI: Open-Weight Llama 3.3](https://img.shields.io/badge/Open--Weight%20AI-Llama%203.3%2070B-orange)](https://www.digitalocean.com/products/genai-platform)
[![Harness: Cyber Threat Verification](https://img.shields.io/badge/Model%20Harness-IOC%20Grounding%20%2B%20Hallucination%20Guardrail-blue)](#model-harness-architecture)

An AI-powered Cyber Threat Intelligence (CTI) Fusion Engine and **Open-Weight Model Verification Harness** that ingests fragmented security incident reports, extracts and refangs Indicators of Compromise (IOCs), correlates multi-stage attack campaigns across a bipartite threat graph, maps adversary behavior to **MITRE ATT&CK**, and generates hallucination-checked defensive playbooks.

---

## Open-Weight AI & Model Harness Architecture

This project implements an **original domain-specific Model Harness** built around open-weight Large Language Models (such as **Meta Llama 3.3 70B Instruct** / **Mistral** hosted on the **DigitalOcean GenAI Platform** or local **Ollama**):

1. **Stage 1 — Deterministic Evidence Grounding (`analyzer.py`):**
   * Refangs obfuscated indicators (`hxxps://` ➔ `https://`, `185.220.101[.]45` ➔ `185.220.101.45`).
   * Extracts `IPv4`, `Domain`, `URL`, `MD5`, `SHA256`, and `CVE` indicators with sentence-level provenance.
   * Builds a cross-report correlation graph identifying shared infrastructure pivot nodes.
2. **Stage 2 — Constrained Open-Weight Inference (`ai_engine.py`):**
   * Connects to **DigitalOcean GenAI Platform** (`https://inference.do-ai.run/v1`) running open-weight **Llama 3.3 70B Instruct**.
   * Injects a strict `VERIFIED IOCs` allow-list into the model context and enforces structured JSON output separating confirmed `evidence_facts` from analytical `ai_hypotheses`.
3. **Stage 3 — Post-Generation Hallucination Audit & Deterministic Fallback (`validate_ai_output`):**
   * Scans all generated model output for IPv4, Domain, CVE, and Hash patterns and cross-verifies every cited indicator against Stage 1's regex ground truth.
   * Provides a deterministic MITRE ATT&CK keyword mapper (14 techniques) and rule-based risk scorer (`0–100`) as an automatic zero-downtime fallback.

---

##  Quick Start

### 1. Install Dependencies
```bash
cd cyber-threat-ai
pip install -r requirements.txt
```

### 2. Configure DigitalOcean GenAI (Open-Weight Model)
**Mac / Linux:**
```bash
export DIGITALOCEAN_API_KEY="your-digitalocean-genai-key"
export DO_BASE_URL="https://inference.do-ai.run/v1"
export DO_MODEL="llama3.3-70b-instruct"
```

**Windows PowerShell (VS Code):**
```powershell
$env:DIGITALOCEAN_API_KEY="your-digitalocean-genai-key"
$env:DO_BASE_URL="https://inference.do-ai.run/v1"
$env:DO_MODEL="llama3.3-70b-instruct"
```
*(Note: If no API key is set, the harness automatically runs in offline deterministic rule-based mode.)*

### 3. Run the Dashboard
```bash
python -m streamlit run app.py
```

---

## 📜 Open-Source License & Attribution

* **Source Code License:** Released under the open-source **[MIT License](LICENSE)**.
* **Open-Weight Model & Inference:** Powered by open-weight models (`llama3.3-70b-instruct`) via **DigitalOcean GenAI Platform** / **Ollama**.
