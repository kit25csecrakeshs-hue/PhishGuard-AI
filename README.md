# PhishGuard-AI: AI-Based Phishing URL Detection, Scam Analysis, and Cyber Threat Protection System

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Manifest V3](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-blue)]()
[![TypeScript](https://img.shields.io/badge/Language-TypeScript-blue)]()
[![Framework](https://img.shields.io/badge/Framework-React%2019%20%7C%20Express-cyan)]()

## Project Abstract
Phishing attacks and social engineering scams remain the leading entry vectors for cybersecurity breaches, unauthorized credential harvesting, and identity theft. Traditional blacklist-based countermeasures fail against ephemeral zero-day domains, randomized subdomains, and obfuscated link shorteners. 

**PhishGuard-AI** is a comprehensive, explainable cyber threat intelligence and protection platform that bridges static heuristic inspection, domain telemetry (RDAP & DNS), ensemble machine learning (calibrated Random Forest), external threat intelligence feeds (Google Safe Browsing & VirusTotal), and real-time in-browser protection via a Chrome Extension (Manifest V3).

---

## System Architecture Pipeline

```text
+----------------------------------------------------------------------------------------------------+
|                                USER CLIENT INTERACTION LAYER                                       |
|   [ React 19 Frontend Web Dashboard ]   <---------->   [ Chrome Extension (Manifest V3) ]          |
+-------------------------------------------------+--------------------------------------------------+
                                                  | REST API Requests (/api/scan, /api/message-scam)
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                 BACKEND SECURITY ORCHESTRATION                                     |
|  - CORS & Rate Limiting    - SSRF Address Screening    - PBKDF2 / HMAC Cryptographic Auth          |
+--------------------+----------------------------+------------------------------------+-------------+
                     |                            |                                    |
                     v                            v                                    v
+-----------------------------+  +----------------------------------+  +-----------------------------+
|    LEXICAL FEATURE ENGINE   |  |   DOMAIN & DNS NETWORK INTEL     |  |  EXTERNAL THREAT INTEL      |
|  - 18 Structural Features   |  |  - RDAP WHOIS Domain Age Lookup  |  |  - Google Safe Browsing v4  |
|  - Shannon Entropy Obf.     |  |  - DNS IPv4/IPv6 Resolution      |  |  - VirusTotal API v3        |
|  - Punycode & Subdomains    |  |  - Private IP Defense Block      |  |  - In-Memory 1-Hour TTL     |
+--------------+--------------+  +----------------+-----------------+  +--------------+--------------+
               |                                  |                                   |
               +----------------------------------+-----------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                         AI & MULTI-FACTOR MACHINE LEARNING RISK ENGINE                             |
|  - Calibrated Random Forest Ensemble (12 Feature Decision Trees)                                  |
|  - Logistic Sigmoid Probability Calibration: P = 1 / (1 + exp(-k * (x - x0)))                      |
|  - Gemini 3.8 Flash Deep Explanatory Synthesis & Social Engineering Pretexting Analysis             |
|  - Composite Risk Engine (0-100 Score, Low/Medium/High Risk, Granular Indicator Penalties)         |
+-------------------------------------------------+--------------------------------------------------+
                                                  |
                                                  v
+----------------------------------------------------------------------------------------------------+
|                                PERSISTENCE & ANALYTICS DATA STORE                                  |
|  [ In-Memory Relational Database Engine: Users, Scans, Features, DomainIntel, MessageScans, CSV ]  |
+----------------------------------------------------------------------------------------------------+
```

---

## Core Feature Modules

### 1. AI Risk Score & Explainable URL Detection
- **Multi-Factor Score (0-100)**: Transparently combines Heuristic Signals (40%), Network/DNS Signals (25%), and ML Probability (35%).
- **Calibrated Probabilities**: Distinguishes deterministic heuristic red flags from calibrated ensemble model probabilities.
- **18 Extracted Structural Features**: Evaluates IP hosts, deep subdomains, URL shorteners, Shannon entropy, Punycode IDN homographs, sensitive keywords, and anomalous parameters.
- **Explainability**: Details exact detected indicators and their respective point contributions (e.g. `+25 pts for Direct IP Host`).
- **Defensive Recommendations**: Prescribes prioritized security steps and includes mandatory disclaimers noting that absence of detections does not imply absolute safety.

### 2. Email & SMS Message Scam Detector
- **Social Engineering Vector Detection**: Scans message text for artificial urgency triggers, credential theft pretexting, OTP/PIN elicitation, fake prizes, and authority impersonation.
- **Embedded Link Extraction**: Automatically extracts all URLs from message bodies and executes the full URL detection pipeline.
- **Multi-Vector Synergy**: Detects classic phishing pairs (e.g. urgency + credential theft) to accurately identify smishing attacks.
- **Legitimate Message Resilience**: Accurately recognizes benign interpersonal communications without false-positive alarms.

### 3. Scan History & Analytics Dashboard
- **Relational Data Persistence**: Stores scans, features, domain metadata, and message results associated with user accounts.
- **Forensic Records & Detail Modal**: Allows deep retrospective inspection of historical scan telemetry.
- **Search, Filter & Sorting**: Filter by High/Medium/Low Risk, search by domain or keyword.
- **CSV Export**: One-click download of scan history for SOC reports and academic documentation.
- **KPI Metrics**: Real-time stats on scan volume, classification breakdowns, and top flagged vectors.

### 4. Google Safe Browsing & VirusTotal Threat Intelligence
- **Vendor Reputation**: Integrates Google Safe Browsing v4 threat matches and VirusTotal v3 multi-antivirus reputation.
- **Server-Side Security**: API keys are securely managed via server environment variables, never exposed in client bundles.
- **TTL Cache & Backoff**: 1-hour in-memory cache to respect API rate limits and avoid duplicate external calls.
- **Graceful Fallbacks**: Works out of the box with clear status indicators when keys are unconfigured.

### 5. Chrome Browser Extension (Manifest V3)
- **Active Tab Protection**: Automatically extracts the current tab URL on user invocation.
- **Visual Alert Badges**: Immediate color-coded feedback (Rose High Risk, Amber Medium Risk, Emerald Low Risk).
- **Zero Background Tracking**: Privacy-first architecture requesting only `activeTab` and `storage` permissions without recording browsing history.
- **One-Click Report Copying**: Copies formatted scan output to the clipboard.

---

## Installation & Execution Guide

### Prerequisites
- Node.js (version 20 or higher)
- npm or bun

### Step 1: Clone Repository
```bash
git clone https://github.com/kit25csecrakeshs-hue/PhishGuard-AI.git
cd PhishGuard-AI
```

### Step 2: Install Dependencies
```bash
npm install
```

### Step 3: Environment Variables Setup
Copy the template file to configure your local environment:
```bash
cp .env.example .env
```
Fill in the optional keys:
- `GEMINI_API_KEY`: API key for Gemini AI semantic reasoning.
- `GOOGLE_SAFE_BROWSING_API_KEY`: Google Cloud Safe Browsing API key.
- `VIRUSTOTAL_API_KEY`: VirusTotal v3 API key.

### Step 4: Run Development Server
```bash
npm run dev
```
The server will start at `http://localhost:3000`.

### Step 5: Run Automated Tests
```bash
npm test
```
Executes all 28 automated test assertions covering feature extraction, ML classification, scam heuristics, SSRF defense, and threat caching.

---

## Chrome Browser Extension Setup

1. In Chrome, navigate to `chrome://extensions/`.
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked** in the top-left corner.
4. Select the `extension/` directory located in the project folder.
5. The **PhishGuard-AI Shield** icon will appear in your browser toolbar!

---

## Demo Script & Viva Voce Q&A (For College Evaluation)

### 3-Minute Demonstration Script
1. **Introduction**: Open the dashboard and highlight the multi-layered defense architecture (URL Scanner, Message Scam Detector, Threat Intel, Chrome Extension).
2. **Flagship URL Scan**: Select the preset "IP Host Credential Kit" (`http://192.168.1.104/secure-chase-login`). Point out the instant 94/100 High Risk assessment, the Random Forest ML probability vs heuristic score breakdown, and the +25 pts IP indicator.
3. **Message Scam Detector**: Navigate to the Message Scam tab. Click the "Chase Bank Smishing SMS" preset. Point out the extracted link analysis, the OTP/credential theft flags, and the automated disclaimer.
4. **Scan History & CSV**: Show the persisted database record in the Scan History tab and click "Export CSV".
5. **Browser Extension**: Open the Browser Extension tab and demonstrate the interactive popup simulator and Manifest V3 permissions.

### Common Viva Voce Questions & Answers
- **Q: What algorithm is used for detection?**  
  *A:* An ensemble Random Forest model evaluating 12 feature decision trees with logistic sigmoid calibration ($P = 1 / (1 + e^{-k(x - x_0)})$) combined with heuristic structural indicators and external threat intelligence.
- **Q: How are zero-day phishing sites handled?**  
  *A:* Newly registered domains lacking historical blacklist records are flagged through structural heuristics (Shannon entropy, domain age < 30 days via RDAP, sensitive keywords, and shortener detection).
- **Q: How does the system prevent SSRF attacks?**  
  *A:* Prior to any resolution, submitted hosts are screened against private, loopback, and cloud metadata IP ranges (127.0.0.0/8, 10.0.0.0/8, 169.254.169.254).

---

## Limitations & Future Enhancements
- **Current Limitations**: RDAP WHOIS queries depend on TLD registrar response availability; client-side extension requires backend network reachability.
- **Future Enhancements**: Visual brand logo spoofing detection via computer vision (comparing favicon and DOM screenshots), and automated email header DKIM/SPF verification.

## License
Apache-2.0 License. Developed for Cybersecurity Research & Education.
