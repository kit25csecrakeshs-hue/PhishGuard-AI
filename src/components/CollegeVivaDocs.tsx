import React, { useState } from 'react';
import {
  GraduationCap,
  BookOpen,
  Cpu,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  FileText,
  Shield,
  Layers,
  CheckCircle2,
} from 'lucide-react';

export const CollegeVivaDocs: React.FC = () => {
  const [openVivaId, setOpenVivaId] = useState<number | null>(0);

  const vivaQuestions = [
    {
      q: 'Q1: What is the core architecture and working methodology of PhishGuard-AI?',
      a: 'PhishGuard-AI is an end-to-end cyber threat assessment pipeline composed of five functional layers: (1) Lexical & Structural Feature Extractor extracting 18 distinct indicators (URL length, Shannon entropy, Punycode, suspicious keywords, @ tricks, IP hosts), (2) RDAP & DNS Network Intelligence inspecting domain registration age and nameservers with SSRF screening, (3) Ensemble Random Forest Machine Learning Model calibrated via logistic sigmoids into true probability estimates, (4) External Threat Feeds integrating Google Safe Browsing and VirusTotal with TTL caching, and (5) Gemini AI Semantic Synthesis providing human-readable explanations.',
    },
    {
      q: 'Q2: How does PhishGuard-AI calculate the 0-100 Multi-Factor Risk Score?',
      a: 'The Risk Score combines three weighted pillars: (1) Heuristic Static & Host Analysis (40%) evaluating acute threat markers like IP hosts (+25 pts), sensitive keywords (+22 pts), @ authority tricks (+20 pts), and young domain age (+18 pts); (2) Network DNS & Threat Feed Intelligence (25%); and (3) Calibrated Random Forest Model Confidence (35%). The combined score maps into Low Risk (0-34), Medium Risk (35-64), and High Risk (65-100).',
    },
    {
      q: 'Q3: Why is a heuristic score distinguished from a calibrated ML probability?',
      a: 'Heuristic rules represent deterministic, rule-based red flags designed to catch known structural anomalies quickly. Calibrated ML probabilities represent a trained statistical model mapping continuous features to a probabilistic likelihood P(phishing | features). Presenting both independently ensures transparency, prevents arbitrary score conflation, and aligns with explainable AI (XAI) security guidelines.',
    },
    {
      q: 'Q4: How does the Email and SMS Message Scam Detector work?',
      a: 'The Message Scam Detector performs multi-stage inspection: First, a regex parser extracts all embedded URLs and executes the full URL scanning pipeline. Second, a natural language rule engine detects social engineering triggers: urgency deadlines ("within 24 hours"), credential theft ("verify your identity"), OTP code elicitation ("reply with 6-digit pin"), and fake prizes. A multi-vector synergy bonus is applied when urgency and credential theft coincide. When configured, Gemini AI synthesizes deep contextual analysis.',
    },
    {
      q: 'Q5: How does PhishGuard-AI protect against Server-Side Request Forgery (SSRF)?',
      a: 'The system validates and screens all submitted hosts before any network resolution. It checks both domain names and resolved IP addresses against private and reserved IPv4/IPv6 subnets: 127.0.0.0/8 (loopback), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918), and 169.254.169.254 (cloud metadata services). Any query resolving to internal address space is blocked immediately.',
    },
    {
      q: 'Q6: Why doesn’t PhishGuard-AI declare a website "100% Safe" if no warnings are found?',
      a: 'In cybersecurity, the absence of known malicious signatures is not proof of absolute safety. Sophisticated zero-day phishing campaigns often deploy brand-new domains, obtain valid Let’s Encrypt TLS certificates, and delay malicious payload activation until after initial automated crawls. PhishGuard-AI explicitly classifies these as "Low Risk" and displays a mandatory disclaimer reminding users to maintain verification hygiene.',
    },
    {
      q: 'Q7: How is the Chrome Browser Extension architected under Manifest V3?',
      a: 'The browser extension uses Google’s latest Manifest V3 standard. It requests minimal permissions ("activeTab" and "storage") and executes user-initiated scans. It communicates securely over CORS with the PhishGuard backend API (/api/scan), contains zero hardcoded API secrets, and strictly adheres to privacy principles by never logging or transmitting browsing history.',
    },
    {
      q: 'Q8: What database schema and authentication mechanisms are implemented?',
      a: 'The system implements role-based relational data persistence with tables for Users, Scans, Features, Domain Intelligence, DNS, and Message Scans. Authentication uses PBKDF2 password derivation with random 16-byte cryptographic salts and HMAC-SHA256 bearer tokens.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <GraduationCap className="w-5 h-5 text-cyan-400" />
            Academic Documentation, Architecture & Viva Guide
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Comprehensive system documentation, architectural flow diagrams, methodology notes, and viva voce interview preparation for college project defense.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded-lg font-mono">
            College Viva Voce Ready
          </span>
        </div>
      </div>

      {/* System Architecture Flow Diagram */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          PhishGuard-AI System Architecture Pipeline
        </h2>

        <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs overflow-x-auto text-slate-300">
          <pre className="leading-relaxed">
{`+----------------------------------------------------------------------------------------------------+
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
+----------------------------------------------------------------------------------------------------+`}
          </pre>
        </div>
      </div>

      {/* College Project Abstract & Module Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <h3 className="text-sm font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
            <BookOpen className="w-4 h-4" />
            Project Abstract
          </h3>
          <p className="text-xs text-slate-300 leading-relaxed">
            Phishing attacks and social engineering scams remain the leading entry vector for organizational breaches, credential theft, and financial fraud. <strong>PhishGuard-AI</strong> presents an intelligent, explainable cybersecurity threat detection system combining lexical feature extraction, RDAP domain telemetry, ensemble Random Forest machine learning, and external threat intelligence APIs.
          </p>
          <p className="text-xs text-slate-300 leading-relaxed">
            Unlike opaque black-box scanners, PhishGuard-AI details the specific technical contributions of flagged anomalies (such as IP-based hosts, Punycode spoofing, and excessive entropy), distinguishes heuristic alerts from calibrated model probabilities, and provides real-time in-browser protection via a Manifest V3 Chrome Extension.
          </p>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
          <h3 className="text-sm font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            Core Module Breakdown
          </h3>
          <ul className="space-y-2 text-xs text-slate-300">
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong>Module 1: URL Feature Engineering:</strong> Extracts 18 lexical and host parameters including Shannon entropy and Punycode.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong>Module 2: Calibrated Random Forest Model:</strong> 12 decision trees evaluating feature weights with sigmoid calibration.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong>Module 3: Message Scam Detector:</strong> Natural language detection of urgent deadlines, OTP elicitation, and fake prizes.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong>Module 4: Threat Intel & SSRF Defense:</strong> Google Safe Browsing, VirusTotal, and private IP screening.</span>
            </li>
            <li className="flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span><strong>Module 5: Manifest V3 Browser Extension:</strong> Active tab scanning with zero user tracking.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* College Viva Voce Questions & Answers Accordion */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-cyan-400" />
          Viva Voce Defense Questions & Model Answers
        </h2>
        <p className="text-xs text-slate-400">
          Frequently asked viva questions during academic evaluation with verified technical responses:
        </p>

        <div className="space-y-3">
          {vivaQuestions.map((item, idx) => {
            const isOpen = openVivaId === idx;
            return (
              <div
                key={idx}
                className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden transition-all"
              >
                <button
                  onClick={() => setOpenVivaId(isOpen ? null : idx)}
                  className="w-full p-3.5 text-left text-xs font-semibold text-slate-200 flex items-center justify-between hover:text-cyan-300 transition-colors"
                >
                  <span>{item.q}</span>
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4 text-cyan-400 shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                  )}
                </button>

                {isOpen && (
                  <div className="px-3.5 pb-3.5 text-xs text-slate-300 leading-relaxed border-t border-slate-800/60 pt-2.5 bg-slate-900/30">
                    {item.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
