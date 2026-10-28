import React, { useState } from 'react';
import {
  Search,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Info,
  ExternalLink,
  Copy,
  Check,
  Server,
  Calendar,
  Layers,
  ChevronRight,
  Sparkles,
} from 'lucide-react';
import type { ScanResult } from '../types.js';

interface UrlScannerProps {
  onScanComplete?: (result: ScanResult) => void;
  token?: string | null;
}

const PRESET_URLS = [
  {
    label: 'IP Host Credential Kit',
    url: 'http://192.168.1.104/secure-chase-login/verify.html?session=9284',
    type: 'HIGH RISK',
  },
  {
    label: 'Shortener Masked Lure',
    url: 'https://bit.ly/paypal-urgent-resolution-center',
    type: 'SUSPICIOUS',
  },
  {
    label: 'Subdomain Brand Spoof',
    url: 'https://secure.login.apple.com.account-verify.xyz/signin',
    type: 'HIGH RISK',
  },
  {
    label: 'Legitimate Repository',
    url: 'https://github.com/kit25csecrakeshs-hue/PhishGuard-AI',
    type: 'LOW RISK',
  },
  {
    label: 'Official Google Portal',
    url: 'https://accounts.google.com/signin/v2/identifier',
    type: 'LOW RISK',
  },
];

export const UrlScanner: React.FC<UrlScannerProps> = ({ onScanComplete, token }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'indicators' | 'features' | 'domain' | 'threatIntel'>('indicators');

  const handleScan = async (e?: React.FormEvent, overrideUrl?: string) => {
    if (e) e.preventDefault();
    const targetUrl = (overrideUrl || url).trim();

    if (!targetUrl) {
      setError('Please enter a target URL to analyze.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/scan', {
        method: 'POST',
        headers,
        body: JSON.stringify({ url: targetUrl }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to complete URL analysis pipeline.');
      }

      setResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err: any) {
      setError(err.message || 'Scan pipeline failed. Ensure server is online.');
    } finally {
      setLoading(false);
    }
  };

  const copyReport = () => {
    if (!result) return;
    const report = `--- PhishGuard-AI Cyber Threat Scan Report ---
Target URL: ${result.url}
Domain: ${result.domain}
Risk Score: ${result.risk_score}/100 (${result.risk_level} Risk)
Random Forest ML Prediction: ${result.prediction} (Confidence: ${Math.round(result.confidence * 100)}%)
Heuristic Risk Contribution: ${result.risk_analysis.heuristic_score}/100
Flagged Threat Indicators (${result.risk_analysis.detected_indicators.length}):
${result.risk_analysis.detected_indicators.map((i) => ` - [${i.severity.toUpperCase()}] ${i.name}: ${i.description} (+${i.score_contribution} pts)`).join('\n')}
Recommendations:
${result.risk_analysis.recommendations.map((r) => ` - ${r}`).join('\n')}
Timestamp: ${result.created_at}
Assessment Disclaimer: ${result.risk_analysis.disclaimer}`;

    navigator.clipboard.writeText(report).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  // Color helpers
  const getRiskColors = (level: string) => {
    switch (level) {
      case 'HIGH':
        return {
          bg: 'bg-rose-950/40',
          border: 'border-rose-700/60',
          text: 'text-rose-400',
          badge: 'bg-rose-950 text-rose-300 border-rose-800',
          accent: '#f43f5e',
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-950/40',
          border: 'border-amber-700/60',
          text: 'text-amber-400',
          badge: 'bg-amber-950 text-amber-300 border-amber-800',
          accent: '#f59e0b',
        };
      default:
        return {
          bg: 'bg-emerald-950/40',
          border: 'border-emerald-700/60',
          text: 'text-emerald-400',
          badge: 'bg-emerald-950 text-emerald-300 border-emerald-800',
          accent: '#10b981',
        };
    }
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Search className="w-5 h-5 text-cyan-400" />
              AI Phishing URL Scanner & Risk Assessor
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Examines URL lexical structures, host indicators, and domain age using a calibrated 12-tree Random Forest ensemble, heuristic rules, and Google Safe Browsing / VirusTotal intelligence.
            </p>
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>Multi-Factor Engine Active</span>
          </div>
        </div>

        {/* Input Bar */}
        <form onSubmit={handleScan} className="mt-5">
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter or paste URL (e.g., http://192.168.1.104/secure-login or bank-domain.com)..."
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 shadow-inner"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="py-3 px-6 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/40 shrink-0"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  <span>Analyzing Vectors...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Scan Target URL</span>
                </>
              )}
            </button>
          </div>
        </form>

        {/* Preset Chips */}
        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-medium">Quick Test Vectors:</span>
          {PRESET_URLS.map((item, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setUrl(item.url);
                handleScan(undefined, item.url);
              }}
              className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 transition-colors flex items-center gap-1.5"
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  item.type === 'HIGH RISK'
                    ? 'bg-rose-400'
                    : item.type === 'SUSPICIOUS'
                    ? 'bg-amber-400'
                    : 'bg-emerald-400'
                }`}
              />
              <span>{item.label}</span>
            </button>
          ))}
        </div>

        {error && (
          <div className="mt-4 p-3.5 bg-rose-950/50 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-start gap-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <div>
              <strong className="font-semibold">Security Alert: </strong>
              <span>{error}</span>
            </div>
          </div>
        )}
      </div>

      {/* Results View */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Main Risk Banner & Dial */}
          {(() => {
            const colors = getRiskColors(result.risk_level);
            return (
              <div className={`p-6 rounded-xl border ${colors.border} ${colors.bg} shadow-xl relative overflow-hidden`}>
                <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
                  {/* Left: Score Dial & Badge */}
                  <div className="flex items-center gap-5">
                    {/* Visual Gauge Circle */}
                    <div className="relative w-24 h-24 flex items-center justify-center shrink-0">
                      <svg className="w-24 h-24 -rotate-90">
                        <circle
                          cx="48"
                          cy="48"
                          r="38"
                          className="stroke-slate-800"
                          strokeWidth="8"
                          fill="transparent"
                        />
                        <circle
                          cx="48"
                          cy="48"
                          r="38"
                          stroke={colors.accent}
                          strokeWidth="8"
                          strokeDasharray={2 * Math.PI * 38}
                          strokeDashoffset={2 * Math.PI * 38 * (1 - result.risk_score / 100)}
                          strokeLinecap="round"
                          fill="transparent"
                          className="transition-all duration-1000 ease-out"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-2xl font-extrabold text-white tracking-tight">
                          {result.risk_score}
                        </span>
                        <span className="text-[10px] text-slate-400 uppercase font-semibold">/ 100</span>
                      </div>
                    </div>

                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`text-xs font-bold uppercase px-2 py-0.5 rounded border ${colors.badge}`}>
                          {result.risk_level} RISK DETECTED
                        </span>
                        <span className="text-xs text-slate-400">·</span>
                        <span className="text-xs font-mono text-slate-300">
                          ML: {result.prediction} ({Math.round(result.confidence * 100)}% Conf)
                        </span>
                      </div>
                      <h2 className="text-lg font-bold text-white break-all">{result.url}</h2>
                      <p className="text-xs text-slate-300 mt-1.5 leading-relaxed max-w-2xl">
                        {result.risk_analysis.summary}
                      </p>
                    </div>
                  </div>

                  {/* Right: Quick Action Controls */}
                  <div className="flex flex-wrap items-center gap-2 shrink-0 w-full lg:w-auto justify-end">
                    <button
                      onClick={copyReport}
                      className="py-2 px-3 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Report Copied' : 'Copy Scan Report'}</span>
                    </button>
                    <a
                      href={result.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="py-2 px-3 bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                      title="Open at your own risk (Do not submit sensitive credentials)"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Inspect Target</span>
                    </a>
                  </div>
                </div>

                {/* Score Comparison Bars: Heuristic vs ML Calibrated Probability */}
                <div className="mt-6 pt-5 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <div className="flex justify-between items-center text-xs mb-1.5">
                      <span className="text-slate-400 font-medium">Heuristic Static Analysis Score:</span>
                      <span className="font-bold text-slate-200">{result.risk_analysis.heuristic_score} / 100</span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-500 rounded-full transition-all duration-700"
                        style={{ width: `${result.risk_analysis.heuristic_score}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 mt-1 block">
                      Aggregated from 13 structural & host indicators (IP, keywords, shorteners, length)
                    </span>
                  </div>

                  <div className="bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                    <div className="flex justify-between items-center text-xs mb-1.5">
                      <span className="text-slate-400 font-medium">Random Forest Ensemble Probability:</span>
                      <span className="font-bold text-slate-200">
                        {Math.round(result.ml_analysis.confidence * 100)}% ({result.prediction})
                      </span>
                    </div>
                    <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-purple-500 rounded-full transition-all duration-700"
                        style={{ width: `${Math.round(result.ml_analysis.confidence * 100)}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 mt-1 block">
                      Evaluated across 12 calibrated decision trees trained on PhishTank & Benign sets
                    </span>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* AI Synthesis Summary if available */}
          {result.ml_analysis.ai_summary && (
            <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl flex items-start gap-3">
              <Sparkles className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300 mb-1">
                  AI Forensic Analysis & Attack Vector Classification
                </h4>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {result.ml_analysis.ai_summary}
                </p>
              </div>
            </div>
          )}

          {/* Safety Recommendation Banner */}
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Actionable Security Recommendations
            </h3>
            <ul className="space-y-1.5">
              {result.risk_analysis.recommendations.map((rec, index) => (
                <li key={index} className="text-xs text-slate-300 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Detailed Forensic Sub-Tabs */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
            <div className="flex border-b border-slate-800 bg-slate-950/60">
              <button
                onClick={() => setActiveSubTab('indicators')}
                className={`py-3 px-4 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeSubTab === 'indicators'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Detected Indicators ({result.risk_analysis.detected_indicators.length})</span>
              </button>
              <button
                onClick={() => setActiveSubTab('features')}
                className={`py-3 px-4 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeSubTab === 'features'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Extracted Features (18)</span>
              </button>
              <button
                onClick={() => setActiveSubTab('domain')}
                className={`py-3 px-4 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeSubTab === 'domain'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Calendar className="w-3.5 h-3.5" />
                <span>Domain & DNS Intel</span>
              </button>
              <button
                onClick={() => setActiveSubTab('threatIntel')}
                className={`py-3 px-4 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 ${
                  activeSubTab === 'threatIntel'
                    ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>External Threat Intel Feeds</span>
              </button>
            </div>

            <div className="p-5">
              {/* Indicators Tab */}
              {activeSubTab === 'indicators' && (
                <div className="space-y-3">
                  {result.risk_analysis.detected_indicators.length === 0 ? (
                    <div className="text-center py-8 text-slate-400 text-xs">
                      <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                      <p className="font-semibold text-slate-300">No Acute Threat Indicators Triggered</p>
                      <p className="text-slate-400 mt-1 max-w-md mx-auto">
                        Static structural and host analysis found no acute phishing signatures. However, always exercise standard hygiene as zero-day attacks may mimic legitimate layout.
                      </p>
                    </div>
                  ) : (
                    result.risk_analysis.detected_indicators.map((ind) => (
                      <div
                        key={ind.id}
                        className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                                ind.severity === 'high'
                                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                                  : ind.severity === 'medium'
                                  ? 'bg-amber-950 text-amber-300 border-amber-800'
                                  : 'bg-blue-950 text-blue-300 border-blue-800'
                              }`}
                            >
                              {ind.severity} severity
                            </span>
                            <span className="text-xs font-semibold text-white">{ind.name}</span>
                            <span className="text-xs text-slate-400 font-mono">({ind.category})</span>
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed">{ind.description}</p>
                          <div className="text-[11px] text-cyan-400/90 font-mono">
                            Evidence: {ind.evidence}
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <span className="text-xs font-bold text-rose-400 font-mono">
                            +{ind.score_contribution} pts
                          </span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Features Tab */}
              {activeSubTab === 'features' && (
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">URL Length:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.url_length} chars</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Domain Length:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.domain_length} chars</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Subdomain Count:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.subdomain_count}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">IP Host:</span>
                    <span className={`font-mono font-bold ${result.features.has_ip_address ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {result.features.has_ip_address ? 'YES (High Risk)' : 'NO (Normal)'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">URL Shortener:</span>
                    <span className={`font-mono font-bold ${result.features.has_shortener ? 'text-amber-400' : 'text-emerald-400'}`}>
                      {result.features.has_shortener ? 'YES (Masked)' : 'NO'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Shannon Entropy:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.entropy} bits</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">HTTPS Encryption:</span>
                    <span className={`font-mono font-bold ${result.features.has_https ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {result.features.has_https ? 'YES (TLS)' : 'NO (Unencrypted)'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Sensitive Keywords:</span>
                    <span className="font-mono font-bold text-slate-200 truncate block">
                      {result.features.suspicious_keywords_found.length > 0
                        ? result.features.suspicious_keywords_found.join(', ')
                        : 'None detected'}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Top-Level Domain (TLD):</span>
                    <span className="font-mono font-bold text-slate-200">.{result.features.tld || 'none'}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Dot Count:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.dot_count}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">Hyphen Count:</span>
                    <span className="font-mono font-bold text-slate-200">{result.features.hyphen_count}</span>
                  </div>
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1">@ Symbol Present:</span>
                    <span className={`font-mono font-bold ${result.features.has_at_symbol ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {result.features.has_at_symbol ? 'YES (Spoof trick)' : 'NO'}
                    </span>
                  </div>
                </div>
              )}

              {/* Domain & DNS Tab */}
              {activeSubTab === 'domain' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                    <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">
                      RDAP WHOIS Domain Intelligence
                    </h4>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Target Host:</span>
                      <span className="font-mono text-slate-200">{result.domain_info.domain}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Creation Date:</span>
                      <span className="font-mono text-slate-200">
                        {result.domain_info.creation_date
                          ? new Date(result.domain_info.creation_date).toLocaleDateString()
                          : 'Unavailable / Redacted'}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Calculated Domain Age:</span>
                      <span className="font-mono font-bold text-cyan-300">
                        {result.features.domain_age_days !== null
                          ? `${result.features.domain_age_days} days`
                          : 'Unknown / IP Host'}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Registrar:</span>
                      <span className="font-mono text-slate-200">{result.domain_info.registrar || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Privacy Shield:</span>
                      <span className="font-mono text-slate-200">
                        {result.domain_info.privacy_protected ? 'Protected / Proxy' : 'Standard'}
                      </span>
                    </div>
                  </div>

                  <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2">
                    <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">
                      DNS Network Infrastructure
                    </h4>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Resolved IPv4:</span>
                      <span className="font-mono text-slate-200 break-all">
                        {result.dns_info.ipv4.length > 0 ? result.dns_info.ipv4.join(', ') : 'Direct host / None'}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">Nameservers:</span>
                      <span className="font-mono text-slate-200 truncate">
                        {result.dns_info.nameservers.length > 0
                          ? result.dns_info.nameservers.join(', ')
                          : 'None / Local'}
                      </span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/60 pb-1.5">
                      <span className="text-slate-400">SSRF Screening:</span>
                      <span
                        className={`font-mono font-bold ${
                          result.dns_info.is_private_ip ? 'text-rose-400' : 'text-emerald-400'
                        }`}
                      >
                        {result.dns_info.is_private_ip ? 'PRIVATE/RESERVED SUBNET' : 'PASS (Public Internet)'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">DNSSEC Validation:</span>
                      <span className="font-mono text-slate-200">{result.dns_info.dnssec ? 'Signed' : 'Unsigned'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Threat Intel Feeds Tab */}
              {activeSubTab === 'threatIntel' && (
                <div className="space-y-4">
                  {result.threat_intel ? (
                    <>
                      <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-center justify-between text-xs">
                        <div>
                          <span className="text-slate-400 font-medium">External Threat Verdict: </span>
                          <span
                            className={`font-bold uppercase ${
                              result.threat_intel.overall_verdict === 'threat_detected'
                                ? 'text-rose-400'
                                : result.threat_intel.overall_verdict === 'no_threats_found'
                                ? 'text-emerald-400'
                                : 'text-slate-400'
                            }`}
                          >
                            {result.threat_intel.overall_verdict.replace(/_/g, ' ')}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400">{result.threat_intel.notes}</span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {result.threat_intel.vendors.map((vendor, idx) => (
                          <div key={idx} className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-white">{vendor.vendor}</span>
                              <span
                                className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                                  vendor.status === 'malicious'
                                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                                    : vendor.status === 'clean'
                                    ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                    : vendor.status === 'unconfigured'
                                    ? 'bg-slate-900 text-slate-400 border-slate-800'
                                    : 'bg-amber-950 text-amber-300 border-amber-800'
                                }`}
                              >
                                {vendor.status}
                              </span>
                            </div>
                            <p className="text-slate-300 leading-relaxed">{vendor.details}</p>
                            <div className="flex justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800/60">
                              <span>Checked: {new Date(vendor.checked_at).toLocaleTimeString()}</span>
                              <span>{vendor.cached ? 'Served from Cache' : 'Live Query'}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </>
                  ) : (
                    <div className="text-xs text-slate-400">External threat intelligence was not queried.</div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Mandatory Automated Results Disclaimer */}
          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-start gap-2.5 text-[11px] text-slate-400">
            <Info className="w-4 h-4 shrink-0 text-cyan-400/80 mt-0.5" />
            <p className="leading-relaxed">
              <strong>Automated Detection Notice: </strong>
              {result.risk_analysis.disclaimer}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
