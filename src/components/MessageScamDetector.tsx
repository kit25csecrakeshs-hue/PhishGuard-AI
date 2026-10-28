import React, { useState } from 'react';
import {
  MessageSquareWarning,
  AlertOctagon,
  ShieldAlert,
  ShieldCheck,
  Link,
  Clock,
  Key,
  Gift,
  Building,
  CreditCard,
  Copy,
  Check,
  Info,
  Sparkles,
} from 'lucide-react';
import type { MessageScanResult } from '../types.js';

interface MessageScamDetectorProps {
  token?: string | null;
}

const PRESET_MESSAGES = [
  {
    title: 'Chase Bank Smishing SMS',
    type: 'SCAM',
    text: `URGENT ALERT: Your Chase Bank debit card has been suspended due to 3 failed PIN attempts. Verify your identity within 24 hours to prevent permanent account lockout: http://chase-identity-recovery.xyz/login?ref=sms`,
  },
  {
    title: 'USPS Package Redelivery Lure',
    type: 'SCAM',
    text: `USPS Notice: Your parcel #US948192 could not be delivered due to an incorrect delivery address and an unpaid $2.95 redelivery fee. Update your address and pay immediately: https://bit.ly/usps-redelivery-update`,
  },
  {
    title: 'OTP Theft Pretext',
    type: 'SCAM',
    text: `Hi, this is PayPal Fraud Prevention. We detected an unauthorized charge of $894.20. To cancel this payment immediately, reply to this message with the 6-digit SMS verification code you just received.`,
  },
  {
    title: 'Crypto Prize / Giveaway',
    type: 'SCAM',
    text: `Congratulations! Your mobile number was selected as a winner in the International Crypto Giveaway 2026. Claim your 0.5 BTC prize immediately before midnight: http://free-crypto-reward.buzz/claim`,
  },
  {
    title: 'Legitimate Team Notification',
    type: 'LEGITIMATE',
    text: `Hi team, reminder that our cybersecurity sprint retrospective is scheduled for tomorrow at 2:00 PM in Conference Room B. Please review the updated agenda on our internal portal.`,
  },
];

export const MessageScamDetector: React.FC<MessageScamDetectorProps> = ({ token }) => {
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MessageScanResult | null>(null);
  const [copied, setCopied] = useState(false);

  const handleAnalyze = async (e?: React.FormEvent, overrideText?: string) => {
    if (e) e.preventDefault();
    const textToScan = (overrideText || message).trim();

    if (!textToScan) {
      setError('Please enter or paste an email or SMS message to analyze.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch('/api/message-scam', {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: textToScan }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to analyze message.');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Scam detector server error.');
    } finally {
      setLoading(false);
    }
  };

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case 'urgency':
        return <Clock className="w-4 h-4 text-amber-400" />;
      case 'credential_theft':
        return <Key className="w-4 h-4 text-rose-400" />;
      case 'otp_request':
        return <AlertOctagon className="w-4 h-4 text-rose-500" />;
      case 'fake_prize':
        return <Gift className="w-4 h-4 text-purple-400" />;
      case 'impersonation':
        return <Building className="w-4 h-4 text-blue-400" />;
      case 'payment':
        return <CreditCard className="w-4 h-4 text-rose-400" />;
      case 'suspicious_link':
        return <Link className="w-4 h-4 text-cyan-400" />;
      default:
        return <AlertOctagon className="w-4 h-4 text-amber-400" />;
    }
  };

  const copyAnalysis = () => {
    if (!result) return;
    const text = `--- PhishGuard-AI Message Scam Analysis ---
Risk Classification: ${result.classification} (Risk Score: ${result.risk_score}/100)
Extracted URLs: ${result.extracted_urls.join(', ') || 'None'}
Indicators Detected (${result.indicators.length}):
${result.indicators.map((i) => ` - ${i.title}: ${i.description} [Matched: ${i.matched_text || 'N/A'}]`).join('\n')}
Analysis Explanation:
${result.explanation}
Recommended Actions:
${result.recommended_actions.map((a) => ` - ${a}`).join('\n')}
Analysis Timestamp: ${result.created_at}`;

    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <MessageSquareWarning className="w-5 h-5 text-amber-400" />
              Email & SMS Message Scam Detector
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Detects coercive urgency, fake prize lures, brand impersonation, credential harvesting bait, and OTP elicitation. Embedded URLs are automatically extracted and passed through the URL risk engine.
            </p>
          </div>
          <div className="text-xs text-slate-400 flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
            <span className="w-2 h-2 rounded-full bg-amber-400" />
            <span>Natural Language Heuristics + URL Inspection</span>
          </div>
        </div>

        {/* Text Area Form */}
        <form onSubmit={handleAnalyze} className="mt-5 space-y-3">
          <div className="relative">
            <textarea
              rows={4}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Paste suspicious SMS text, phishing email body, WhatsApp message, or direct message..."
              className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-amber-500 shadow-inner resize-y"
            />
            <div className="text-right text-[11px] text-slate-400 mt-1">
              {message.length} characters
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            {/* Presets */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              <span className="text-slate-400 font-medium">Test Lures:</span>
              {PRESET_MESSAGES.map((preset, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setMessage(preset.text);
                    handleAnalyze(undefined, preset.text);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700 transition-colors flex items-center gap-1.5"
                >
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      preset.type === 'SCAM' ? 'bg-rose-400' : 'bg-emerald-400'
                    }`}
                  />
                  <span>{preset.title}</span>
                </button>
              ))}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="py-2.5 px-6 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-slate-950 font-semibold rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shadow-lg shadow-amber-950/40 shrink-0"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-slate-950/30 border-t-slate-950 rounded-full animate-spin" />
                  <span>Inspecting Content...</span>
                </>
              ) : (
                <>
                  <MessageSquareWarning className="w-4 h-4" />
                  <span>Analyze Message</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-3.5 bg-rose-950/50 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-start gap-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <div>
              <strong className="font-semibold">Analysis Error: </strong>
              <span>{error}</span>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Result */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Main Classification Card */}
          <div
            className={`p-6 rounded-xl border shadow-xl ${
              result.classification === 'SCAM'
                ? 'bg-rose-950/40 border-rose-700/60'
                : result.classification === 'SUSPICIOUS'
                ? 'bg-amber-950/40 border-amber-700/60'
                : 'bg-emerald-950/40 border-emerald-700/60'
            }`}
          >
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
              {/* Dial + Badge */}
              <div className="flex items-center gap-5">
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
                      stroke={
                        result.classification === 'SCAM'
                          ? '#f43f5e'
                          : result.classification === 'SUSPICIOUS'
                          ? '#f59e0b'
                          : '#10b981'
                      }
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
                    <span
                      className={`text-xs font-bold uppercase px-2 py-0.5 rounded border ${
                        result.classification === 'SCAM'
                          ? 'bg-rose-950 text-rose-300 border-rose-800'
                          : result.classification === 'SUSPICIOUS'
                          ? 'bg-amber-950 text-amber-300 border-amber-800'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      }`}
                    >
                      {result.classification} VERDICT
                    </span>
                    <span className="text-xs text-slate-400">·</span>
                    <span className="text-xs text-slate-300 font-mono">
                      Method: {result.analysis_method.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white">
                    {result.classification === 'SCAM'
                      ? 'High-Risk Cyber Scam / Smishing Detected'
                      : result.classification === 'SUSPICIOUS'
                      ? 'Potentially Deceptive Communication'
                      : 'Legitimate Communication Pattern'}
                  </h3>
                  <p className="text-xs text-slate-300 mt-1 max-w-2xl leading-relaxed">
                    {result.explanation}
                  </p>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={copyAnalysis}
                  className="py-2 px-3 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Analysis Copied' : 'Copy Analysis'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Extracted URLs Inspection */}
          {result.extracted_urls.length > 0 && (
            <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
              <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <Link className="w-4 h-4" />
                Extracted URLs Scanned in Message ({result.extracted_urls.length})
              </h3>
              <div className="space-y-2">
                {result.url_scan_results.map((u, idx) => (
                  <div
                    key={idx}
                    className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div className="space-y-1">
                      <span className="font-mono text-white break-all">{u.url}</span>
                      <div className="text-slate-400">Host: {u.domain}</div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      <span
                        className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                          u.risk_level === 'HIGH'
                            ? 'bg-rose-950 text-rose-300 border-rose-800'
                            : u.risk_level === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        }`}
                      >
                        {u.risk_level} Risk ({u.risk_score}/100)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Flagged Indicators Grid */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <AlertOctagon className="w-4 h-4 text-rose-400" />
              Scam & Social Engineering Indicators ({result.indicators.length})
            </h3>

            {result.indicators.length === 0 ? (
              <div className="text-center py-6 text-slate-400 text-xs">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                <p className="font-semibold text-slate-300">No Malicious Indicators Identified</p>
                <p className="text-slate-400 mt-1 max-w-md mx-auto">
                  The message does not employ coercive deadlines, OTP solicitations, or deceptive account recovery links.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.indicators.map((ind, idx) => (
                  <div
                    key={idx}
                    className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 text-xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {getIndicatorIcon(ind.type)}
                        <span className="font-semibold text-white">{ind.title}</span>
                      </div>
                      <span
                        className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                          ind.severity === 'high'
                            ? 'bg-rose-950 text-rose-300'
                            : 'bg-amber-950 text-amber-300'
                        }`}
                      >
                        {ind.severity}
                      </span>
                    </div>
                    <p className="text-slate-300 leading-relaxed">{ind.description}</p>
                    {ind.matched_text && (
                      <div className="text-[11px] text-cyan-400/90 font-mono">
                        Trigger: "{ind.matched_text}"
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Actionable Recommendations */}
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-1.5">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              Recommended Defensive Steps
            </h3>
            <ul className="space-y-1.5">
              {result.recommended_actions.map((act, idx) => (
                <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                  <span>{act}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Automated Assessment Disclaimer */}
          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-start gap-2.5 text-[11px] text-slate-400">
            <Info className="w-4 h-4 shrink-0 text-cyan-400/80 mt-0.5" />
            <p className="leading-relaxed">
              <strong>Automated Detection Disclaimer: </strong>
              These findings are produced by automated natural language pattern recognition and heuristic link extraction. Results represent an automated risk assessment rather than a guaranteed conclusion. Always confirm sensitive communications through verified official channels.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
