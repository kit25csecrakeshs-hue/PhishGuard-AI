import React, { useState } from 'react';
import {
  Globe2,
  ShieldCheck,
  ShieldAlert,
  Server,
  Key,
  RefreshCw,
  Search,
  ExternalLink,
  Info,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import type { ThreatIntelligenceResult } from '../types.js';

export const ThreatIntelligenceView: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [forceRefresh, setForceRefresh] = useState(false);
  const [result, setResult] = useState<ThreatIntelligenceResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleQuery = async (e?: React.FormEvent, presetUrl?: string) => {
    if (e) e.preventDefault();
    const target = (presetUrl || url).trim();

    if (!target) {
      setError('Please provide a URL to query external threat intelligence.');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const res = await fetch('/api/threat-intel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, forceRefresh }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to query threat intelligence.');
      }

      setResult(data);
    } catch (err: any) {
      setError(err.message || 'Threat intelligence query failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2">
              <Globe2 className="w-5 h-5 text-cyan-400" />
              External Threat Intelligence Hub
            </h1>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Queries real-time global security feeds including Google Safe Browsing API v4 and VirusTotal v3 URL reputation engines, complete with server-side caching and rate-limit backoff.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs px-2.5 py-1 bg-slate-950 border border-slate-800 text-slate-300 rounded-lg font-mono">
              TTL Cache: 60 min
            </span>
          </div>
        </div>

        {/* Query Input */}
        <form onSubmit={handleQuery} className="mt-5 space-y-3">
          <div className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Query URL reputation (e.g., https://phishing-domain.com or test-site.xyz)..."
              className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={loading}
              className="py-2.5 px-6 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Querying Feeds...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Check Reputation</span>
                </>
              )}
            </button>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span>Bypass in-memory cache (Force fresh API query)</span>
            </label>
            <div className="flex items-center gap-2">
              <span>Samples:</span>
              <button
                type="button"
                onClick={() => {
                  setUrl('https://example.com');
                  handleQuery(undefined, 'https://example.com');
                }}
                className="text-cyan-400 hover:underline"
              >
                example.com
              </button>
              <span>·</span>
              <button
                type="button"
                onClick={() => {
                  setUrl('https://testsafebrowsing.appspot.com/s/phishing.html');
                  handleQuery(undefined, 'https://testsafebrowsing.appspot.com/s/phishing.html');
                }}
                className="text-cyan-400 hover:underline"
              >
                Google Test Phishing
              </button>
            </div>
          </div>
        </form>

        {error && (
          <div className="mt-4 p-3.5 bg-rose-950/50 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-start gap-2.5">
            <ShieldAlert className="w-4 h-4 shrink-0 text-rose-400 mt-0.5" />
            <div>
              <strong className="font-semibold">Query Error: </strong>
              <span>{error}</span>
            </div>
          </div>
        )}
      </div>

      {/* Query Result View */}
      {result && (
        <div className="space-y-4 animate-fadeIn">
          {/* Main Verdict Card */}
          <div
            className={`p-5 rounded-xl border ${
              result.overall_verdict === 'threat_detected'
                ? 'bg-rose-950/40 border-rose-700/60'
                : result.overall_verdict === 'no_threats_found'
                ? 'bg-emerald-950/40 border-emerald-700/60'
                : 'bg-slate-900 border-slate-800'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span
                  className={`text-xs font-bold uppercase px-2 py-0.5 rounded border ${
                    result.overall_verdict === 'threat_detected'
                      ? 'bg-rose-950 text-rose-300 border-rose-800'
                      : result.overall_verdict === 'no_threats_found'
                      ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                      : 'bg-slate-950 text-slate-400 border-slate-800'
                  }`}
                >
                  {result.overall_verdict.replace(/_/g, ' ')}
                </span>
                <span className="text-xs text-slate-400 font-mono">Domain: {result.domain}</span>
              </div>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">{result.notes}</p>
          </div>

          {/* Individual Vendor Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {result.vendors.map((v, idx) => (
              <div key={idx} className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="w-4 h-4 text-cyan-400" />
                    <span className="font-bold text-white text-sm">{v.vendor}</span>
                  </div>
                  <span
                    className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                      v.status === 'malicious'
                        ? 'bg-rose-950 text-rose-300 border-rose-800'
                        : v.status === 'clean'
                        ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        : v.status === 'unconfigured'
                        ? 'bg-slate-950 text-slate-400 border-slate-800'
                        : 'bg-amber-950 text-amber-300 border-amber-800'
                    }`}
                  >
                    {v.status}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{v.details}</p>

                {v.positives !== undefined && v.total_scans !== undefined && (
                  <div className="p-2 bg-slate-950 rounded border border-slate-800/80 text-xs flex justify-between">
                    <span className="text-slate-400">Engine Detections:</span>
                    <span className="font-mono font-bold text-white">
                      {v.positives} / {v.total_scans} Security Vendors Flagged
                    </span>
                  </div>
                )}

                <div className="flex justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/60">
                  <span>Checked: {new Date(v.checked_at).toLocaleTimeString()}</span>
                  <span className="font-mono">{v.cached ? '⚡ In-Memory Cached' : '🌐 Live Network Hit'}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Integration & Setup Instructions Card */}
      <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Key className="w-4 h-4 text-cyan-400" />
          Threat Intelligence API Configuration Guide
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          PhishGuard-AI connects to external threat feeds securely on the backend server. To enable live vendor lookups in your deployment, specify credentials in your server environment variables:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <strong className="text-cyan-300">Google Safe Browsing v4</strong>
              <span className="text-[10px] text-emerald-400 font-mono">Free Tier Available</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Provides lookup against Google's constantly updated blacklist of suspected phishing and malware pages.
            </p>
            <div className="bg-slate-900 p-2 rounded font-mono text-[11px] text-slate-300 break-all">
              GOOGLE_SAFE_BROWSING_API_KEY="AIzaSy..."
            </div>
          </div>

          <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <div className="flex items-center justify-between">
              <strong className="text-cyan-300">VirusTotal API v3</strong>
              <span className="text-[10px] text-emerald-400 font-mono">Free 4 req/min</span>
            </div>
            <p className="text-slate-400 leading-relaxed">
              Aggregates detections across 70+ antivirus and domain blacklist engines for multi-vendor consensus.
            </p>
            <div className="bg-slate-900 p-2 rounded font-mono text-[11px] text-slate-300 break-all">
              VIRUSTOTAL_API_KEY="4f91b7..."
            </div>
          </div>
        </div>

        <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-start gap-2">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <span>
            <strong>Zero-Exposition Guarantee: </strong>
            API keys are strictly managed on the server side via environment variables. Keys are never passed to the client browser, never bundled into static assets, and never written into extension files.
          </span>
        </div>
      </div>
    </div>
  );
};
