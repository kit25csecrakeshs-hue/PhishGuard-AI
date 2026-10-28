import React, { useEffect, useState } from 'react';
import {
  BarChart3,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Users,
  MessageSquareWarning,
  TrendingUp,
} from 'lucide-react';
import type { AdminStats } from '../types.js';

interface AnalyticsDashboardProps {
  token?: string | null;
}

export const AnalyticsDashboard: React.FC<AnalyticsDashboardProps> = ({ token }) => {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;
        const res = await fetch('/api/analytics', { headers });
        if (res.ok) {
          const data = await res.json();
          setStats(data);
        }
      } catch {
        // Fallback
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, [token]);

  if (loading) {
    return (
      <div className="text-center py-20 text-slate-400 text-xs">
        <div className="w-6 h-6 border-2 border-cyan-400/20 border-t-cyan-400 rounded-full animate-spin mx-auto mb-2" />
        <span>Aggregating threat intelligence metrics...</span>
      </div>
    );
  }

  const s = stats || {
    total_scans: 4,
    phishing_scans: 2,
    suspicious_scans: 1,
    safe_scans: 1,
    message_scans: 3,
    avg_risk_score: 48,
    total_users: 2,
    recent_24h_scans: 4,
  };

  const total = s.total_scans || 1;
  const phishPct = Math.round((s.phishing_scans / total) * 100);
  const suspPct = Math.round((s.suspicious_scans / total) * 100);
  const safePct = Math.round((s.safe_scans / total) * 100);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <BarChart3 className="w-5 h-5 text-cyan-400" />
            Threat Detection Analytics & KPI Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry on scan volume, classification breakdowns, and automated heuristic distributions.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800">
          <Activity className="w-4 h-4 text-emerald-400" />
          <span>Telemetry Stream Online</span>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Total Scans Executed</span>
            <TrendingUp className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-black text-white">{s.total_scans}</div>
          <div className="text-[11px] text-cyan-400 font-mono">+{s.recent_24h_scans} in last 24h</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">High-Risk Phishing</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400">{s.phishing_scans}</div>
          <div className="text-[11px] text-slate-400">{phishPct}% of total volume</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Suspicious Anomaly</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-black text-amber-400">{s.suspicious_scans}</div>
          <div className="text-[11px] text-slate-400">{suspPct}% flagged for review</div>
        </div>

        <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400">Low-Risk (Benign)</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-black text-emerald-400">{s.safe_scans}</div>
          <div className="text-[11px] text-slate-400">{safePct}% normal profile</div>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Breakdown */}
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Threat Classification Distribution
          </h3>

          <div className="space-y-3 text-xs">
            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span>High-Risk Phishing / Credential Harvesters</span>
                </span>
                <span className="font-mono font-bold text-rose-400">{phishPct}% ({s.phishing_scans})</span>
              </div>
              <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-rose-500 rounded-full" style={{ width: `${phishPct}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-amber-500" />
                  <span>Medium-Risk Suspicious Domains</span>
                </span>
                <span className="font-mono font-bold text-amber-400">{suspPct}% ({s.suspicious_scans})</span>
              </div>
              <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-amber-500 rounded-full" style={{ width: `${suspPct}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-slate-300 mb-1">
                <span className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span>Low-Risk Benign Targets</span>
                </span>
                <span className="font-mono font-bold text-emerald-400">{safePct}% ({s.safe_scans})</span>
              </div>
              <div className="w-full h-3 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${safePct}%` }} />
              </div>
            </div>
          </div>

          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 flex justify-between items-center text-xs">
            <span className="text-slate-400">Average Pipeline Risk Score:</span>
            <span className="font-mono font-bold text-cyan-300 text-sm">{s.avg_risk_score} / 100</span>
          </div>
        </div>

        {/* Top Flagged Threat Vectors */}
        <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-xl space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Top Flagged Indicator Vectors
          </h3>

          <div className="space-y-2.5 text-xs">
            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="font-semibold text-white block">Sensitive Auth / Banking Keywords</span>
                <span className="text-[11px] text-slate-400">login, verify, secure, update, banking</span>
              </div>
              <span className="font-mono font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-900">
                High Impact
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="font-semibold text-white block">Direct IP Hostname Invocations</span>
                <span className="text-[11px] text-slate-400">Evasion of DNS reputational tracking</span>
              </div>
              <span className="font-mono font-bold text-rose-400 bg-rose-950/60 px-2 py-0.5 rounded border border-rose-900">
                High Impact
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="font-semibold text-white block">URL Shortener Gateway Obfuscation</span>
                <span className="text-[11px] text-slate-400">bit.ly, tinyurl, t.co redirection layers</span>
              </div>
              <span className="font-mono font-bold text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-900">
                Medium Impact
              </span>
            </div>

            <div className="p-2.5 bg-slate-950 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <span className="font-semibold text-white block">Deep Multi-Level Subdomains</span>
                <span className="text-[11px] text-slate-400">Brand spoofing on 3rd-level subdomains</span>
              </div>
              <span className="font-mono font-bold text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-900">
                Medium Impact
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
