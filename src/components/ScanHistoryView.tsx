import React, { useState, useEffect } from 'react';
import {
  History,
  Search,
  Filter,
  Download,
  Trash2,
  ExternalLink,
  Eye,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  X,
  FileSpreadsheet,
} from 'lucide-react';
import type { ScanResult, DbScanRecord, MessageScanResult } from '../types.js';

interface ScanHistoryViewProps {
  token?: string | null;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({ token }) => {
  const [scans, setScans] = useState<DbScanRecord[]>([]);
  const [messages, setMessages] = useState<MessageScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Search
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRisk, setFilterRisk] = useState<string>('ALL');
  const [activeTab, setActiveTab] = useState<'urls' | 'messages'>('urls');
  const [selectedScanDetail, setSelectedScanDetail] = useState<ScanResult | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const [resScans, resMsgs] = await Promise.all([
        fetch('/api/scans/history', { headers }),
        fetch('/api/scans/messages', { headers }),
      ]);

      if (!resScans.ok || !resMsgs.ok) {
        throw new Error('Failed to load scan records from database.');
      }

      const scansData = await resScans.json();
      const msgsData = await resMsgs.json();

      setScans(scansData);
      setMessages(msgsData);
    } catch (err: any) {
      setError(err.message || 'Error fetching history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [token]);

  const handleDeleteScan = async (id: number) => {
    if (!confirm('Are you sure you want to permanently delete this scan record?')) return;

    try {
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/scans/${id}`, {
        method: 'DELETE',
        headers,
      });

      if (!res.ok) throw new Error('Deletion failed.');

      setScans((prev) => prev.filter((s) => s.id !== id));
      if (selectedScanDetail && selectedScanDetail.id === id) {
        setSelectedScanDetail(null);
      }
    } catch (err: any) {
      alert(err.message || 'Could not delete record.');
    }
  };

  const handleDeleteMessage = async (id: number) => {
    if (!confirm('Delete this message scan record?')) return;

    try {
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/scans/messages/${id}`, {
        method: 'DELETE',
        headers,
      });

      if (!res.ok) throw new Error('Deletion failed.');
      setMessages((prev) => prev.filter((m) => m.id !== id));
    } catch (err: any) {
      alert(err.message || 'Could not delete record.');
    }
  };

  const handleViewDetail = async (id: number) => {
    setDetailLoading(true);
    try {
      const headers: Record<string, string> = {};
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`/api/scans/${id}`, { headers });
      if (!res.ok) throw new Error('Failed to load scan details');
      const data = await res.json();
      setSelectedScanDetail(data);
    } catch (err: any) {
      alert(err.message || 'Failed to open record');
    } finally {
      setDetailLoading(false);
    }
  };

  const handleExportCsv = () => {
    window.location.href = '/api/scans/export/csv';
  };

  // Filter scans
  const filteredScans = scans.filter((s) => {
    const matchesSearch =
      s.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = filterRisk === 'ALL' || s.risk_level === filterRisk;
    return matchesSearch && matchesRisk;
  });

  const filteredMessages = messages.filter((m) => {
    const matchesSearch = m.message_preview.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = filterRisk === 'ALL' || m.risk_level === filterRisk;
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="space-y-6">
      {/* Header with Export */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-400" />
            Detection History & Forensics Repository
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Persisted scan database records with risk classifications, timestamps, and granular indicator forensics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="py-2 px-3.5 bg-slate-950 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg text-xs font-medium flex items-center gap-2 transition-colors shadow-sm"
          >
            <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Filter and Tab Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-slate-900/40 p-3 rounded-xl border border-slate-800">
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <div className="flex p-1 bg-slate-950 rounded-lg border border-slate-800 w-full sm:w-auto">
            <button
              onClick={() => setActiveTab('urls')}
              className={`flex-1 sm:flex-none py-1.5 px-3 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'urls'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              URL Scans ({scans.length})
            </button>
            <button
              onClick={() => setActiveTab('messages')}
              className={`flex-1 sm:flex-none py-1.5 px-3 rounded-md text-xs font-medium transition-colors ${
                activeTab === 'messages'
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Message Scans ({messages.length})
            </button>
          </div>
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          {/* Search */}
          <div className="relative flex-1 sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search domain or keyword..."
              className="w-full bg-slate-950 border border-slate-750 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Risk Level Filter */}
          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="bg-slate-950 border border-slate-750 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="HIGH">High Risk</option>
            <option value="MEDIUM">Medium Risk</option>
            <option value="LOW">Low Risk</option>
          </select>
        </div>
      </div>

      {/* Table Data */}
      {loading ? (
        <div className="text-center py-16 text-slate-400 text-xs">
          <div className="w-6 h-6 border-2 border-cyan-400/20 border-t-cyan-400 rounded-full animate-spin mx-auto mb-2" />
          <span>Loading historical records...</span>
        </div>
      ) : activeTab === 'urls' ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Target URL / Domain</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">ML Model</th>
                  <th className="py-3 px-4">Scanned On</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredScans.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-slate-500">
                      No URL scans matching the selected filters.
                    </td>
                  </tr>
                ) : (
                  filteredScans.map((s) => (
                    <tr key={s.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                            s.risk_level === 'HIGH'
                              ? 'bg-rose-950 text-rose-300 border-rose-800'
                              : s.risk_level === 'MEDIUM'
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          }`}
                        >
                          {s.risk_level} RISK
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-xs sm:max-w-md truncate">
                        <span className="font-mono text-slate-200 block truncate">{s.url}</span>
                        <span className="text-[11px] text-slate-500">{s.domain}</span>
                      </td>
                      <td className="py-3 px-4 font-mono whitespace-nowrap">
                        <span
                          className={`font-bold ${
                            s.risk_score >= 65
                              ? 'text-rose-400'
                              : s.risk_score >= 35
                              ? 'text-amber-400'
                              : 'text-emerald-400'
                          }`}
                        >
                          {s.risk_score}
                        </span>
                        <span className="text-slate-600">/100</span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 whitespace-nowrap">
                        {s.prediction} ({Math.round(s.confidence * 100)}%)
                      </td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                        {new Date(s.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleViewDetail(s.id)}
                            title="Inspect full forensic breakdown"
                            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteScan(s.id)}
                            title="Delete scan record"
                            className="p-1.5 rounded hover:bg-rose-950/60 text-slate-500 hover:text-rose-400 transition-colors"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* Messages Table */
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <tr>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Message Preview</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4">Extracted URLs</th>
                  <th className="py-3 px-4">Analyzed On</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredMessages.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-slate-500">
                      No message scam scans matching criteria.
                    </td>
                  </tr>
                ) : (
                  filteredMessages.map((m) => (
                    <tr key={m.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                            m.classification === 'SCAM'
                              ? 'bg-rose-950 text-rose-300 border-rose-800'
                              : m.classification === 'SUSPICIOUS'
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                          }`}
                        >
                          {m.classification}
                        </span>
                      </td>
                      <td className="py-3 px-4 max-w-sm truncate text-slate-200">
                        {m.message_preview}
                      </td>
                      <td className="py-3 px-4 font-mono whitespace-nowrap font-bold text-slate-200">
                        {m.risk_score}/100
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-400 whitespace-nowrap">
                        {m.extracted_urls.length} link(s)
                      </td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap font-mono text-[11px]">
                        {new Date(m.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <button
                          onClick={() => handleDeleteMessage(m.id)}
                          title="Delete message record"
                          className="p-1.5 rounded hover:bg-rose-950/60 text-slate-500 hover:text-rose-400 transition-colors"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Forensic Detail Modal */}
      {selectedScanDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 text-slate-100 max-h-[85vh] overflow-y-auto">
            <button
              onClick={() => setSelectedScanDetail(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="mb-4">
              <span className="text-[10px] uppercase font-bold text-cyan-400 font-mono">
                RECORD #{selectedScanDetail.id}
              </span>
              <h3 className="text-lg font-bold text-white break-all mt-0.5">
                {selectedScanDetail.url}
              </h3>
              <div className="flex items-center gap-2 text-xs text-slate-400 mt-1">
                <span>Domain: {selectedScanDetail.domain}</span>
                <span>·</span>
                <span>{new Date(selectedScanDetail.created_at).toLocaleString()}</span>
              </div>
            </div>

            <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 mb-4 flex items-center justify-between">
              <div>
                <span className="text-xs text-slate-400 block mb-0.5">Assessed Risk Score</span>
                <span className="text-2xl font-black text-white">{selectedScanDetail.risk_score}/100</span>
                <span className="text-xs text-slate-400 ml-2">({selectedScanDetail.risk_level} Risk)</span>
              </div>
              <div className="text-right">
                <span className="text-xs text-slate-400 block mb-0.5">ML Classification</span>
                <span className="text-sm font-bold text-cyan-300">
                  {selectedScanDetail.prediction} ({Math.round(selectedScanDetail.confidence * 100)}%)
                </span>
              </div>
            </div>

            <div className="space-y-3 text-xs mb-4">
              <h4 className="font-bold text-slate-300 uppercase tracking-wider">Recommendations</h4>
              <p className="text-slate-300 bg-slate-950/80 p-3 rounded border border-slate-800 leading-relaxed">
                {selectedScanDetail.recommendation}
              </p>
            </div>

            <div className="text-right pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedScanDetail(null)}
                className="py-1.5 px-4 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium"
              >
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
