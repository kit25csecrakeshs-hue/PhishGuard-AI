import React, { useState } from 'react';
import {
  Puzzle,
  Download,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Code2,
  Copy,
  Check,
  Shield,
  Layers,
} from 'lucide-react';

export const ExtensionGuide: React.FC = () => {
  const [copiedStep, setCopiedStep] = useState<number | null>(null);
  const [activeCodeFile, setActiveCodeFile] = useState<'manifest' | 'popupJs' | 'popupHtml'>('manifest');

  const copyText = (text: string, index: number) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedStep(index);
      setTimeout(() => setCopiedStep(null), 2000);
    });
  };

  const codeSnippets = {
    manifest: `{
  "manifest_version": 3,
  "name": "PhishGuard-AI Cyber Threat Shield",
  "version": "1.0.0",
  "description": "AI-Powered Real-Time Phishing URL & Scam Detection directly in your browser.",
  "permissions": ["activeTab", "storage"],
  "host_permissions": [
    "http://localhost:3000/*",
    "http://127.0.0.1:3000/*"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "PhishGuard-AI Shield"
  }
}`,
    popupJs: `// PhishGuard-AI Chrome Extension Popup Controller
async function scanActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  const res = await fetch('http://localhost:3000/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: tab.url }),
  });
  const data = await res.json();
  renderResults(data);
}`,
    popupHtml: `<!DOCTYPE html>
<html>
<head>
  <link rel="stylesheet" href="popup.css" />
</head>
<body>
  <div class="extension-container">
    <header><h1>PhishGuard-AI</h1></header>
    <main>
      <input id="urlInput" placeholder="https://example.com" />
      <button id="scanBtn">Analyze Target URL</button>
      <div id="resultState">...</div>
    </main>
  </div>
  <script src="popup.js"></script>
</body>
</html>`,
  };

  return (
    <div className="space-y-6">
      {/* Overview Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Puzzle className="w-5 h-5 text-cyan-400" />
            Chrome Browser Extension (Manifest V3)
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Real-time browser security companion. Analyzes the active tab URL directly against the PhishGuard-AI backend with zero private data harvesting.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs px-2.5 py-1 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded-lg font-mono">
            Manifest V3 Ready
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Step-by-Step Installation Instructions */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            Local Chrome Installation Walkthrough
          </h2>

          <div className="space-y-4 text-xs">
            {/* Step 1 */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-300">Step 1: Open Chrome Extensions Manager</span>
                <button
                  onClick={() => copyText('chrome://extensions/', 1)}
                  className="text-slate-400 hover:text-slate-200 flex items-center gap-1"
                >
                  {copiedStep === 1 ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedStep === 1 ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <p className="text-slate-300">
                In Google Chrome, Brave, or Edge, type this address into your URL bar:
              </p>
              <div className="p-2 bg-slate-900 rounded font-mono text-cyan-300">chrome://extensions/</div>
            </div>

            {/* Step 2 */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <span className="font-bold text-cyan-300 block">Step 2: Enable Developer Mode</span>
              <p className="text-slate-300 leading-relaxed">
                Toggle the switch labeled <strong>"Developer mode"</strong> in the top-right corner of the Extensions page.
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-300">Step 3: Load Unpacked Extension</span>
              </div>
              <p className="text-slate-300 leading-relaxed">
                Click <strong>"Load unpacked"</strong> in the top-left toolbar and select the directory:
              </p>
              <div className="p-2 bg-slate-900 rounded font-mono text-cyan-300 break-all">
                /applet/extension/
              </div>
            </div>

            {/* Step 4 */}
            <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <span className="font-bold text-cyan-300 block">Step 4: Pin & Protect</span>
              <p className="text-slate-300 leading-relaxed">
                Click the puzzle icon in the Chrome toolbar and pin <strong>PhishGuard-AI</strong>. When browsing any website, click the shield to instantly scan the destination!
              </p>
            </div>
          </div>
        </div>

        {/* Extension Interactive Simulator Preview */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg flex flex-col items-center justify-center">
          <div className="text-center mb-2">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Live Extension Popup Preview
            </h3>
            <span className="text-[11px] text-slate-400">
              Interactive preview of the extension popup UI
            </span>
          </div>

          {/* Popup Mock Frame */}
          <div className="w-[340px] bg-[#0b0f19] border border-slate-700/80 rounded-xl p-4 shadow-2xl space-y-3 text-slate-100 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-cyan-400" />
                <div>
                  <div className="font-bold text-white leading-tight">PhishGuard-AI</div>
                  <div className="text-[9px] text-slate-400">Threat Intelligence Shield</div>
                </div>
              </div>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                Connected
              </span>
            </div>

            <div className="bg-[#131b2e] p-3 rounded-lg border border-slate-800 space-y-2">
              <label className="text-[10px] uppercase font-bold text-slate-400">Target URL</label>
              <input
                type="text"
                readOnly
                value="http://192.168.1.104/secure-chase-login"
                className="w-full bg-[#0b0f19] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono"
              />
              <button className="w-full py-1.5 bg-cyan-600 text-white font-semibold rounded text-xs">
                Analyze Target URL
              </button>
            </div>

            <div className="bg-[#131b2e] p-3 rounded-lg border border-rose-900/40 space-y-2">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-full border-2 border-rose-500 bg-[#0b0f19] flex flex-col items-center justify-center shrink-0">
                  <span className="text-sm font-black text-white">94</span>
                  <span className="text-[8px] text-slate-400">/100</span>
                </div>
                <div>
                  <div className="text-xs font-bold text-rose-400 uppercase">HIGH RISK DETECTED</div>
                  <div className="text-[10px] text-slate-400 font-mono">192.168.1.104</div>
                  <div className="text-[9px] text-slate-500">ML Confidence: 96%</div>
                </div>
              </div>
              <p className="text-[11px] text-slate-300 leading-snug">
                Direct IP host with acute credential harvesting keywords (secure, login).
              </p>
            </div>

            <div className="text-center text-[10px] text-slate-500 pt-1">
              PhishGuard-AI Manifest V3 Engine
            </div>
          </div>
        </div>
      </div>

      {/* Code Viewer */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="flex border-b border-slate-800 bg-slate-950/60">
          <button
            onClick={() => setActiveCodeFile('manifest')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeCodeFile === 'manifest'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            extension/manifest.json
          </button>
          <button
            onClick={() => setActiveCodeFile('popupJs')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeCodeFile === 'popupJs'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            extension/popup.js
          </button>
          <button
            onClick={() => setActiveCodeFile('popupHtml')}
            className={`py-2.5 px-4 text-xs font-medium border-b-2 transition-colors ${
              activeCodeFile === 'popupHtml'
                ? 'border-cyan-400 text-cyan-300 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            extension/popup.html
          </button>
        </div>

        <div className="p-4 bg-slate-950">
          <pre className="text-xs font-mono text-cyan-300/90 overflow-x-auto p-2">
            <code>{codeSnippets[activeCodeFile]}</code>
          </pre>
        </div>
      </div>
    </div>
  );
};
