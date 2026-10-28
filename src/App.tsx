import React, { useState, useEffect } from 'react';
import { Navbar, type NavTab } from './components/Navbar.tsx';
import { UrlScanner } from './components/UrlScanner.tsx';
import { MessageScamDetector } from './components/MessageScamDetector.tsx';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView.tsx';
import { ScanHistoryView } from './components/ScanHistoryView.tsx';
import { AnalyticsDashboard } from './components/AnalyticsDashboard.tsx';
import { ExtensionGuide } from './components/ExtensionGuide.tsx';
import { CollegeVivaDocs } from './components/CollegeVivaDocs.tsx';
import { AuthModal } from './components/AuthModal.tsx';
import type { User } from './types.js';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('url');
  const [currentUser, setCurrentUser] = useState<User | null>({
    id: 2,
    name: 'Rakesh S (Student Demo)',
    email: 'rakesh@phishguard.local',
    username: 'student',
    role: 'user',
    created_at: new Date().toISOString(),
  });
  const [token, setToken] = useState<string | null>(null);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  // Restore token if previously saved
  useEffect(() => {
    const savedToken = localStorage.getItem('phishguard_token');
    const savedUser = localStorage.getItem('phishguard_user');
    if (savedToken && savedUser) {
      try {
        setToken(savedToken);
        setCurrentUser(JSON.parse(savedUser));
      } catch {
        // Fallback to demo
      }
    }
  }, []);

  const handleLoginSuccess = (user: User, authToken: string) => {
    setCurrentUser(user);
    setToken(authToken);
    localStorage.setItem('phishguard_token', authToken);
    localStorage.setItem('phishguard_user', JSON.stringify(user));
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setToken(null);
    localStorage.removeItem('phishguard_token');
    localStorage.removeItem('phishguard_user');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        currentUser={currentUser}
        onOpenAuth={() => setIsAuthModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main Workspace View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentTab === 'url' && <UrlScanner token={token} />}
        {currentTab === 'message' && <MessageScamDetector token={token} />}
        {currentTab === 'intel' && <ThreatIntelligenceView />}
        {currentTab === 'history' && <ScanHistoryView token={token} />}
        {currentTab === 'analytics' && <AnalyticsDashboard token={token} />}
        {currentTab === 'extension' && <ExtensionGuide />}
        {currentTab === 'viva' && <CollegeVivaDocs />}
      </main>

      {/* Security Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/80 py-6 text-xs text-slate-400 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span className="font-semibold text-slate-300">PhishGuard-AI</span>
            <span className="text-slate-600">·</span>
            <span>AI-Based Phishing URL Detection & Scam Analysis System</span>
          </div>

          <div className="flex items-center gap-4 text-slate-400">
            <span>Manifest V3 Compatible</span>
            <span className="text-slate-600">·</span>
            <span>Google Safe Browsing & VirusTotal Integrated</span>
            <span className="text-slate-600">·</span>
            <span>Academic Defense Ready</span>
          </div>
        </div>
      </footer>

      {/* Auth Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onLoginSuccess={handleLoginSuccess}
      />
    </div>
  );
}
