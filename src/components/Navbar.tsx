import React from 'react';
import {
  Shield,
  Search,
  MessageSquareWarning,
  Globe2,
  History,
  BarChart3,
  Puzzle,
  GraduationCap,
  LogIn,
  LogOut,
  UserCheck,
} from 'lucide-react';
import type { User } from '../types.js';

export type NavTab = 'url' | 'message' | 'intel' | 'history' | 'analytics' | 'extension' | 'viva';

interface NavbarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  currentUser: User | null;
  onOpenAuth: () => void;
  onLogout: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  onTabChange,
  currentUser,
  onOpenAuth,
  onLogout,
}) => {
  const tabs = [
    { id: 'url' as NavTab, label: 'URL Scanner', icon: Search },
    { id: 'message' as NavTab, label: 'Message Scam Detector', icon: MessageSquareWarning },
    { id: 'intel' as NavTab, label: 'Threat Intelligence', icon: Globe2 },
    { id: 'history' as NavTab, label: 'Scan History', icon: History },
    { id: 'analytics' as NavTab, label: 'Analytics', icon: BarChart3 },
    { id: 'extension' as NavTab, label: 'Browser Extension', icon: Puzzle },
    { id: 'viva' as NavTab, label: 'Project Docs & Viva', icon: GraduationCap },
  ];

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo */}
          <div
            onClick={() => onTabChange('url')}
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white group-hover:text-cyan-300 transition-colors">
                  PhishGuard-AI
                </span>
                <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                AI Phishing URL, Scam & Threat Intelligence System
              </p>
            </div>
          </div>

          {/* System Status and User Control */}
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-2 text-xs text-slate-400 bg-slate-900/80 border border-slate-800 px-2.5 py-1.5 rounded-lg">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Engine Active</span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-400">Threat Intel Ready</span>
            </div>

            {currentUser ? (
              <div className="flex items-center gap-2">
                <div className="text-right hidden sm:block">
                  <div className="text-xs font-semibold text-slate-200">{currentUser.name}</div>
                  <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-mono">
                    {currentUser.role}
                  </div>
                </div>
                <button
                  onClick={onLogout}
                  title="Sign out"
                  className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-rose-300 hover:border-rose-900/50 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                </button>
              </div>
            ) : (
              <button
                onClick={onOpenAuth}
                className="flex items-center gap-1.5 py-1.5 px-3 rounded-lg bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 hover:bg-cyan-900/80 text-xs font-medium transition-colors"
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Sign In / Demo</span>
              </button>
            )}
          </div>
        </div>

        {/* Navigation Tabs Bar */}
        <nav className="flex space-x-1 overflow-x-auto py-2 scrollbar-none border-t border-slate-800/60">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = currentTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onTabChange(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-950'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
