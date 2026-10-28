import React, { useState } from 'react';
import { X, Lock, User, Mail, ShieldAlert, CheckCircle2 } from 'lucide-react';
import type { User as UserType } from '../types.js';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onLoginSuccess: (user: UserType, token: string) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onLoginSuccess }) => {
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<'user' | 'admin'>('user');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const endpoint = isRegister ? '/api/auth/register' : '/api/auth/login';
    const body = isRegister
      ? { name, email, username, password, role }
      : { username, password };

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Authentication failed');
      }

      onLoginSuccess(data.user, data.token);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Network error during authentication');
    } finally {
      setLoading(false);
    }
  };

  const handleDemoFill = (type: 'student' | 'admin') => {
    setIsRegister(false);
    setError(null);
    if (type === 'student') {
      setUsername('student');
      setPassword('student123');
    } else {
      setUsername('admin');
      setPassword('admin123');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-md bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 text-slate-100">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-slate-200 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="mb-6">
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            <Lock className="w-5 h-5 text-cyan-400" />
            {isRegister ? 'Create PhishGuard Account' : 'Sign In to PhishGuard-AI'}
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            {isRegister
              ? 'Register to persist personal scans, export CSVs, and manage threat alerts.'
              : 'Sign in to access your security scan history and administrative analytics.'}
          </p>
        </div>

        {/* Demo Account Quick-Fill Buttons */}
        <div className="mb-4 p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg">
          <div className="text-xs font-semibold text-slate-400 mb-2">QUICK DEMO SIGN-IN:</div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => handleDemoFill('student')}
              className="flex-1 py-1.5 px-3 text-xs font-medium rounded-md bg-cyan-950/60 text-cyan-300 border border-cyan-800/50 hover:bg-cyan-900/60 transition-colors"
            >
              Student Demo (student / student123)
            </button>
            <button
              type="button"
              onClick={() => handleDemoFill('admin')}
              className="flex-1 py-1.5 px-3 text-xs font-medium rounded-md bg-purple-950/60 text-purple-300 border border-purple-800/50 hover:bg-purple-900/60 transition-colors"
            >
              Admin (admin / admin123)
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-rose-950/50 border border-rose-800 text-rose-300 text-xs rounded-lg flex items-start gap-2">
            <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {isRegister && (
            <>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
                <div className="relative">
                  <User className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Rakesh S"
                    className="w-full bg-slate-950 border border-slate-750 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@university.edu"
                    className="w-full bg-slate-950 border border-slate-750 rounded-lg pl-9 pr-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Account Role</label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-750 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-cyan-500"
                >
                  <option value="user">Student / Security Analyst (Standard)</option>
                  <option value="admin">SOC Administrator (Admin Access)</option>
                </select>
              </div>
            </>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Username</label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username"
              className="w-full bg-slate-950 border border-slate-750 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full bg-slate-950 border border-slate-750 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-medium rounded-lg text-sm transition-colors flex items-center justify-center gap-2 shadow-lg shadow-cyan-900/20"
          >
            {loading ? (
              <span className="inline-block w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
            ) : isRegister ? (
              'Create Account'
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        <div className="mt-4 pt-4 border-t border-slate-800 text-center">
          <button
            type="button"
            onClick={() => {
              setIsRegister(!isRegister);
              setError(null);
            }}
            className="text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
          >
            {isRegister
              ? 'Already registered? Sign in with existing credentials'
              : "Don't have an account? Create one here"}
          </button>
        </div>
      </div>
    </div>
  );
};
