import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { db, hashPassword, verifyPassword } from './server/db.js';
import {
  authenticateToken,
  requireAdmin,
  optionalAuth,
  generateToken,
  AuthenticatedRequest,
} from './server/auth.js';
import { extractUrlFeatures } from './server/features.js';
import { lookupDomainRDAP, calculateDomainAgeDays } from './server/rdap.js';
import { lookupDnsAndIp, isPrivateOrReservedIp } from './server/dns.js';
import { classifyUrlWithML } from './server/ml_model.js';
import { calculateRiskScore } from './server/risk_engine.js';
import { analyzeMessageScam } from './server/message_analyzer.js';
import { queryThreatIntelligence } from './server/threat_intel.js';
import type { ScanResult } from './src/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Configure CORS for web app and Chrome Extension (chrome-extension://)
  app.use(
    cors({
      origin: true,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    })
  );

  app.use(express.json({ limit: '1mb' }));

  // ==========================================
  // AUTHENTICATION ROUTES
  // ==========================================

  // Register
  app.post('/api/auth/register', (req, res) => {
    try {
      const { name, email, username, password, role } = req.body;

      if (!name || !email || !username || !password) {
        res.status(400).json({ error: 'All fields are required' });
        return;
      }

      if (password.length < 6) {
        res.status(400).json({ error: 'Password must be at least 6 characters long' });
        return;
      }

      const existingUser = db.getUserByUsernameOrEmail(username);
      if (existingUser) {
        res.status(400).json({ error: 'Username is already taken' });
        return;
      }

      const existingEmail = db.getUserByUsernameOrEmail(email);
      if (existingEmail) {
        res.status(400).json({ error: 'Email is already registered' });
        return;
      }

      const assignedRole = role === 'admin' ? 'admin' : 'user';

      const newUser = db.createUser({
        name: name.trim(),
        email: email.trim().toLowerCase(),
        username: username.trim().toLowerCase(),
        password_hash: hashPassword(password),
        role: assignedRole,
      });

      const token = generateToken({
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        username: newUser.username,
        role: newUser.role,
        created_at: newUser.created_at,
      });

      res.status(201).json({
        success: true,
        token,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          username: newUser.username,
          role: newUser.role,
          created_at: newUser.created_at,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Registration failed' });
    }
  });

  // Login
  app.post('/api/auth/login', (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        res.status(400).json({ error: 'Username and password are required' });
        return;
      }

      const user = db.getUserByUsernameOrEmail(username);
      if (!user) {
        res.status(401).json({ error: 'Invalid username or password' });
        return;
      }

      const isValid = verifyPassword(password, user.password_hash);
      if (!isValid) {
        res.status(401).json({ error: 'Invalid username or password' });
        return;
      }

      db.updateUserLastLogin(user.id);

      const token = generateToken({
        id: user.id,
        name: user.name,
        email: user.email,
        username: user.username,
        role: user.role,
        created_at: user.created_at,
      });

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          username: user.username,
          role: user.role,
          created_at: user.created_at,
          last_login: user.last_login,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Login failed' });
    }
  });

  // Get current user
  app.get('/api/auth/me', authenticateToken, (req: AuthenticatedRequest, res) => {
    res.json({ user: req.user });
  });

  // Update profile
  app.put('/api/auth/profile', authenticateToken, (req: AuthenticatedRequest, res) => {
    try {
      const { name, email } = req.body;
      if (!name || !email) {
        res.status(400).json({ error: 'Name and email are required' });
        return;
      }

      const updated = db.updateUserProfile(req.user!.id, name.trim(), email.trim().toLowerCase());
      if (!updated) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({
        success: true,
        user: {
          id: updated.id,
          name: updated.name,
          email: updated.email,
          username: updated.username,
          role: updated.role,
          created_at: updated.created_at,
        },
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to update profile' });
    }
  });

  // ==========================================
  // URL ANALYSIS PIPELINE
  // ==========================================

  app.post('/api/scan', optionalAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { url } = req.body;

      if (!url || typeof url !== 'string' || url.trim().length === 0) {
        res.status(400).json({ error: 'Valid URL is required' });
        return;
      }

      let rawUrl = url.trim();
      if (!/^https?:\/\//i.test(rawUrl)) {
        rawUrl = 'https://' + rawUrl;
      }

      let parsed: URL;
      try {
        parsed = new URL(rawUrl);
      } catch {
        res.status(400).json({ error: 'Malformed URL structure. Please check syntax.' });
        return;
      }

      const domain = parsed.hostname.toLowerCase();

      // SSRF Security Defense: Block private/loopback/cloud metadata scanning attempts
      if (
        domain === 'localhost' ||
        domain === '127.0.0.1' ||
        domain === '169.254.169.254' ||
        isPrivateOrReservedIp(domain)
      ) {
        res.status(400).json({
          error: 'Security Policy Violation: Scanning internal, private, loopback, or cloud-metadata destinations is restricted to protect local infrastructure.',
        });
        return;
      }

      // Step 1: Initial feature extraction
      const initialFeatures = extractUrlFeatures(rawUrl);

      // Step 2, 3 & 4: Concurrent RDAP WHOIS, DNS Lookups, and Threat Intelligence
      const [domainInfo, dnsInfo, threatIntel] = await Promise.all([
        lookupDomainRDAP(domain),
        lookupDnsAndIp(domain),
        queryThreatIntelligence(rawUrl, domain),
      ]);

      // Calculate domain age in days from RDAP
      const domainAgeDays = calculateDomainAgeDays(domainInfo.creation_date);

      // Refresh features with domain age
      const features = extractUrlFeatures(rawUrl, domainAgeDays);

      // Step 5: AI/ML Random Forest Classification (+ Gemini analysis)
      const mlResult = await classifyUrlWithML(rawUrl, features, domain);

      // Step 6: Multi-Factor Risk Calculation
      const riskResult = calculateRiskScore(features, domainInfo, dnsInfo, mlResult);

      // Adjust risk score if external threat intelligence confirmed active malware/phishing
      if (threatIntel.overall_verdict === 'threat_detected') {
        riskResult.risk_score = Math.max(riskResult.risk_score, 88);
        riskResult.risk_level = 'HIGH';
        riskResult.detected_indicators.unshift({
          id: 'ind_threat_intel_match',
          name: 'Confirmed External Threat Intelligence Hit',
          category: 'reputation',
          severity: 'high',
          score_contribution: 35,
          description: threatIntel.notes,
          evidence: threatIntel.vendors.filter(v => v.status === 'malicious').map(v => `${v.vendor}: ${v.details}`).join('; ') || 'Malicious feed match',
        });
      }

      const userId = req.user ? req.user.id : 2; // Default to student demo user if unauthenticated

      // Step 7: Persist into database tables
      const scanId = db.saveScanRecord(
        {
          user_id: userId,
          url: rawUrl,
          domain,
          prediction: mlResult.prediction,
          confidence: mlResult.confidence,
          risk_score: riskResult.risk_score,
          risk_level: riskResult.risk_level,
        },
        {
          url_length: features.url_length,
          domain_length: features.domain_length,
          subdomain_count: features.subdomain_count,
          special_character_count: features.special_character_count,
          digit_count: features.digit_count,
          has_https: features.has_https,
          has_ip: features.has_ip_address,
          has_shortener: features.has_shortener,
          suspicious_keyword: features.suspicious_keyword_detected,
          dot_count: features.dot_count,
          hyphen_count: features.hyphen_count,
          has_at_symbol: features.has_at_symbol,
          unusual_tld: features.unusual_tld,
          encoded_chars: features.encoded_characters_detected,
          suspicious_params: features.suspicious_params_detected,
          entropy: features.entropy,
          domain_age_days: features.domain_age_days,
          suspicious_keywords_found: features.suspicious_keywords_found,
          tld: features.tld,
        },
        {
          domain: domainInfo.domain,
          creation_date: domainInfo.creation_date,
          expiration_date: domainInfo.expiration_date,
          updated_date: domainInfo.updated_date,
          registrar: domainInfo.registrar,
          registrar_id: domainInfo.registrar_id,
          registrant_name: domainInfo.registrant_name,
          organization: domainInfo.organization,
          country: domainInfo.country,
          privacy_protected: domainInfo.privacy_protected,
          domain_status: domainInfo.domain_status,
          abuse_contact: domainInfo.abuse_contact,
        },
        {
          ipv4: dnsInfo.ipv4,
          ipv6: dnsInfo.ipv6,
          nameservers: dnsInfo.nameservers,
          hostname: dnsInfo.hostname,
          dnssec: dnsInfo.dnssec,
        }
      );

      const fullResult: ScanResult = {
        id: scanId,
        user_id: userId,
        url: rawUrl,
        domain,
        prediction: mlResult.prediction,
        confidence: mlResult.confidence,
        risk_score: riskResult.risk_score,
        risk_level: riskResult.risk_level,
        created_at: new Date().toISOString(),
        features,
        domain_info: domainInfo,
        dns_info: dnsInfo,
        ml_analysis: mlResult,
        risk_analysis: riskResult,
        threat_intel: threatIntel,
        recommendation:
          mlResult.prediction === 'PHISHING' || riskResult.risk_level === 'HIGH'
            ? 'Exercise extreme caution. Do not input credentials, passwords, or personal data. Report this domain to security administrators.'
            : mlResult.prediction === 'SUSPICIOUS' || riskResult.risk_level === 'MEDIUM'
            ? 'Exercise caution and verify the website through an independent trusted source before proceeding.'
            : 'Website demonstrates standard legitimate structural attributes and active DNS/domain history.',
      };

      res.json(fullResult);
    } catch (err: any) {
      console.error('Scan pipeline error:', err);
      res.status(500).json({ error: err.message || 'Failed to complete URL analysis pipeline' });
    }
  });

  // Dedicated Domain Intelligence Lookup
  app.post('/api/domain-intel', async (req, res) => {
    try {
      const { domain } = req.body;
      if (!domain) {
        res.status(400).json({ error: 'Domain is required' });
        return;
      }

      const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//i, '').split('/')[0].trim();

      const [domainInfo, dnsInfo] = await Promise.all([
        lookupDomainRDAP(cleanDomain),
        lookupDnsAndIp(cleanDomain),
      ]);

      res.json({
        domain_info: domainInfo,
        dns_info: dnsInfo,
        domain_age_days: calculateDomainAgeDays(domainInfo.creation_date),
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Domain intelligence query failed' });
    }
  });

  // Dedicated External Threat Intelligence Lookup
  app.post('/api/threat-intel', async (req, res) => {
    try {
      const { url, forceRefresh } = req.body;
      if (!url) {
        res.status(400).json({ error: 'URL is required' });
        return;
      }

      let rawUrl = url.trim();
      if (!/^https?:\/\//i.test(rawUrl)) {
        rawUrl = 'https://' + rawUrl;
      }
      const parsed = new URL(rawUrl);

      const result = await queryThreatIntelligence(rawUrl, parsed.hostname, !!forceRefresh);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Threat intelligence query failed' });
    }
  });

  // ==========================================
  // MESSAGE SCAM DETECTOR ROUTE
  // ==========================================

  app.post('/api/message-scam', optionalAuth, async (req: AuthenticatedRequest, res) => {
    try {
      const { message } = req.body;
      if (!message || typeof message !== 'string' || message.trim().length === 0) {
        res.status(400).json({ error: 'Message text is required for scam analysis.' });
        return;
      }

      const userId = req.user ? req.user.id : 2;
      const result = await analyzeMessageScam(message, userId);

      // Save into DB
      db.saveMessageScanRecord(result);

      res.json(result);
    } catch (err: any) {
      console.error('Message scam analysis error:', err);
      res.status(500).json({ error: err.message || 'Failed to analyze message for scams.' });
    }
  });

  // ==========================================
  // DETECTION HISTORY ROUTES
  // ==========================================

  // User History (Optional Auth allows demo user viewing without forced login)
  app.get('/api/scans/history', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const userId = req.user ? req.user.id : 2; // Default to demo student user if not logged in
      const scans = db.getUserScans(userId);
      res.json(scans);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to load scan history' });
    }
  });

  // Message Scan History
  app.get('/api/scans/messages', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const userId = req.user ? req.user.id : 2;
      const messages = db.getUserMessageScans(userId);
      res.json(messages);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to load message history' });
    }
  });

  // Scan by ID
  app.get('/api/scans/:id', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const scan = db.getScanResultById(id);

      if (!scan) {
        res.status(404).json({ error: 'Scan record not found' });
        return;
      }

      // If authenticated and not admin, verify ownership
      if (req.user && req.user.role !== 'admin' && scan.user_id && scan.user_id !== req.user.id) {
        res.status(403).json({ error: 'Access restricted to report owner' });
        return;
      }

      res.json(scan);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch scan' });
    }
  });

  // Delete Scan
  app.delete('/api/scans/:id', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const userId = req.user ? req.user.id : 2;
      const role = req.user ? req.user.role : 'user';

      const success = db.deleteScan(id, userId, role);
      if (!success) {
        res.status(404).json({ error: 'Scan not found or permission denied' });
        return;
      }

      res.json({ success: true, message: 'Scan deleted successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to delete scan' });
    }
  });

  // Delete Message Scan
  app.delete('/api/scans/messages/:id', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const userId = req.user ? req.user.id : 2;
      const role = req.user ? req.user.role : 'user';

      const success = db.deleteMessageScan(id, userId, role);
      if (!success) {
        res.status(404).json({ error: 'Message scan not found or permission denied' });
        return;
      }

      res.json({ success: true, message: 'Message scan deleted successfully' });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to delete message scan' });
    }
  });

  // CSV Export
  app.get('/api/scans/export/csv', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const userId = req.user ? req.user.id : 2;
      const csv = db.exportScansCsv(userId);

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="phishguard-scans-${Date.now()}.csv"`);
      res.send(csv);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to export CSV' });
    }
  });

  // Analytics endpoint
  app.get('/api/analytics', optionalAuth, (req: AuthenticatedRequest, res) => {
    try {
      const stats = db.getAdminStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to load analytics' });
    }
  });

  // ==========================================
  // ADMIN DASHBOARD ROUTES
  // ==========================================

  app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
    try {
      const stats = db.getAdminStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to compute admin statistics' });
    }
  });

  app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    try {
      const users = db.getAllUsers().map((u) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        username: u.username,
        role: u.role,
        created_at: u.created_at,
        last_login: u.last_login,
      }));
      res.json(users);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch user list' });
    }
  });

  app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const success = db.deleteUser(id);
      if (!success) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      res.json({ success: true, message: 'User removed' });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to remove user' });
    }
  });

  app.get('/api/admin/all-scans', authenticateToken, requireAdmin, (req, res) => {
    try {
      const allScans = db.getAllScans();
      res.json(allScans);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Failed to fetch global scans' });
    }
  });

  // Health check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'PhishGuard-AI Threat Protection Server',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      integrations: {
        gemini_api: !!process.env.GEMINI_API_KEY,
        google_safe_browsing: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY && process.env.GOOGLE_SAFE_BROWSING_API_KEY !== 'MY_SAFE_BROWSING_KEY',
        virustotal: !!process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY !== 'MY_VIRUSTOTAL_KEY',
      },
    });
  });

  // ==========================================
  // VITE CLIENT MIDDLEWARE
  // ==========================================

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard AI Server active at http://0.0.0.0:${PORT}`);
  });
}

startServer();
