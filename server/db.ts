import { hashPassword } from './auth.js';
import type {
  RiskLevel,
  Prediction,
  ScanResult,
  AdminStats,
  MessageScanResult,
} from '../src/types.js';

export interface DbUser {
  id: number;
  name: string;
  email: string;
  username: string;
  password_hash: string;
  role: 'admin' | 'user';
  created_at: string;
  last_login?: string;
}

export interface DbScanRecord {
  id: number;
  user_id: number | null;
  url: string;
  domain: string;
  prediction: Prediction;
  confidence: number;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
}

export interface DbFeatures {
  scan_id: number;
  url_length: number;
  domain_length: number;
  subdomain_count: number;
  special_character_count: number;
  digit_count: number;
  has_https: boolean;
  has_ip: boolean;
  has_shortener: boolean;
  suspicious_keyword: boolean;
  dot_count: number;
  hyphen_count: number;
  has_at_symbol: boolean;
  unusual_tld: boolean;
  encoded_chars: boolean;
  suspicious_params: boolean;
  entropy: number;
  domain_age_days: number | null;
  suspicious_keywords_found: string[];
  tld: string;
}

export interface DbDomainIntel {
  scan_id: number;
  domain: string;
  creation_date: string | null;
  expiration_date: string | null;
  updated_date: string | null;
  registrar: string | null;
  registrar_id: string | null;
  registrant_name: string | null;
  organization: string | null;
  country: string | null;
  privacy_protected: boolean;
  domain_status: string[];
  abuse_contact: string | null;
}

export interface DbDnsRecord {
  scan_id: number;
  ipv4: string[];
  ipv6: string[];
  nameservers: string[];
  hostname: string | null;
  dnssec: boolean;
}

class PhishGuardDatabase {
  private users: Map<number, DbUser> = new Map();
  private scans: Map<number, DbScanRecord> = new Map();
  private features: Map<number, DbFeatures> = new Map();
  private domainIntel: Map<number, DbDomainIntel> = new Map();
  private dnsRecords: Map<number, DbDnsRecord> = new Map();
  private messageScans: Map<number, MessageScanResult> = new Map();

  private nextUserId = 1;
  private nextScanId = 1;
  private nextMsgScanId = 1;

  constructor() {
    this.seedInitialData();
  }

  private seedInitialData() {
    // 1. Seed Administrator
    const adminId = this.nextUserId++;
    this.users.set(adminId, {
      id: adminId,
      name: 'Cyber Security Admin',
      email: 'admin@phishguard.local',
      username: 'admin',
      password_hash: hashPassword('admin123'),
      role: 'admin',
      created_at: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      last_login: new Date().toISOString(),
    });

    // 2. Seed Student / Demo User
    const studentId = this.nextUserId++;
    this.users.set(studentId, {
      id: studentId,
      name: 'Rakesh S (Student Researcher)',
      email: 'rakesh@phishguard.local',
      username: 'student',
      password_hash: hashPassword('student123'),
      role: 'user',
      created_at: new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString(),
      last_login: new Date().toISOString(),
    });

    // 3. Seed Sample Scans
    this.seedSampleScans(studentId);
  }

  private seedSampleScans(userId: number) {
    const seedUrls = [
      {
        url: 'http://192.168.1.104/secure-chase-login/verify.html?session=9284',
        domain: '192.168.1.104',
        prediction: 'PHISHING' as Prediction,
        confidence: 0.96,
        risk_score: 94,
        risk_level: 'HIGH' as RiskLevel,
        features: {
          url_length: 64,
          domain_length: 13,
          subdomain_count: 0,
          special_character_count: 14,
          digit_count: 15,
          has_https: false,
          has_ip: true,
          has_shortener: false,
          suspicious_keyword: true,
          dot_count: 4,
          hyphen_count: 2,
          has_at_symbol: false,
          unusual_tld: false,
          encoded_chars: false,
          suspicious_params: true,
          entropy: 4.35,
          domain_age_days: null,
          suspicious_keywords_found: ['secure', 'login', 'verify'],
          tld: '',
        },
      },
      {
        url: 'http://bit.ly/paypal-urgent-resolution-center',
        domain: 'bit.ly',
        prediction: 'SUSPICIOUS' as Prediction,
        confidence: 0.72,
        risk_score: 68,
        risk_level: 'HIGH' as RiskLevel,
        features: {
          url_length: 46,
          domain_length: 6,
          subdomain_count: 0,
          special_character_count: 7,
          digit_count: 0,
          has_https: false,
          has_ip: false,
          has_shortener: true,
          suspicious_keyword: true,
          dot_count: 1,
          hyphen_count: 3,
          has_at_symbol: false,
          unusual_tld: false,
          encoded_chars: false,
          suspicious_params: false,
          entropy: 4.12,
          domain_age_days: 5200,
          suspicious_keywords_found: ['paypal', 'urgent'],
          tld: 'ly',
        },
      },
      {
        url: 'https://github.com/kit25csecrakeshs-hue/PhishGuard-AI',
        domain: 'github.com',
        prediction: 'SAFE' as Prediction,
        confidence: 0.05,
        risk_score: 12,
        risk_level: 'LOW' as RiskLevel,
        features: {
          url_length: 53,
          domain_length: 10,
          subdomain_count: 0,
          special_character_count: 8,
          digit_count: 4,
          has_https: true,
          has_ip: false,
          has_shortener: false,
          suspicious_keyword: false,
          dot_count: 1,
          hyphen_count: 2,
          has_at_symbol: false,
          unusual_tld: false,
          encoded_chars: false,
          suspicious_params: false,
          entropy: 3.82,
          domain_age_days: 6100,
          suspicious_keywords_found: [],
          tld: 'com',
        },
      },
      {
        url: 'https://accounts.google.com/signin/v2/identifier',
        domain: 'accounts.google.com',
        prediction: 'SAFE' as Prediction,
        confidence: 0.12,
        risk_score: 18,
        risk_level: 'LOW' as RiskLevel,
        features: {
          url_length: 49,
          domain_length: 19,
          subdomain_count: 1,
          special_character_count: 7,
          digit_count: 1,
          has_https: true,
          has_ip: false,
          has_shortener: false,
          suspicious_keyword: true,
          dot_count: 2,
          hyphen_count: 0,
          has_at_symbol: false,
          unusual_tld: false,
          encoded_chars: false,
          suspicious_params: false,
          entropy: 3.78,
          domain_age_days: 9500,
          suspicious_keywords_found: ['signin'],
          tld: 'com',
        },
      },
    ];

    for (const item of seedUrls) {
      this.saveScanRecord(
        {
          user_id: userId,
          url: item.url,
          domain: item.domain,
          prediction: item.prediction,
          confidence: item.confidence,
          risk_score: item.risk_score,
          risk_level: item.risk_level,
        },
        item.features,
        {
          domain: item.domain,
          creation_date: '2010-01-01T00:00:00Z',
          expiration_date: '2028-01-01T00:00:00Z',
          updated_date: '2025-01-01T00:00:00Z',
          registrar: 'MarkMonitor Inc.',
          registrar_id: '292',
          registrant_name: 'Verified Host',
          organization: 'Infrastructure Services',
          country: 'US',
          privacy_protected: false,
          domain_status: ['clientTransferProhibited'],
          abuse_contact: 'abuse@domain.com',
        },
        {
          ipv4: ['140.82.121.3'],
          ipv6: [],
          nameservers: ['ns1.dns.com', 'ns2.dns.com'],
          hostname: item.domain,
          dnssec: true,
        }
      );
    }
  }

  // --- User Operations ---

  getUserByUsernameOrEmail(identifier: string): DbUser | undefined {
    const clean = identifier.trim().toLowerCase();
    for (const user of this.users.values()) {
      if (user.username.toLowerCase() === clean || user.email.toLowerCase() === clean) {
        return user;
      }
    }
    return undefined;
  }

  getUserById(id: number): DbUser | undefined {
    return this.users.get(id);
  }

  createUser(userData: Omit<DbUser, 'id' | 'created_at'>): DbUser {
    const id = this.nextUserId++;
    const user: DbUser = {
      id,
      ...userData,
      created_at: new Date().toISOString(),
    };
    this.users.set(id, user);
    return user;
  }

  updateUserLastLogin(userId: number): void {
    const user = this.users.get(userId);
    if (user) {
      user.last_login = new Date().toISOString();
    }
  }

  updateUserProfile(userId: number, name: string, email: string): DbUser | undefined {
    const user = this.users.get(userId);
    if (user) {
      user.name = name;
      user.email = email;
      return user;
    }
    return undefined;
  }

  getAllUsers(): DbUser[] {
    return Array.from(this.users.values());
  }

  deleteUser(id: number): boolean {
    return this.users.delete(id);
  }

  // --- Scan Operations ---

  saveScanRecord(
    scanData: Omit<DbScanRecord, 'id' | 'created_at'>,
    featureData: Omit<DbFeatures, 'scan_id'>,
    domainData: Omit<DbDomainIntel, 'scan_id'>,
    dnsData: Omit<DbDnsRecord, 'scan_id'>
  ): number {
    const scanId = this.nextScanId++;
    const record: DbScanRecord = {
      id: scanId,
      ...scanData,
      created_at: new Date().toISOString(),
    };

    this.scans.set(scanId, record);
    this.features.set(scanId, { scan_id: scanId, ...featureData });
    this.domainIntel.set(scanId, { scan_id: scanId, ...domainData });
    this.dnsRecords.set(scanId, { scan_id: scanId, ...dnsData });

    return scanId;
  }

  getUserScans(userId: number): DbScanRecord[] {
    const result: DbScanRecord[] = [];
    for (const scan of this.scans.values()) {
      if (scan.user_id === userId) {
        result.push(scan);
      }
    }
    return result.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  getAllScans(): DbScanRecord[] {
    return Array.from(this.scans.values()).sort(
      (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }

  getScanResultById(id: number): ScanResult | null {
    const scan = this.scans.get(id);
    if (!scan) return null;

    const feat = this.features.get(id);
    const domain = this.domainIntel.get(id);
    const dns = this.dnsRecords.get(id);

    return {
      id: scan.id,
      user_id: scan.user_id,
      url: scan.url,
      domain: scan.domain,
      prediction: scan.prediction,
      confidence: scan.confidence,
      risk_score: scan.risk_score,
      risk_level: scan.risk_level,
      created_at: scan.created_at,
      features: (feat as any) || {},
      domain_info: (domain as any) || { domain: scan.domain },
      dns_info: (dns as any) || { ipv4: [], nameservers: [] },
      ml_analysis: {
        prediction: scan.prediction,
        confidence: scan.confidence,
        model_type: 'Calibrated Random Forest Ensemble (12 Feature Trees)',
        top_features: [],
      },
      risk_analysis: {
        risk_score: scan.risk_score,
        risk_level: scan.risk_level,
        confidence: scan.confidence,
        heuristic_score: scan.risk_score,
        ml_probability: scan.confidence,
        detected_indicators: [],
        total_indicators_checked: 13,
        summary: `Historical assessment: ${scan.prediction} with risk score ${scan.risk_score}/100.`,
        recommendations: [
          scan.risk_level === 'HIGH'
            ? 'Avoid clicking or sharing credentials on this flagged destination.'
            : 'Maintain standard cybersecurity precautions.',
        ],
        disclaimer: 'Historical scan stored in database.',
      },
      recommendation:
        scan.prediction === 'PHISHING'
          ? 'Exercise extreme caution. Do not input credentials, passwords, or personal data.'
          : scan.prediction === 'SUSPICIOUS'
          ? 'Exercise caution and verify website identity through independent channels.'
          : 'Website demonstrates standard legitimate structural attributes.',
    };
  }

  deleteScan(id: number, userId: number, role?: string): boolean {
    const scan = this.scans.get(id);
    if (!scan) return false;

    // Authorization: User can only delete own scan, unless admin
    if (role !== 'admin' && scan.user_id !== userId) {
      return false;
    }

    this.scans.delete(id);
    this.features.delete(id);
    this.domainIntel.delete(id);
    this.dnsRecords.delete(id);
    return true;
  }

  // --- Message Scam Operations ---

  saveMessageScanRecord(record: MessageScanResult): number {
    const id = this.nextMsgScanId++;
    const stored = { ...record, id };
    this.messageScans.set(id, stored);
    return id;
  }

  getUserMessageScans(userId: number): MessageScanResult[] {
    const list: MessageScanResult[] = [];
    for (const scan of this.messageScans.values()) {
      if (scan.user_id === userId) {
        list.push(scan);
      }
    }
    return list.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  }

  deleteMessageScan(id: number, userId: number, role?: string): boolean {
    const scan = this.messageScans.get(id);
    if (!scan) return false;
    if (role !== 'admin' && scan.user_id !== userId) {
      return false;
    }
    return this.messageScans.delete(id);
  }

  // --- Admin & Global Analytics ---

  getAdminStats(): AdminStats {
    let phishing = 0;
    let suspicious = 0;
    let safe = 0;
    let totalScore = 0;
    const now = Date.now();
    let recent24h = 0;

    for (const s of this.scans.values()) {
      if (s.prediction === 'PHISHING' || s.risk_level === 'HIGH') phishing++;
      else if (s.prediction === 'SUSPICIOUS' || s.risk_level === 'MEDIUM') suspicious++;
      else safe++;

      totalScore += s.risk_score;
      if (now - new Date(s.created_at).getTime() < 24 * 60 * 60 * 1000) {
        recent24h++;
      }
    }

    const totalScans = this.scans.size;
    const avgScore = totalScans > 0 ? Math.round(totalScore / totalScans) : 0;

    return {
      total_scans: totalScans,
      phishing_scans: phishing,
      suspicious_scans: suspicious,
      safe_scans: safe,
      message_scans: this.messageScans.size,
      avg_risk_score: avgScore,
      total_users: this.users.size,
      recent_24h_scans: recent24h,
    };
  }

  exportScansCsv(userId?: number): string {
    const scansToExport = userId
      ? Array.from(this.scans.values()).filter(s => s.user_id === userId)
      : Array.from(this.scans.values());

    const headers = ['ID', 'Timestamp', 'Target URL', 'Domain', 'Classification', 'Risk Score', 'Risk Level', 'ML Confidence'];
    const rows = scansToExport.map(s => [
      s.id,
      `"${s.created_at}"`,
      `"${s.url.replace(/"/g, '""')}"`,
      `"${s.domain.replace(/"/g, '""')}"`,
      s.prediction,
      s.risk_score,
      s.risk_level,
      Math.round(s.confidence * 100) + '%',
    ]);

    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }
}

export const db = new PhishGuardDatabase();
export { hashPassword, verifyPassword } from './auth.js';
