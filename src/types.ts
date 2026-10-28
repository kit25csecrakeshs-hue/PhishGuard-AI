/**
 * PhishGuard-AI Type Definitions
 */

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type Prediction = 'SAFE' | 'SUSPICIOUS' | 'PHISHING';

export interface UrlFeatures {
  url_length: number;
  domain_length: number;
  subdomain_count: number;
  special_character_count: number;
  digit_count: number;
  has_https: boolean;
  has_ip_address: boolean;
  has_shortener: boolean;
  suspicious_keyword_detected: boolean;
  suspicious_keywords_found: string[];
  dot_count: number;
  hyphen_count: number;
  has_at_symbol: boolean;
  unusual_tld: boolean;
  tld: string;
  encoded_characters_detected: boolean;
  suspicious_params_detected: boolean;
  entropy: number;
  domain_age_days: number | null;
  path_depth: number;
  has_punycode: boolean;
}

export interface DomainInfo {
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

export interface DnsInfo {
  ipv4: string[];
  ipv6: string[];
  nameservers: string[];
  hostname: string | null;
  dnssec: boolean;
  is_private_ip: boolean;
}

export interface IndicatorDetail {
  id: string;
  name: string;
  category: 'lexical' | 'host' | 'reputation' | 'content';
  severity: 'low' | 'medium' | 'high';
  score_contribution: number;
  description: string;
  evidence: string;
}

export interface MLAnalysis {
  prediction: Prediction;
  confidence: number; // 0 to 1 calibrated probability
  model_type: string;
  decision_trees_voted_phishing?: number;
  total_trees?: number;
  top_features: { name: string; weight: number; value: any }[];
  ai_summary?: string;
}

export interface RiskAnalysis {
  risk_score: number; // 0 to 100
  risk_level: RiskLevel;
  confidence: number;
  heuristic_score: number;
  ml_probability: number;
  detected_indicators: IndicatorDetail[];
  total_indicators_checked: number;
  summary: string;
  recommendations: string[];
  disclaimer: string;
}

export interface ThreatIntelligenceVendor {
  vendor: 'Google Safe Browsing' | 'VirusTotal' | 'PhishGuard Local ThreatDB';
  status: 'clean' | 'malicious' | 'suspicious' | 'unconfigured' | 'error';
  threat_type?: string;
  positives?: number;
  total_scans?: number;
  cached: boolean;
  checked_at: string;
  details?: string;
}

export interface ThreatIntelligenceResult {
  url: string;
  domain: string;
  overall_verdict: 'threat_detected' | 'no_threats_found' | 'intelligence_inconclusive';
  vendors: ThreatIntelligenceVendor[];
  notes: string;
}

export interface ScanResult {
  id: number;
  user_id?: number | null;
  url: string;
  domain: string;
  prediction: Prediction;
  confidence: number;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
  features: UrlFeatures;
  domain_info: DomainInfo;
  dns_info: DnsInfo;
  ml_analysis: MLAnalysis;
  risk_analysis: RiskAnalysis;
  threat_intel?: ThreatIntelligenceResult;
  recommendation: string;
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

export interface MessageScanIndicator {
  type: 'urgency' | 'payment' | 'credential_theft' | 'impersonation' | 'fake_prize' | 'suspicious_link' | 'otp_request';
  severity: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  matched_text?: string;
}

export interface MessageScanResult {
  id: number;
  user_id?: number | null;
  message_preview: string;
  message_length: number;
  risk_score: number;
  risk_level: RiskLevel;
  classification: 'LEGITIMATE' | 'SUSPICIOUS' | 'SCAM';
  extracted_urls: string[];
  url_scan_results: Partial<ScanResult>[];
  indicators: MessageScanIndicator[];
  analysis_method: 'GEMINI_AI_ASSISTED' | 'HEURISTIC_RULE_ENGINE';
  explanation: string;
  recommended_actions: string[];
  created_at: string;
}

export interface User {
  id: number;
  name: string;
  email: string;
  username: string;
  role: 'user' | 'admin';
  created_at: string;
  last_login?: string;
}

export interface AdminStats {
  total_scans: number;
  phishing_scans: number;
  suspicious_scans: number;
  safe_scans: number;
  message_scans: number;
  avg_risk_score: number;
  total_users: number;
  recent_24h_scans: number;
}
