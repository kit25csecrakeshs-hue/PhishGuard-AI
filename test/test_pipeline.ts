/**
 * PhishGuard-AI Automated Test Suite
 * Tests Feature Extraction, Random Forest ML, Risk Engine, Scam Analyzer, and Auth
 */

process.env.NODE_ENV = 'test';

import { extractUrlFeatures, calculateShannonEntropy } from '../server/features.js';
import { classifyUrlWithML } from '../server/ml_model.js';
import { calculateRiskScore } from '../server/risk_engine.js';
import { analyzeMessageScam } from '../server/message_analyzer.js';
import { isPrivateOrReservedIp } from '../server/dns.js';
import { hashPassword, verifyPassword, generateToken, decodeToken } from '../server/auth.js';
import { queryThreatIntelligence } from '../server/threat_intel.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName} ${detail ? `- ${detail}` : ''}`);
    failed++;
  }
}

async function runTestSuite() {
  console.log('\n=============================================');
  console.log('   PhishGuard-AI Automated Test Pipeline');
  console.log('=============================================\n');

  // Test 1: Feature Extraction - IP Address Host
  console.log('Group 1: URL Feature Extraction & Normalization');
  const ipFeatures = extractUrlFeatures('http://192.168.1.1/login.php');
  assert(ipFeatures.has_ip_address === true, 'Detects IPv4 host target');
  assert(ipFeatures.suspicious_keywords_found.includes('login'), 'Detects login keyword in path');

  // Test 2: URL Shortener
  const shortenerFeatures = extractUrlFeatures('https://bit.ly/secure-paypal-verify');
  assert(shortenerFeatures.has_shortener === true, 'Detects URL shortener domain (bit.ly)');
  assert(shortenerFeatures.suspicious_keywords_found.includes('paypal'), 'Detects brand impersonation keyword');

  // Test 3: Authority trick (@ symbol)
  const atFeatures = extractUrlFeatures('https://google.com@evil-attacker.xyz/auth');
  assert(atFeatures.has_at_symbol === true, 'Detects @ authority spoofing character');
  assert(atFeatures.unusual_tld === true, 'Detects unusual/high-risk TLD (.xyz)');

  // Test 4: Shannon Entropy
  const lowEntropy = calculateShannonEntropy('https://example.com/index.html');
  const highEntropy = calculateShannonEntropy('https://d9f82k3jx81nmqp928vj4.com/xq9281js?a=9284192');
  assert(highEntropy > lowEntropy, 'High randomness URL exhibits higher Shannon entropy than regular URL');

  // Test 5: SSRF Screening
  console.log('\nGroup 2: SSRF & Network Security Screening');
  assert(isPrivateOrReservedIp('127.0.0.1') === true, 'Flags 127.0.0.1 as reserved loopback');
  assert(isPrivateOrReservedIp('10.0.0.5') === true, 'Flags 10.0.0.0/8 private network');
  assert(isPrivateOrReservedIp('169.254.169.254') === true, 'Flags AWS/GCP link-local metadata address');
  assert(isPrivateOrReservedIp('8.8.8.8') === false, 'Allows public routable internet address');

  // Test 6: Calibrated ML Ensemble Classification
  console.log('\nGroup 3: Calibrated Random Forest ML Model');
  const phishTestUrl = 'http://192.168.1.1/paypal-update/login.php?token=9284';
  const phishTestFeatures = extractUrlFeatures(phishTestUrl);
  const mlPhish = await classifyUrlWithML(
    phishTestUrl,
    phishTestFeatures,
    '192.168.1.1'
  );
  assert(mlPhish.confidence > 0.6, 'ML calibrated probability > 0.6 for acute phishing features');
  assert(mlPhish.prediction === 'PHISHING' || mlPhish.prediction === 'SUSPICIOUS', 'ML prediction is flagged');

  // Test 7: Multi-Factor Risk Engine
  console.log('\nGroup 4: Multi-Factor Risk Engine & Explanations');
  const dummyDomainInfo = {
    domain: '192.168.1.1',
    creation_date: null,
    expiration_date: null,
    updated_date: null,
    registrar: null,
    registrar_id: null,
    registrant_name: null,
    organization: null,
    country: null,
    privacy_protected: false,
    domain_status: ['active'],
    abuse_contact: null,
  };
  const dummyDns = {
    ipv4: ['192.168.1.1'],
    ipv6: [],
    nameservers: [],
    hostname: '192.168.1.1',
    dnssec: false,
    is_private_ip: true,
  };
  const risk = calculateRiskScore(ipFeatures, dummyDomainInfo, dummyDns, mlPhish);
  assert(risk.risk_score >= 65, 'Calculates HIGH risk score for IP host with credentials');
  assert(risk.detected_indicators.length > 0, 'Generates granular detected indicators with score contributions');
  assert(risk.recommendations.length > 0, 'Provides actionable safety guidance');
  assert(typeof risk.disclaimer === 'string', 'Includes explicit automated assessment disclaimer');

  // Test 8: Email & SMS Scam Analyzer
  console.log('\nGroup 5: Email & SMS Scam Analysis');
  const phishingMessage = `URGENT: Your Chase Bank account has been restricted due to unauthorized login attempts. You must verify your identity within 24 hours to prevent permanent account suspension. Click here immediately: http://chase-secure-verification.xyz/login`;
  const scamResult = await analyzeMessageScam(phishingMessage);
  assert(scamResult.classification === 'SCAM', 'Classifies coercive urgency message as SCAM');
  assert(scamResult.extracted_urls.length > 0, 'Extracts embedded phishing links from message body');
  assert(scamResult.indicators.some(i => i.type === 'urgency'), 'Detects artificial urgency indicator');
  assert(scamResult.indicators.some(i => i.type === 'credential_theft'), 'Detects credential theft indicator');

  // Test 9: Legitimate Message Handling
  const benignMessage = `Hi Rakesh, are you available tomorrow at 3 PM to review the final project slides in the lab? Let me know if that works.`;
  const benignResult = await analyzeMessageScam(benignMessage);
  assert(benignResult.classification === 'LEGITIMATE', 'Legitimate conversation is NOT falsely classified as scam');
  assert(benignResult.risk_score < 35, 'Risk score is low for standard interpersonal message');

  // Test 10: Authentication & PBKDF2 Hashing
  console.log('\nGroup 6: Cryptographic Authentication & RBAC');
  const hashed = hashPassword('MySecretPassword@2026');
  assert(verifyPassword('MySecretPassword@2026', hashed) === true, 'PBKDF2 verifies correct password');
  assert(verifyPassword('WrongPassword', hashed) === false, 'Rejects incorrect password');

  const testUser = {
    id: 99,
    name: 'Security Analyst',
    email: 'analyst@phishguard.local',
    username: 'analyst',
    role: 'user' as const,
    created_at: new Date().toISOString(),
  };
  const token = generateToken(testUser);
  const decoded = decodeToken(token);
  assert(decoded !== null && decoded.username === 'analyst', 'Signed token decodes matching user payload');

  // Test 11: Threat Intelligence & Caching
  console.log('\nGroup 7: Threat Intelligence Caching & Fallbacks');
  const intel1 = await queryThreatIntelligence('https://example.com', 'example.com');
  assert(intel1.vendors.length === 2, 'Checks both Google Safe Browsing and VirusTotal vendors');
  const intel2 = await queryThreatIntelligence('https://example.com', 'example.com');
  assert(intel2.vendors[0].cached === true, 'Subsequent threat intel lookup returns from in-memory cache');

  console.log('\n=============================================');
  console.log(`Test Execution Finished: ${passed} Passed, ${failed} Failed.`);
  console.log('=============================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Fatal test execution error:', err);
  process.exit(1);
});
