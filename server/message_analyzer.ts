import { GoogleGenAI } from '@google/genai';
import { extractUrlFeatures } from './features.js';
import { classifyUrlWithML } from './ml_model.js';
import { calculateRiskScore } from './risk_engine.js';
import type {
  MessageScanResult,
  MessageScanIndicator,
  RiskLevel,
  ScanResult,
} from '../src/types.js';

// Regex for extracting HTTP/HTTPS and bare domain URLs from message text
const URL_REGEX = /\b(?:https?:\/\/[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|xyz|top|info|biz|io|online|co|site|app|me|club|buzz)\b[^\s<>"'{}|\\^`]*)/gi;

// Heuristic keyword clusters for scam categories
const URGENCY_TRIGGERS = [
  'immediately', 'urgent', 'urgently', 'within 24 hours', 'within 12 hours',
  'act now', 'limited time', 'final notice', 'account suspended', 'terminated immediately',
  'immediate action required', 'expires today', 'last chance', 'warning notice', 'restricted',
  'account has been restricted', 'suspension notice'
];

const CREDENTIAL_THEFT_TRIGGERS = [
  'verify your account', 'verify your identity', 'confirm your identity', 'update your credentials',
  'reset your password', 'security update required', 'unauthorized login', 'unauthorized activity',
  'suspicious activity detected', 'unlock your account', 'reactivate your account',
  'log in to verify', 'billing information expired', 'kyc verification', 'account verification'
];

const OTP_THEFT_TRIGGERS = [
  'send back the otp', 'reply with otp', 'share your code', 'provide the 6-digit',
  'one-time password', 'sms verification code', 'do not share this code with anyone but',
  'verification pin', 'enter code here'
];

const FAKE_PRIZE_TRIGGERS = [
  'congratulations you won', 'lottery winner', 'selected for a prize', 'claim your prize',
  'free gift card', 'walmart gift', 'amazon gift voucher', 'cash reward',
  'inheritance funds', 'millions of dollars', 'bitcoin giveaway', 'crypto reward'
];

const IMPERSONATION_TRIGGERS = [
  'irs', 'tax refund', 'usps', 'fedex', 'dhl', 'ups delivery', 'postal service',
  'paypal', 'apple support', 'microsoft support', 'chase bank', 'wells fargo',
  'bank of america', 'citi bank', 'geek squad', 'norton', 'mcafee', 'amazon support'
];

const PAYMENT_PRESSURE_TRIGGERS = [
  'wire money', 'gift card payment', 'pay overdue fee', 'bitcoin payment',
  'western union', 'penalty fee', 'legal action will be taken', 'law enforcement notice',
  'arrest warrant', 'court appearance', 'settle immediately', 'overdue payment'
];

/**
 * Extracts URLs from raw message text
 */
export function extractUrlsFromText(text: string): string[] {
  if (!text) return [];
  const matches = text.match(URL_REGEX) || [];
  return Array.from(new Set(matches.map(u => u.trim())));
}

/**
 * Heuristic scan of text for scam indicators
 */
function evaluateHeuristicScamSignals(text: string): {
  indicators: MessageScanIndicator[];
  rawHeuristicScore: number;
} {
  const lower = text.toLowerCase();
  const indicators: MessageScanIndicator[] = [];
  let score = 0;

  // 1. Urgency triggers
  const foundUrgency = URGENCY_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundUrgency.length > 0) {
    const pts = foundUrgency.length >= 2 ? 24 : 14;
    score += pts;
    indicators.push({
      type: 'urgency',
      severity: foundUrgency.length >= 2 ? 'high' : 'medium',
      title: 'Artificial Urgency & Coercive Deadline',
      description: 'The message creates panic through artificial deadlines or threats of immediate suspension to force hasty action.',
      matched_text: foundUrgency.slice(0, 3).join(', '),
    });
  }

  // 2. Credential Theft triggers
  const foundCred = CREDENTIAL_THEFT_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundCred.length > 0) {
    const pts = foundCred.length >= 2 ? 30 : 20;
    score += pts;
    indicators.push({
      type: 'credential_theft',
      severity: 'high',
      title: 'Credential Harvesting Bait',
      description: 'The message solicits account verification, password resets, or identity confirmation, a prime credential theft pattern.',
      matched_text: foundCred.slice(0, 3).join(', '),
    });
  }

  // 3. OTP / Security Code Requests
  const foundOtp = OTP_THEFT_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundOtp.length > 0) {
    const pts = 32;
    score += pts;
    indicators.push({
      type: 'otp_request',
      severity: 'high',
      title: 'One-Time Password (OTP) Elicitation',
      description: 'Legitimate services never ask you to forward or reply with verification codes. This is an account takeover attempt.',
      matched_text: foundOtp.slice(0, 2).join(', '),
    });
  }

  // 4. Fake Prize / Lottery
  const foundPrize = FAKE_PRIZE_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundPrize.length > 0) {
    const pts = 28;
    score += pts;
    indicators.push({
      type: 'fake_prize',
      severity: 'high',
      title: 'Unsolicited Prize / Reward Lure',
      description: 'Classic advance-fee or survey scam offering prizes, gift cards, or crypto rewards to entice clicking or fee payments.',
      matched_text: foundPrize.slice(0, 2).join(', '),
    });
  }

  // 5. Impersonation of trusted entities
  const foundImp = IMPERSONATION_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundImp.length > 0) {
    const pts = 20;
    score += pts;
    indicators.push({
      type: 'impersonation',
      severity: 'medium',
      title: 'Brand / Authority Impersonation',
      description: 'Message claims to represent postal services, tax agencies, or financial institutions commonly exploited as pretexting authorities.',
      matched_text: foundImp.slice(0, 2).join(', '),
    });
  }

  // 6. Payment pressure
  const foundPay = PAYMENT_PRESSURE_TRIGGERS.filter(kw => lower.includes(kw));
  if (foundPay.length > 0) {
    const pts = 24;
    score += pts;
    indicators.push({
      type: 'payment',
      severity: 'high',
      title: 'Unusual Payment / Wire Demand',
      description: 'Demands payment via non-standard irreversible channels (crypto, wire, gift cards) under threat of penalties or legal action.',
      matched_text: foundPay.slice(0, 2).join(', '),
    });
  }

  // Multi-Vector Synergy Bonus: Classic Phishing combination (Urgency + Credential Theft + Brand Impersonation)
  if (foundUrgency.length > 0 && (foundCred.length > 0 || foundImp.length > 0)) {
    score += 16;
  }

  return { indicators, rawHeuristicScore: Math.min(100, score) };
}

/**
 * Analyzes full email or SMS text, extracting URLs and calculating composite threat risk
 */
export async function analyzeMessageScam(
  text: string,
  userId?: number | null
): Promise<MessageScanResult> {
  const cleanText = (text || '').trim();
  const extractedUrls = extractUrlsFromText(cleanText);

  // 1. Analyze all extracted URLs using our URL pipeline
  const urlScanResults: Partial<ScanResult>[] = [];
  let highestUrlRisk = 0;

  for (const rawUrl of extractedUrls.slice(0, 4)) {
    try {
      let normalizedUrl = rawUrl;
      if (!/^https?:\/\//i.test(normalizedUrl)) {
        normalizedUrl = 'https://' + normalizedUrl;
      }
      const parsed = new URL(normalizedUrl);
      const features = extractUrlFeatures(normalizedUrl);
      const mlAnalysis = await classifyUrlWithML(normalizedUrl, features, parsed.hostname);
      const dummyDomainInfo = {
        domain: parsed.hostname,
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
        ipv4: [],
        ipv6: [],
        nameservers: [],
        hostname: parsed.hostname,
        dnssec: false,
        is_private_ip: false,
      };
      const risk = calculateRiskScore(features, dummyDomainInfo, dummyDns, mlAnalysis);

      if (risk.risk_score > highestUrlRisk) {
        highestUrlRisk = risk.risk_score;
      }

      urlScanResults.push({
        url: normalizedUrl,
        domain: parsed.hostname,
        prediction: mlAnalysis.prediction,
        confidence: mlAnalysis.confidence,
        risk_score: risk.risk_score,
        risk_level: risk.risk_level,
        recommendation: risk.recommendations[0] || 'Be cautious',
      });
    } catch {
      // Malformed URL, skip
    }
  }

  // 2. Evaluate heuristic scam signals
  const { indicators, rawHeuristicScore } = evaluateHeuristicScamSignals(cleanText);

  // Add indicator if suspicious link found in message
  if (extractedUrls.length > 0) {
    if (highestUrlRisk >= 65) {
      indicators.push({
        type: 'suspicious_link',
        severity: 'high',
        title: 'High-Risk Phishing Link Contained in Message',
        description: `Message embeds link(s) exhibiting strong phishing indicators (Risk Score: ${highestUrlRisk}/100).`,
        matched_text: extractedUrls[0],
      });
    } else if (highestUrlRisk >= 35) {
      indicators.push({
        type: 'suspicious_link',
        severity: 'medium',
        title: 'Suspicious Link Contained in Message',
        description: `Message embeds link(s) that require verification before clicking.`,
        matched_text: extractedUrls[0],
      });
    }
  }

  // Combine heuristic score and URL risk
  let combinedRiskScore = Math.max(rawHeuristicScore, Math.round(rawHeuristicScore * 0.5 + highestUrlRisk * 0.5));
  if (extractedUrls.length > 0 && highestUrlRisk >= 75) {
    combinedRiskScore = Math.max(combinedRiskScore, 80);
  }

  // Cap score
  combinedRiskScore = Math.min(100, Math.max(0, combinedRiskScore));

  let classification: 'LEGITIMATE' | 'SUSPICIOUS' | 'SCAM' = 'LEGITIMATE';
  let riskLevel: RiskLevel = 'LOW';

  if (combinedRiskScore >= 65) {
    classification = 'SCAM';
    riskLevel = 'HIGH';
  } else if (combinedRiskScore >= 35) {
    classification = 'SUSPICIOUS';
    riskLevel = 'MEDIUM';
  } else {
    classification = 'LEGITIMATE';
    riskLevel = 'LOW';
  }

  // 3. Optional Gemini AI semantic reasoning when valid API key is available
  let analysisMethod: 'GEMINI_AI_ASSISTED' | 'HEURISTIC_RULE_ENGINE' = 'HEURISTIC_RULE_ENGINE';
  let explanation = '';

  const apiKey = process.env.GEMINI_API_KEY;
  const isValidApiKey =
    process.env.NODE_ENV !== 'test' &&
    apiKey &&
    apiKey !== 'MY_GEMINI_API_KEY' &&
    !apiKey.startsWith('MY_');

  if (isValidApiKey && cleanText.length > 15) {
    try {
      const ai = new GoogleGenAI({
        apiKey: apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });

      const prompt = `You are a cybersecurity incident responder analyzing a suspicious email or SMS message.
Message content:
"""${cleanText.slice(0, 1500)}"""

Extracted URLs: ${extractedUrls.join(', ') || 'None'}
Heuristic Indicators: ${indicators.map(i => i.title).join('; ') || 'None'}
Initial Risk Score: ${combinedRiskScore}/100 (${classification})

Task:
1. Provide a concise, clear explanation (2-3 sentences) evaluating whether this message is a scam/phishing attempt or legitimate communication.
2. If legitimate, explain why (e.g. standard operational notification, benign tone, no coercive triggers).
3. If scam, explain the exact social engineering attack vector (e.g., smishing parcel delivery lure, CEO fraud, credential harvesting, or lottery scam).`;

      const geminiRes = await Promise.race([
        ai.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: prompt,
        }),
        new Promise<any>((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
      ]);

      if (geminiRes && geminiRes.text) {
        explanation = geminiRes.text.trim();
        analysisMethod = 'GEMINI_AI_ASSISTED';
      }
    } catch (err) {
      console.warn('Gemini scam analysis skipped:', err);
    }
  }

  // Fallback explanation if AI not configured or offline
  if (!explanation) {
    if (classification === 'SCAM') {
      explanation = `This message exhibits strong characteristics of a cyber scam (${indicators.length} warning indicators identified). The combination of coercive urgency, sensitive information requests, and embedded links represents a high-probability social engineering attack vector.`;
    } else if (classification === 'SUSPICIOUS') {
      explanation = `This message contains borderline suspicious language or unverified links (${indicators.length} indicator flagged). While it may be an aggressive marketing communication, treat it with caution and do not disclose sensitive details.`;
    } else {
      explanation = `This message does not exhibit characteristic phishing triggers, coercive urgency keywords, or deceptive credential links. It appears to be standard non-malicious text communication.`;
    }
  }

  // Recommendations
  const recommendedActions: string[] = [];
  if (classification === 'SCAM') {
    recommendedActions.push('Do not click any links, open attachments, or reply to the message.');
    recommendedActions.push('Never disclose passwords, two-factor authentication (OTP) codes, or payment cards.');
    recommendedActions.push('Block the sender number/address and report the communication as spam/phishing.');
    recommendedActions.push('If this was received in an organization, forward it to the internal security/SOC team.');
  } else if (classification === 'SUSPICIOUS') {
    recommendedActions.push('Contact the purported organization directly through verified contact details on their official website (not numbers or links provided in the message).');
    recommendedActions.push('Verify whether any action is actually pending on your official account.');
  } else {
    recommendedActions.push('Standard low-risk communication. Maintain standard cybersecurity hygiene.');
    recommendedActions.push('Remember that automated tools provide probability assessments and cannot guarantee 100% safety.');
  }

  return {
    id: Date.now(),
    user_id: userId,
    message_preview: cleanText.slice(0, 160) + (cleanText.length > 160 ? '...' : ''),
    message_length: cleanText.length,
    risk_score: combinedRiskScore,
    risk_level: riskLevel,
    classification,
    extracted_urls: extractedUrls,
    url_scan_results: urlScanResults,
    indicators,
    analysis_method: analysisMethod,
    explanation,
    recommended_actions: recommendedActions,
    created_at: new Date().toISOString(),
  };
}
