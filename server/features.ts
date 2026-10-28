import type { UrlFeatures } from '../src/types.js';

// Common URL shortening domains often leveraged in phishing campaigns
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'cutt.ly', 'rebrand.ly', 'tiny.cc', 'shorte.st',
  's.id', 'shorturl.at', 'bl.ink', 'rb.gy', 'v.gd', 'qr.ae'
]);

// Suspicious security-sensitive keywords frequently targeted by credential harvesters
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'secure',
  'account', 'update', 'banking', 'wallet', 'security', 'password', 'credential',
  'paypal', 'appleid', 'netflix', 'microsoft', 'office365', 'chase', 'wellsfargo',
  'bankofamerica', 'support', 'billing', 'invoice', 'confirm', 'recover',
  'authenticate', 'suspension', 'suspended', 'unlock', 'urgent', 'kyc', 'crypto'
];

// High-risk or frequently abused TLDs (based on Spamhaus & APWG intelligence)
const UNUSUAL_OR_RISKY_TLDS = new Set([
  'xyz', 'top', 'buzz', 'club', 'work', 'loan', 'gq', 'tk', 'ml', 'cf', 'ga',
  'surf', 'icu', 'fit', 'rest', 'live', 'click', 'link', 'mom', 'date', 'faith',
  'racing', 'win', 'party', 'stream', 'accountant', 'download', 'bid'
]);

/**
 * Computes Shannon entropy of an input string to gauge randomness/obfuscation
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const len = str.length;
  const frequencies = new Map<string, number>();

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Comprehensive lexical, structural, and host feature extractor
 */
export function extractUrlFeatures(rawUrl: string, domainAgeDays: number | null = null): UrlFeatures {
  let normalized = rawUrl.trim();
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'https://' + normalized;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    // Return safe default features on malformed string
    return {
      url_length: normalized.length,
      domain_length: 0,
      subdomain_count: 0,
      special_character_count: (normalized.match(/[^a-zA-Z0-9]/g) || []).length,
      digit_count: (normalized.match(/[0-9]/g) || []).length,
      has_https: false,
      has_ip_address: false,
      has_shortener: false,
      suspicious_keyword_detected: false,
      suspicious_keywords_found: [],
      dot_count: (normalized.match(/\./g) || []).length,
      hyphen_count: (normalized.match(/-/g) || []).length,
      has_at_symbol: normalized.includes('@'),
      unusual_tld: false,
      tld: '',
      encoded_characters_detected: /%[0-9a-fA-F]{2}/.test(normalized),
      suspicious_params_detected: false,
      entropy: calculateShannonEntropy(normalized),
      domain_age_days: domainAgeDays,
      path_depth: 0,
      has_punycode: false,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const search = parsed.search;

  // 1. IP Address Host Check (IPv4 or IPv6)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  const hasIpAddress = ipv4Regex.test(hostname) || isIpv6;

  // 2. Subdomains extraction
  const domainParts = hostname.split('.');
  const tld = domainParts.length > 1 ? domainParts[domainParts.length - 1] : '';
  const subdomainCount = Math.max(0, domainParts.length - 2);

  // 3. Shortener detection
  const hasShortener = SHORTENER_DOMAINS.has(hostname) || SHORTENER_DOMAINS.has(domainParts.slice(-2).join('.'));

  // 4. Keyword detection across full URL (lowercase)
  const fullLower = normalized.toLowerCase();
  const keywordsFound = SUSPICIOUS_KEYWORDS.filter(kw => fullLower.includes(kw));

  // 5. Special character and digit counts
  const specialChars = (normalized.match(/[^a-zA-Z0-9]/g) || []).length;
  const digitCount = (normalized.match(/[0-9]/g) || []).length;
  const dotCount = (normalized.match(/\./g) || []).length;
  const hyphenCount = (normalized.match(/-/g) || []).length;
  const hasAtSymbol = normalized.includes('@');

  // 6. Encoded characters (%20, %2f, etc.)
  const encodedChars = /%[0-9a-fA-F]{2}/.test(normalized);

  // 7. Suspicious query params
  const suspiciousParams = /(?:redirect|return|return_url|next|goto|auth|session|token|passwd|password|account_id)=/i.test(search);

  // 8. Path depth
  const pathDepth = pathname.split('/').filter(Boolean).length;

  // 9. Punycode check (internationalized domain spoofing / homograph attack)
  const hasPunycode = hostname.includes('xn--');

  // 10. TLD Risk
  const unusualTld = UNUSUAL_OR_RISKY_TLDS.has(tld);

  return {
    url_length: normalized.length,
    domain_length: hostname.length,
    subdomain_count: subdomainCount,
    special_character_count: specialChars,
    digit_count: digitCount,
    has_https: parsed.protocol === 'https:',
    has_ip_address: hasIpAddress,
    has_shortener: hasShortener,
    suspicious_keyword_detected: keywordsFound.length > 0,
    suspicious_keywords_found: keywordsFound,
    dot_count: dotCount,
    hyphen_count: hyphenCount,
    has_at_symbol: hasAtSymbol,
    unusual_tld: unusualTld,
    tld,
    encoded_characters_detected: encodedChars,
    suspicious_params_detected: suspiciousParams,
    entropy: calculateShannonEntropy(normalized),
    domain_age_days: domainAgeDays,
    path_depth: pathDepth,
    has_punycode: hasPunycode,
  };
}
