import type { ThreatIntelligenceResult, ThreatIntelligenceVendor } from '../src/types.js';

interface CacheEntry {
  result: ThreatIntelligenceResult;
  timestamp: number;
}

// In-memory cache to respect API rate limits and avoid duplicate external calls (TTL: 1 hour)
const threatIntelCache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 60 * 60 * 1000;

/**
 * Performs Google Safe Browsing Lookup v4
 */
async function checkGoogleSafeBrowsing(url: string, apiKey: string | undefined): Promise<ThreatIntelligenceVendor> {
  const checkedAt = new Date().toISOString();

  if (!apiKey || apiKey === 'MY_SAFE_BROWSING_KEY' || apiKey.trim() === '') {
    return {
      vendor: 'Google Safe Browsing',
      status: 'unconfigured',
      cached: false,
      checked_at: checkedAt,
      details: 'API key not configured in server environment. Add GOOGLE_SAFE_BROWSING_API_KEY in .env to activate live checks.',
    };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    const body = {
      client: {
        clientId: 'phishguard-ai',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };

    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 429) {
      return {
        vendor: 'Google Safe Browsing',
        status: 'error',
        cached: false,
        checked_at: checkedAt,
        details: 'Rate limit exceeded (HTTP 429). Threat intelligence request throttled by provider.',
      };
    }

    if (!res.ok) {
      return {
        vendor: 'Google Safe Browsing',
        status: 'error',
        cached: false,
        checked_at: checkedAt,
        details: `Service returned HTTP error ${res.status}. Check API key quotas and restrictions.`,
      };
    }

    const data = await res.json();
    if (data.matches && Array.isArray(data.matches) && data.matches.length > 0) {
      const match = data.matches[0];
      return {
        vendor: 'Google Safe Browsing',
        status: 'malicious',
        threat_type: match.threatType || 'SOCIAL_ENGINEERING',
        cached: false,
        checked_at: checkedAt,
        details: `Confirmed threat in Google Safe Browsing database (${match.threatType}).`,
      };
    }

    return {
      vendor: 'Google Safe Browsing',
      status: 'clean',
      cached: false,
      checked_at: checkedAt,
      details: 'No known security threats matched in current Google Safe Browsing repository.',
    };
  } catch (err: any) {
    return {
      vendor: 'Google Safe Browsing',
      status: 'error',
      cached: false,
      checked_at: checkedAt,
      details: err.name === 'AbortError' ? 'Lookup request timed out after 4 seconds.' : 'Network connection to Safe Browsing API failed.',
    };
  }
}

/**
 * Performs VirusTotal API v3 URL Reputation Check
 */
async function checkVirusTotal(url: string, apiKey: string | undefined): Promise<ThreatIntelligenceVendor> {
  const checkedAt = new Date().toISOString();

  if (!apiKey || apiKey === 'MY_VIRUSTOTAL_KEY' || apiKey.trim() === '') {
    return {
      vendor: 'VirusTotal',
      status: 'unconfigured',
      cached: false,
      checked_at: checkedAt,
      details: 'API key not configured in server environment. Add VIRUSTOTAL_API_KEY in .env to activate multi-engine intelligence.',
    };
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);

    // VirusTotal v3 requires base64url encoded URL identifier
    const urlId = Buffer.from(url).toString('base64url');

    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (res.status === 404) {
      return {
        vendor: 'VirusTotal',
        status: 'clean',
        cached: false,
        checked_at: checkedAt,
        details: 'URL has not been submitted or reported to VirusTotal partner engines yet.',
      };
    }

    if (res.status === 429) {
      return {
        vendor: 'VirusTotal',
        status: 'error',
        cached: false,
        checked_at: checkedAt,
        details: 'VirusTotal rate limit exceeded (HTTP 429 - 4 req/min free tier limit reached).',
      };
    }

    if (!res.ok) {
      return {
        vendor: 'VirusTotal',
        status: 'error',
        cached: false,
        checked_at: checkedAt,
        details: `VirusTotal returned status HTTP ${res.status}. Verify your API credentials.`,
      };
    }

    const json = await res.json();
    const stats = json?.data?.attributes?.last_analysis_stats;
    const malicious = stats?.malicious || 0;
    const suspicious = stats?.suspicious || 0;
    const total = (stats?.harmless || 0) + (stats?.undetected || 0) + malicious + suspicious;

    if (malicious > 0) {
      return {
        vendor: 'VirusTotal',
        status: 'malicious',
        positives: malicious,
        total_scans: total,
        cached: false,
        checked_at: checkedAt,
        details: `${malicious} out of ${total} antivirus engines flagged this URL as malicious.`,
      };
    }

    if (suspicious > 1) {
      return {
        vendor: 'VirusTotal',
        status: 'suspicious',
        positives: suspicious,
        total_scans: total,
        cached: false,
        checked_at: checkedAt,
        details: `${suspicious} out of ${total} security engines flagged suspicious indicators.`,
      };
    }

    return {
      vendor: 'VirusTotal',
      status: 'clean',
      positives: 0,
      total_scans: total,
      cached: false,
      checked_at: checkedAt,
      details: `0 / ${total} security engines detected threats on this URL.`,
    };
  } catch (err: any) {
    return {
      vendor: 'VirusTotal',
      status: 'error',
      cached: false,
      checked_at: checkedAt,
      details: err.name === 'AbortError' ? 'Lookup request timed out after 4 seconds.' : 'Network connection to VirusTotal API failed.',
    };
  }
}

/**
 * Aggregates threat intelligence from configured external providers with caching and fallback
 */
export async function queryThreatIntelligence(
  url: string,
  domain: string,
  forceRefresh = false
): Promise<ThreatIntelligenceResult> {
  const cacheKey = url.toLowerCase().trim();

  // Check in-memory cache
  if (!forceRefresh && threatIntelCache.has(cacheKey)) {
    const cached = threatIntelCache.get(cacheKey)!;
    if (Date.now() - cached.timestamp < CACHE_TTL_MS) {
      return {
        ...cached.result,
        vendors: cached.result.vendors.map(v => ({ ...v, cached: true })),
      };
    }
  }

  const safeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  const virusTotalKey = process.env.VIRUSTOTAL_API_KEY;

  const [gsbVendor, vtVendor] = await Promise.all([
    checkGoogleSafeBrowsing(url, safeBrowsingKey),
    checkVirusTotal(url, virusTotalKey),
  ]);

  const vendors: ThreatIntelligenceVendor[] = [gsbVendor, vtVendor];

  // Determine overall intelligence verdict
  const hasConfirmedMalicious = vendors.some(v => v.status === 'malicious');
  const hasSuspicious = vendors.some(v => v.status === 'suspicious');
  const allUnconfiguredOrError = vendors.every(v => v.status === 'unconfigured' || v.status === 'error');

  let overallVerdict: 'threat_detected' | 'no_threats_found' | 'intelligence_inconclusive';
  let notes: string;

  if (hasConfirmedMalicious) {
    overallVerdict = 'threat_detected';
    notes = 'One or more external threat intelligence providers confirmed active malicious reputation for this URL.';
  } else if (hasSuspicious) {
    overallVerdict = 'threat_detected';
    notes = 'Security vendors flagged anomalous or suspicious behavior associated with this domain.';
  } else if (allUnconfiguredOrError) {
    overallVerdict = 'intelligence_inconclusive';
    notes = 'External threat intelligence feeds are either unconfigured or unreachable. Detections rely on PhishGuard AI ML model and local heuristics.';
  } else {
    overallVerdict = 'no_threats_found';
    notes = 'External reputation feeds returned no known threat records. Note that zero hits on threat feeds does not guarantee a URL is harmless (zero-day phishing).';
  }

  const result: ThreatIntelligenceResult = {
    url,
    domain,
    overall_verdict: overallVerdict,
    vendors,
    notes,
  };

  // Cache result
  threatIntelCache.set(cacheKey, {
    result,
    timestamp: Date.now(),
  });

  return result;
}
