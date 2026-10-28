import type {
  UrlFeatures,
  DomainInfo,
  DnsInfo,
  MLAnalysis,
  RiskAnalysis,
  RiskLevel,
  IndicatorDetail,
} from '../src/types.js';

/**
 * Calculates a multi-factor risk score from 0 to 100 combining:
 * 1. Lexical and structural heuristic signals (40%)
 * 2. Host, domain reputation, and DNS signals (25%)
 * 3. Calibrated ML Ensemble probability (35%)
 */
export function calculateRiskScore(
  features: UrlFeatures,
  domainInfo: DomainInfo,
  dnsInfo: DnsInfo,
  mlAnalysis: MLAnalysis
): RiskAnalysis {
  const detectedIndicators: IndicatorDetail[] = [];
  let heuristicRawScore = 0;

  // 1. Check IP Host
  if (features.has_ip_address) {
    const pts = 25;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_ip_host',
      name: 'Direct IP Address Host',
      category: 'host',
      severity: 'high',
      score_contribution: pts,
      description: 'The URL uses an IP address instead of a domain name, a primary tactic used by phishing kits to evade DNS-based security filters.',
      evidence: `Host: ${domainInfo.domain}`,
    });
  }

  // 2. Suspicious URL Length
  if (features.url_length > 100) {
    const pts = 12;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_url_length',
      name: 'Excessive URL Length',
      category: 'lexical',
      severity: 'medium',
      score_contribution: pts,
      description: 'The URL is unusually long (> 100 characters), frequently used to hide actual destination paths or embed malicious payload tokens.',
      evidence: `Length: ${features.url_length} characters`,
    });
  } else if (features.url_length > 75) {
    const pts = 6;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_url_length_mod',
      name: 'Moderate URL Length',
      category: 'lexical',
      severity: 'low',
      score_contribution: pts,
      description: 'The URL length is above average (> 75 characters).',
      evidence: `Length: ${features.url_length} characters`,
    });
  }

  // 3. Subdomain Depth
  if (features.subdomain_count >= 3) {
    const pts = 15;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_subdomains',
      name: 'Deep Subdomain Nesting',
      category: 'lexical',
      severity: 'high',
      score_contribution: pts,
      description: 'URL exhibits 3 or more subdomain levels, typical of multi-tenant phishing kits spoofing legitimate brand names as subdomains.',
      evidence: `Subdomains: ${features.subdomain_count} detected`,
    });
  } else if (features.subdomain_count === 2) {
    const pts = 6;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_subdomains_mod',
      name: 'Multi-level Subdomain',
      category: 'lexical',
      severity: 'medium',
      score_contribution: pts,
      description: 'URL exhibits multiple subdomains, which may be used to mislead visitors regarding the true domain owner.',
      evidence: `Subdomains: 2 detected`,
    });
  }

  // 4. URL Shortener Gateway
  if (features.has_shortener) {
    const pts = 14;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_shortener',
      name: 'URL Shortener Redirection',
      category: 'reputation',
      severity: 'medium',
      score_contribution: pts,
      description: 'URL uses a link-shortening service that masks the real destination domain and impedes static reputation analysis.',
      evidence: `Shortener host detected`,
    });
  }

  // 5. Suspicious Security/Banking Keywords
  if (features.suspicious_keywords_found.length > 0) {
    const isMultiple = features.suspicious_keywords_found.length >= 2;
    const pts = isMultiple ? 22 : 12;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_keywords',
      name: isMultiple ? 'Multiple Sensitive Keywords' : 'Sensitive Keyword Detected',
      category: 'lexical',
      severity: isMultiple ? 'high' : 'medium',
      score_contribution: pts,
      description: `URL contains targeted terms (${features.suspicious_keywords_found.join(', ')}) commonly used in phishing campaigns targeting login credentials or payments.`,
      evidence: `Found: ${features.suspicious_keywords_found.join(', ')}`,
    });
  }

  // 6. '@' Symbol in URL
  if (features.has_at_symbol) {
    const pts = 20;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_at_symbol',
      name: '@ Character in URL Authority',
      category: 'lexical',
      severity: 'high',
      score_contribution: pts,
      description: 'The "@" character causes standard web browsers to ignore everything prior to it and navigate strictly to the host following it (URL spoofing).',
      evidence: 'Contains @ authority trick',
    });
  }

  // 7. Unusual or High-Risk TLD
  if (features.unusual_tld) {
    const pts = 12;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_unusual_tld',
      name: 'High-Abuse Top-Level Domain',
      category: 'reputation',
      severity: 'medium',
      score_contribution: pts,
      description: `The domain uses a TLD (.${features.tld}) with disproportionately high historical abuse rates according to threat intelligence feeds.`,
      evidence: `TLD: .${features.tld}`,
    });
  }

  // 8. Newly Created Domain (< 30 days)
  if (features.domain_age_days !== null && features.domain_age_days < 30) {
    const pts = 18;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_domain_age',
      name: 'Newly Registered Domain (< 30 days old)',
      category: 'host',
      severity: 'high',
      score_contribution: pts,
      description: 'Domain was registered very recently. Threat actors frequently create fresh domains and discard them after brief phishing campaigns.',
      evidence: `Age: ${features.domain_age_days} days old`,
    });
  }

  // 9. High Shannon Entropy / Obfuscation
  if (features.entropy > 4.2) {
    const pts = 10;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_entropy',
      name: 'High String Entropy (Obfuscation Signal)',
      category: 'lexical',
      severity: 'medium',
      score_contribution: pts,
      description: 'Character distribution exhibits high randomness (> 4.2 bits), characteristic of algorithmically generated domain names or obfuscated paths.',
      evidence: `Entropy: ${features.entropy} bits/char`,
    });
  }

  // 10. Punycode IDN Spoofing
  if (features.has_punycode) {
    const pts = 16;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_punycode',
      name: 'Punycode Internationalized Domain (IDN)',
      category: 'host',
      severity: 'high',
      score_contribution: pts,
      description: 'Domain uses xn-- encoding which can be exploited for homograph attacks (visually mimicking Latin characters with Cyrillic or Greek symbols).',
      evidence: 'Contains xn-- prefix',
    });
  }

  // 11. Suspicious Query Parameters (auth/redirect)
  if (features.suspicious_params_detected) {
    const pts = 8;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_params',
      name: 'Suspicious Redirect / Auth Parameters',
      category: 'lexical',
      severity: 'low',
      score_contribution: pts,
      description: 'URL parameters include redirect, token, or session keywords often used in open-redirect chaining attacks.',
      evidence: 'Query string contains redirect/token triggers',
    });
  }

  // 12. Non-HTTPS Protocol
  if (!features.has_https) {
    const pts = 8;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_no_https',
      name: 'Unencrypted HTTP Protocol',
      category: 'host',
      severity: 'low',
      score_contribution: pts,
      description: 'The connection lacks SSL/TLS encryption. Sensitive data transmitted over this URL is vulnerable to eavesdropping and interception.',
      evidence: 'Protocol: http://',
    });
  }

  // 13. Private/Reserved IP (SSRF danger)
  if (dnsInfo.is_private_ip) {
    const pts = 30;
    heuristicRawScore += pts;
    detectedIndicators.push({
      id: 'ind_private_ip',
      name: 'Internal / Private IP Host Target',
      category: 'host',
      severity: 'high',
      score_contribution: pts,
      description: 'Resolves to private, loopback, or cloud metadata address space. Potential SSRF vector.',
      evidence: `Resolves to: ${dnsInfo.ipv4.join(', ') || 'private IP'}`,
    });
  }

  // Cap heuristic score at 100
  const normalizedHeuristic = Math.min(100, heuristicRawScore);

  // ML model probability contribution (calibrated 0-1 mapped to 0-100)
  const mlContribution = Math.round(mlAnalysis.confidence * 100);

  // Composite Risk Score: 60% Heuristic + 40% ML Probability
  const compositeScore = Math.round(normalizedHeuristic * 0.6 + mlContribution * 0.4);
  const finalRiskScore = Math.min(100, Math.max(0, compositeScore));

  // Determine Risk Level
  let riskLevel: RiskLevel = 'LOW';
  if (finalRiskScore >= 65) {
    riskLevel = 'HIGH';
  } else if (finalRiskScore >= 35) {
    riskLevel = 'MEDIUM';
  } else {
    riskLevel = 'LOW';
  }

  // Actionable recommendations based on score and detected indicators
  const recommendations: string[] = [];
  if (riskLevel === 'HIGH') {
    recommendations.push('Do NOT click this link or submit any passwords, credit card numbers, or personal information.');
    recommendations.push('If this link was received in an email or SMS, report it as phishing to your security administrator or mail provider.');
    recommendations.push('If you already visited the URL, immediately change credentials for any associated account and enable two-factor authentication (2FA).');
  } else if (riskLevel === 'MEDIUM') {
    recommendations.push('Proceed with heightened caution. The URL exhibits anomalous attributes that may indicate a deceptive site.');
    recommendations.push('Inspect the browser address bar carefully to verify the exact domain spelling before entering any credentials.');
    recommendations.push('Consider cross-referencing with external threat intelligence or bookmarking the official service website directly.');
  } else {
    recommendations.push('No obvious phishing heuristics or high-risk signatures were flagged for this URL.');
    recommendations.push('Remain vigilant: low automated risk does NOT guarantee absolute safety. Always verify SSL certificates and site ownership before submitting private data.');
  }

  const summary =
    riskLevel === 'HIGH'
      ? `High-risk indicators detected (${detectedIndicators.length} flags, risk score ${finalRiskScore}/100). The destination exhibits strong hallmarks of credential harvesting, spoofing, or malicious redirection.`
      : riskLevel === 'MEDIUM'
      ? `Suspicious markers identified (${detectedIndicators.length} flags, risk score ${finalRiskScore}/100). Exercise caution and avoid submitting sensitive information until domain identity is confirmed.`
      : `Standard structural profile observed (${detectedIndicators.length} flags, risk score ${finalRiskScore}/100). No acute phishing indicators found in static and host heuristics.`;

  return {
    risk_score: finalRiskScore,
    risk_level: riskLevel,
    confidence: mlAnalysis.confidence,
    heuristic_score: normalizedHeuristic,
    ml_probability: mlAnalysis.confidence,
    detected_indicators: detectedIndicators,
    total_indicators_checked: 13,
    summary,
    recommendations,
    disclaimer:
      'Automated cybersecurity assessment based on static heuristics, domain telemetry, and ensemble machine learning. Automated detections can yield false positives or false negatives. The absence of detected warning signs does not constitute a guarantee of domain safety.',
  };
}
