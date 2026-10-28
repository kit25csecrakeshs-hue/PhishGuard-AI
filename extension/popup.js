// PhishGuard-AI Chrome Extension Popup Script

const DEFAULT_BACKEND = 'http://localhost:3000';
let currentBackendUrl = DEFAULT_BACKEND;
let lastScanData = null;

// DOM Elements
const urlInput = document.getElementById('urlInput');
const getCurrentTabBtn = document.getElementById('getCurrentTabBtn');
const scanBtn = document.getElementById('scanBtn');
const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const resultState = document.getElementById('resultState');
const backendStatus = document.getElementById('backendStatus');
const errorMessage = document.getElementById('errorMessage');
const retryBtn = document.getElementById('retryBtn');

const riskScoreEl = document.getElementById('riskScore');
const riskClassificationEl = document.getElementById('riskClassification');
const targetDomainEl = document.getElementById('targetDomain');
const mlConfidenceEl = document.getElementById('mlConfidence');
const explanationTextEl = document.getElementById('explanationText');
const indicatorListEl = document.getElementById('indicatorList');
const indicatorCountEl = document.getElementById('indicatorCount');
const recommendationTextEl = document.getElementById('recommendationText');
const copyDetailsBtn = document.getElementById('copyDetailsBtn');
const copiedNotice = document.getElementById('copiedNotice');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  // Check backend health
  checkBackendHealth();

  // Try to populate current tab URL
  populateActiveTabUrl();

  // Event Listeners
  getCurrentTabBtn.addEventListener('click', populateActiveTabUrl);
  scanBtn.addEventListener('click', handleScan);
  retryBtn.addEventListener('click', checkBackendHealth);
  copyDetailsBtn.addEventListener('click', copyScanReport);
});

async function checkBackendHealth() {
  backendStatus.textContent = 'Connecting...';
  backendStatus.className = 'badge-status';

  try {
    const res = await fetch(`${currentBackendUrl}/api/health`, { method: 'GET' });
    if (res.ok) {
      backendStatus.textContent = 'Backend Online';
      backendStatus.className = 'badge-status online';
      hideError();
    } else {
      throw new Error(`Server returned status ${res.status}`);
    }
  } catch (err) {
    backendStatus.textContent = 'Backend Offline';
    backendStatus.className = 'badge-status offline';
  }
}

function populateActiveTabUrl() {
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        const url = tabs[0].url;
        // Don't auto-fill internal chrome:// or extension:// URLs
        if (!url.startsWith('chrome://') && !url.startsWith('chrome-extension://')) {
          urlInput.value = url;
        }
      }
    });
  } else {
    // Fallback for local preview in browser
    if (!urlInput.value) {
      urlInput.value = 'https://phishing-bank-verification.com/login?token=urgent';
    }
  }
}

async function handleScan() {
  const rawUrl = urlInput.value.trim();
  if (!rawUrl) {
    showError('Please enter or select a valid URL to analyze.');
    return;
  }

  hideAllPanels();
  loadingState.classList.remove('hidden');

  try {
    const res = await fetch(`${currentBackendUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl }),
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.error || `Scan request failed with HTTP ${res.status}`);
    }

    const data = await res.json();
    lastScanData = data;
    renderScanResult(data);
  } catch (err) {
    loadingState.classList.add('hidden');
    showError(err.message || 'Could not communicate with the PhishGuard server. Is the server running?');
  }
}

function renderScanResult(data) {
  loadingState.classList.add('hidden');
  resultState.classList.remove('hidden');

  const riskScore = data.risk_score || 0;
  const riskLevel = data.risk_level || 'LOW';

  riskScoreEl.textContent = riskScore;
  riskClassificationEl.textContent = `${riskLevel} Risk`;
  targetDomainEl.textContent = data.domain || 'Target Host';
  mlConfidenceEl.textContent = `ML Confidence: ${Math.round((data.confidence || 0) * 100)}%`;

  // Update dial color
  const dial = document.querySelector('.score-dial');
  dial.className = 'score-dial';
  if (riskLevel === 'HIGH') {
    dial.classList.add('high-risk');
    riskClassificationEl.style.color = '#f43f5e';
  } else if (riskLevel === 'MEDIUM') {
    dial.classList.add('medium-risk');
    riskClassificationEl.style.color = '#f59e0b';
  } else {
    dial.classList.add('low-risk');
    riskClassificationEl.style.color = '#10b981';
  }

  // Security Analysis Summary
  explanationTextEl.textContent =
    data.risk_analysis?.summary || data.ml_analysis?.ai_summary || 'Analysis completed.';

  // Indicators
  const indicators = data.risk_analysis?.detected_indicators || [];
  indicatorCountEl.textContent = indicators.length;
  indicatorListEl.innerHTML = '';

  if (indicators.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No acute threat indicators flagged in static heuristics.';
    li.style.borderLeftColor = '#10b981';
    indicatorListEl.appendChild(li);
  } else {
    indicators.slice(0, 5).forEach((ind) => {
      const li = document.createElement('li');
      li.innerHTML = `<span><strong>${ind.name}</strong></span> <span>+${ind.score_contribution} pts</span>`;
      li.style.borderLeftColor = ind.severity === 'high' ? '#f43f5e' : '#f59e0b';
      indicatorListEl.appendChild(li);
    });
  }

  // Recommendation
  recommendationTextEl.textContent = data.recommendation || 'Maintain standard vigilance.';
}

function copyScanReport() {
  if (!lastScanData) return;

  const text = `--- PhishGuard-AI Threat Scan Report ---
Target URL: ${lastScanData.url}
Domain: ${lastScanData.domain}
Risk Score: ${lastScanData.risk_score}/100 (${lastScanData.risk_level})
ML Prediction: ${lastScanData.prediction} (Confidence: ${Math.round((lastScanData.confidence || 0) * 100)}%)
Recommendation: ${lastScanData.recommendation}
Generated by PhishGuard-AI at ${new Date().toISOString()}`;

  navigator.clipboard.writeText(text).then(() => {
    copiedNotice.classList.remove('hidden');
    setTimeout(() => copiedNotice.classList.add('hidden'), 2500);
  });
}

function showError(msg) {
  loadingState.classList.add('hidden');
  resultState.classList.add('hidden');
  errorState.classList.remove('hidden');
  errorMessage.textContent = msg;
}

function hideError() {
  errorState.classList.add('hidden');
}

function hideAllPanels() {
  loadingState.classList.add('hidden');
  errorState.classList.add('hidden');
  resultState.classList.add('hidden');
}
