/**
 * PhishShield Chrome Extension - Popup Script
 * Scans current tab URL and displays risk assessment.
 */

const API_BASE = 'http://localhost:5000/api';

// Lightweight URL analyzer (runs in extension)
function analyzeURL(url) {
    const suspiciousTokens = ['login', 'signin', 'verify', 'account', 'password', 'secure', 'update', 'banking', 'confirm', 'credential', 'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'click', 'free', 'urgent', 'suspend'];
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site', '.pw', '.buzz', '.icu'];
    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];

    let parsed;
    try { parsed = new URL(url); } catch { return { score: 0.5, reasons: ['Unable to parse URL'] }; }

    const domain = parsed.hostname;
    let score = 0;
    const reasons = [];

    // Length
    if (url.length > 75) { score += 0.06; reasons.push(`Long URL (${url.length} chars)`); }
    if (url.length > 150) { score += 0.06; reasons.push('Extremely long URL'); }

    // IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) { score += 0.24; reasons.push('IP address used instead of domain'); }

    // Subdomains
    const subCount = domain.split('.').length - 2;
    if (subCount > 2) { score += 0.12; reasons.push(`Many subdomains (${subCount})`); }

    // Suspicious TLD
    if (suspiciousTLDs.some(t => domain.endsWith(t))) { score += 0.12; reasons.push('Suspicious TLD'); }

    // Shortener
    if (shorteners.some(s => domain.includes(s))) { score += 0.09; reasons.push('URL shortener'); }

    // @ sign
    if (url.includes('@')) { score += 0.15; reasons.push('Contains @ redirect'); }

    // HTTPS
    if (parsed.protocol !== 'https:') { score += 0.05; reasons.push('No HTTPS'); }

    // Suspicious tokens
    const urlLower = url.toLowerCase();
    const found = suspiciousTokens.filter(t => urlLower.includes(t));
    if (found.length) { score += Math.min(found.length * 0.04, 0.16); reasons.push(`Keywords: ${found.slice(0, 3).join(', ')}`); }

    // Hyphens
    const hyphens = (domain.match(/-/g) || []).length;
    if (hyphens > 3) { score += 0.07; reasons.push(`Many hyphens (${hyphens})`); }

    // Entropy
    const freq = {};
    for (const c of url) freq[c] = (freq[c] || 0) + 1;
    let entropy = 0;
    for (const c in freq) { const p = freq[c] / url.length; entropy -= p * Math.log2(p); }
    if (entropy > 4.5) { score += 0.07; reasons.push(`High entropy (${entropy.toFixed(1)})`); }

    score = Math.min(Math.max(score, 0), 1);
    return { score, reasons };
}

function getRiskLevel(score) {
    if (score > 0.8) return { level: 'CRITICAL', color: '#ef4444', icon: '🔴' };
    if (score > 0.6) return { level: 'HIGH', color: '#f97316', icon: '🟠' };
    if (score > 0.4) return { level: 'MEDIUM', color: '#eab308', icon: '🟡' };
    if (score > 0.2) return { level: 'LOW', color: '#84cc16', icon: '🟢' };
    return { level: 'SAFE', color: '#22c55e', icon: '✅' };
}

async function scanCurrentPage() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tabs[0]?.url || 'unknown';
    document.getElementById('currentUrl').textContent = url;

    if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) {
        document.getElementById('riskScore').textContent = '—';
        document.getElementById('riskScore').style.color = '#94a3b8';
        document.getElementById('riskLabel').textContent = 'BROWSER PAGE';
        document.getElementById('riskDesc').textContent = 'Internal browser pages are not scanned';
        return;
    }

    // Analyze locally
    const result = analyzeURL(url);
    const risk = getRiskLevel(result.score);

    document.getElementById('riskScore').textContent = `${(result.score * 100).toFixed(0)}%`;
    document.getElementById('riskScore').style.color = risk.color;
    document.getElementById('riskLabel').textContent = `${risk.icon} ${risk.level}`;
    document.getElementById('riskLabel').style.color = risk.color;
    document.getElementById('riskDesc').textContent = result.score > 0.6 ? '⚠️ This page may be a phishing attempt' : 'This page appears safe';

    if (result.reasons.length) {
        document.getElementById('reasonsBox').style.display = 'block';
        document.getElementById('reasonsList').innerHTML = result.reasons.map(r =>
            `<div class="reason-item"><span class="icon">⚡</span><span>${r}</span></div>`
        ).join('');
    }

    // Update status bar
    if (result.score > 0.6) {
        document.getElementById('statusDot').style.background = '#ef4444';
        document.getElementById('statusDot').style.boxShadow = '0 0 8px #ef4444';
        document.getElementById('statusText').textContent = 'Threat detected!';
    }

    // Try to also call backend API
    try {
        const response = await fetch(`${API_BASE}/scan/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        if (response.ok) {
            const data = await response.json();
            // Use backend result if available (more accurate)
            const backendRisk = getRiskLevel(data.risk_score);
            document.getElementById('riskScore').textContent = `${(data.risk_score * 100).toFixed(0)}%`;
            document.getElementById('riskScore').style.color = backendRisk.color;
            document.getElementById('riskLabel').textContent = `${backendRisk.icon} ${backendRisk.level}`;
            document.getElementById('riskLabel').style.color = backendRisk.color;
        }
    } catch (e) {
        // Backend not available, client-side results are shown
    }
}

function rescan() {
    document.getElementById('riskScore').textContent = '...';
    document.getElementById('riskScore').style.color = '#00d4ff';
    document.getElementById('riskLabel').textContent = 'Scanning...';
    document.getElementById('reasonsBox').style.display = 'none';
    setTimeout(scanCurrentPage, 500);
}

function reportPhishing() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const url = tabs[0]?.url;
        if (url) {
            chrome.storage.local.get('reports', (data) => {
                const reports = data.reports || [];
                reports.push({ url, timestamp: new Date().toISOString() });
                chrome.storage.local.set({ reports });
            });
            alert('⚠️ Page reported as phishing. Thank you for helping protect others!');
        }
    });
}

// Initialize
scanCurrentPage();
