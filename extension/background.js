/**
 * PhishShield Chrome Extension - Background Service Worker
 * Monitors navigation and provides real-time protection.
 */

const API_BASE = 'http://localhost:5000/api';

// Suspicious TLDs for quick check
const SUSPECT_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site', '.pw', '.buzz', '.icu'];
const SUSPECT_TOKENS = ['login', 'signin', 'verify', 'account', 'password', 'suspend', 'urgent', 'banking', 'confirm', 'credential'];

// Listen for tab navigation
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        checkURL(tab.url, tabId);
    }
});

async function checkURL(url, tabId) {
    if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://')) return;

    // Quick local check first
    const quickScore = quickAnalyze(url);

    if (quickScore > 0.6) {
        // Show warning notification
        chrome.notifications.create(`warning-${tabId}`, {
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: '🛡️ PhishShield Warning',
            message: `Potential phishing site detected! Risk: ${(quickScore * 100).toFixed(0)}%\n${url.substring(0, 60)}...`,
            priority: 2
        });

        // Store the warning
        chrome.storage.local.get('warnings', (data) => {
            const warnings = data.warnings || [];
            warnings.unshift({ url, score: quickScore, timestamp: new Date().toISOString() });
            chrome.storage.local.set({ warnings: warnings.slice(0, 100) });
        });
    }

    // Also try backend API for deeper analysis
    try {
        const response = await fetch(`${API_BASE}/scan/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });
        if (response.ok) {
            const data = await response.json();
            if (data.is_phishing) {
                chrome.notifications.create(`api-warning-${tabId}`, {
                    type: 'basic',
                    iconUrl: 'icons/icon128.png',
                    title: '🚨 PhishShield ALERT',
                    message: `AI detected phishing! Risk: ${data.risk_level}\n${data.reasons?.[0] || 'Suspicious content detected'}`,
                    priority: 2
                });
            }
        }
    } catch (e) {
        // Backend not available
    }
}

function quickAnalyze(url) {
    let score = 0;
    try {
        const parsed = new URL(url);
        const domain = parsed.hostname;
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) score += 0.3;
        if (SUSPECT_TLDS.some(t => domain.endsWith(t))) score += 0.15;
        if (url.includes('@')) score += 0.2;
        if (domain.split('.').length > 4) score += 0.15;
        const urlLower = url.toLowerCase();
        const tokenHits = SUSPECT_TOKENS.filter(t => urlLower.includes(t)).length;
        score += Math.min(tokenHits * 0.05, 0.2);
        if (url.length > 100) score += 0.05;
        if (parsed.protocol !== 'https:') score += 0.05;
    } catch (e) { }
    return Math.min(score, 1);
}

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
    chrome.tabs.create({ url: 'http://localhost:8080' });
});

console.log('🛡️ PhishShield background service worker active');
