/**
 * PhishShield Chrome Extension - Content Script
 * Scans page content for phishing indicators and injects warnings.
 */

(function () {
    'use strict';

    // Only run on HTTP/HTTPS pages
    if (!window.location.protocol.startsWith('http')) return;

    const INDICATORS = {
        passwordFields: document.querySelectorAll('input[type="password"]').length,
        loginForms: document.querySelectorAll('form[action*="login"], form[action*="signin"], form[action*="auth"]').length,
        hiddenFields: document.querySelectorAll('input[type="hidden"]').length,
        externalForms: 0,
        hasKeyLogger: false,
        hasObfuscatedJS: false,
        hasDisabledRightClick: false,
    };

    // Check external form submissions
    document.querySelectorAll('form[action]').forEach(form => {
        const action = form.getAttribute('action');
        if (action && action.startsWith('http') && !action.includes(window.location.hostname)) {
            INDICATORS.externalForms++;
        }
    });

    // Check for right-click disabled
    if (document.body?.getAttribute('oncontextmenu')?.includes('return false')) {
        INDICATORS.hasDisabledRightClick = true;
    }

    // Check scripts for suspicious patterns
    document.querySelectorAll('script').forEach(script => {
        const content = script.textContent || '';
        if (/eval\s*\(|unescape\s*\(|atob\s*\(/.test(content)) INDICATORS.hasObfuscatedJS = true;
        if (/onkeypress|onkeydown|addEventListener.*key/.test(content)) INDICATORS.hasKeyLogger = true;
    });

    // Calculate risk
    let risk = 0;
    if (INDICATORS.passwordFields > 0) risk += 0.1;
    if (INDICATORS.loginForms > 0) risk += 0.15;
    if (INDICATORS.externalForms > 0) risk += 0.3;
    if (INDICATORS.hiddenFields > 5) risk += 0.15;
    if (INDICATORS.hasKeyLogger) risk += 0.4;
    if (INDICATORS.hasObfuscatedJS) risk += 0.15;
    if (INDICATORS.hasDisabledRightClick) risk += 0.15;
    risk = Math.min(risk, 1);

    // Send results to background
    chrome.runtime?.sendMessage?.({
        type: 'PAGE_SCAN_RESULT',
        url: window.location.href,
        indicators: INDICATORS,
        risk: risk,
        timestamp: new Date().toISOString()
    });

    // If high risk, inject a warning banner
    if (risk > 0.5) {
        const banner = document.createElement('div');
        banner.id = 'phishshield-warning';
        banner.innerHTML = `
      <div style="
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 2147483647;
        background: linear-gradient(90deg, #ef4444, #dc2626);
        color: white;
        padding: 12px 20px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 12px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        animation: slideDown 0.3s ease;
      ">
        <span style="font-size: 20px;">🛡️</span>
        <strong>PhishShield Warning:</strong>
        <span>This page shows signs of a phishing attack. Exercise extreme caution!</span>
        <span style="margin-left:auto; font-size:12px; opacity:0.8;">Risk: ${(risk * 100).toFixed(0)}%</span>
        <button onclick="this.parentElement.parentElement.remove()" style="
          background: rgba(255,255,255,0.2);
          border: none;
          color: white;
          padding: 4px 12px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 12px;
        ">Dismiss</button>
      </div>
    `;

        const style = document.createElement('style');
        style.textContent = '@keyframes slideDown { from { transform: translateY(-100%); } to { transform: translateY(0); } }';
        document.head.appendChild(style);
        document.body.insertBefore(banner, document.body.firstChild);
    }
})();
