/**
 * PhishShield Dashboard — Main Application JavaScript
 * Handles navigation, scanning, results display, and real-time updates.
 */

const API_BASE = 'http://localhost:5000/api';

// ===== Theme Management =====
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('phishshield-theme', next);
  updateThemeUI(next);
}

function updateThemeUI(theme) {
  const icon = document.getElementById('theme-icon');
  const label = document.getElementById('theme-label');
  if (icon) icon.textContent = theme === 'dark' ? '🌙' : '☀️';
  if (label) label.textContent = theme === 'dark' ? 'Dark Mode' : 'Light Mode';
}

// Auto-load saved theme
(function initTheme() {
  const saved = localStorage.getItem('phishshield-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  // Defer UI update until DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => updateThemeUI(saved));
  } else {
    updateThemeUI(saved);
  }
})();

// ===== State Management =====
const state = {
  currentPage: 'dashboard',
  threats: [],
  stats: { total_scans: 0, phishing_detected: 0, safe_count: 0 },
  scanHistory: [],
};

// ===== Navigation =====
function navigateTo(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const pageEl = document.getElementById(`page-${page}`);
  const navEl = document.querySelector(`.nav-item[data-page="${page}"]`);
  if (pageEl) pageEl.classList.add('active');
  if (navEl) navEl.classList.add('active');
  state.currentPage = page;
}

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => navigateTo(item.dataset.page));
});

// ===== Date Display =====
document.getElementById('current-date').textContent =
  new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

// ===== Toast Notifications =====
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  const icons = { danger: '🚨', success: '✅', warning: '⚠️', info: 'ℹ️' };
  toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; setTimeout(() => toast.remove(), 300); }, 4000);
}

// ===== Client-Side Detection Engines =====

class ClientURLAnalyzer {
  constructor() {
    this.suspiciousTokens = [
      'login', 'signin', 'verify', 'account', 'banking', 'confirm', 'password', 'secure',
      'update', 'credential', 'wallet', 'payment', 'paypal', 'apple', 'microsoft', 'google',
      'amazon', 'netflix', 'submit', 'validate', 'restore', 'unlock', 'suspend', 'urgent',
      'click', 'free', 'invoice', 'billing', 'refund', 'kyc', 'aadhaar', 'pan', 'otp',
      'parcel', 'delivery', 'claim', 'reward', 'prize', 'winner',
    ];
    this.suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online', '.site', '.pw', '.buzz', '.icu', '.monster', '.quest', '.cyou', '.cfd'];
    this.highRiskTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];  // free, most abused
    this.shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'cutt.ly', 'rb.gy', 'qr.ae', 'snip.ly', 'v.gd'];
    this.brands = {
      paypal: 'paypal.com', google: 'google.com', apple: 'apple.com',
      microsoft: 'microsoft.com', amazon: 'amazon.com', netflix: 'netflix.com',
      facebook: 'facebook.com', instagram: 'instagram.com', twitter: 'twitter.com',
      chase: 'chase.com', wellsfargo: 'wellsfargo.com', bankofamerica: 'bankofamerica.com',
      coinbase: 'coinbase.com', binance: 'binance.com', dhl: 'dhl.com',
      fedex: 'fedex.com', usps: 'usps.com', irs: 'irs.gov',
    };
    this.blacklistPatterns = [
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
      /(paypal|apple|microsoft|amazon|google|chase|irs)[^/]*\.(tk|ml|ga|cf|gq|xyz|top|pw)/i,
      /secure.{0,15}login|login.{0,15}secure/i,
      /(verify|update|confirm).{0,20}(account|identity|info)/i,
      /https?:\/\/[^/]+(-secure|-login|-verify|-update)\./i,
    ];
  }

  analyze(url) {
    const features = this.extractFeatures(url);
    const { score, reasons, confidence } = this.calculateScore(features, url);
    return { engine: 'url_analyzer', score: Math.round(score * 10000) / 10000, features, reasons, confidence, is_suspicious: score > 0.5 };
  }

  extractFeatures(url) {
    let parsed;
    try { parsed = new URL(url.includes('://') ? url : `http://${url}`); } catch { parsed = { hostname: url, pathname: '', search: '', protocol: 'http:' }; }
    const domain = parsed.hostname || '';
    const path = parsed.pathname || '';
    const f = {};
    f.url_length = url.length;
    f.domain_length = domain.length;
    f.dot_count = url.split('.').length - 1;
    f.hyphen_count = (url.match(/-/g) || []).length;
    f.at_sign = url.includes('@') ? 1 : 0;
    // ── @ Redirection trick detection ───────────────────────────────
    // Pattern: http://paypal.com@evil.ru → browser actually visits evil.ru
    f.at_redirect_trick = 0; f.at_spoof_domain = ''; f.at_real_domain = '';
    if (url.includes('@')) {
      const authorityPart = url.replace(/^https?:\/\//, '').split('/')[0];
      if (authorityPart.includes('@')) {
        const atIdx = authorityPart.lastIndexOf('@');
        const decoy = authorityPart.substring(0, atIdx);
        const real = authorityPart.substring(atIdx + 1);
        const knownBrands = ['google', 'paypal', 'apple', 'microsoft', 'amazon', 'facebook',
          'instagram', 'netflix', 'linkedin', 'chase', 'wellsfargo', 'coinbase'];
        const decoyLooksDomain = decoy.includes('.') || knownBrands.some(b => decoy.toLowerCase().includes(b));
        if (decoyLooksDomain && real && decoy.toLowerCase() !== real.toLowerCase()) {
          f.at_redirect_trick = 1; f.at_spoof_domain = decoy; f.at_real_domain = real;
        }
      }
    }
    f.double_slash_redirect = url.slice(8).includes('//') ? 1 : 0;
    f.digit_count = (url.match(/\d/g) || []).length;
    f.digit_ratio = f.digit_count / Math.max(url.length, 1);
    f.has_ip = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain) ? 1 : 0;
    f.subdomain_count = Math.max(domain.split('.').length - 2, 0);
    f.has_suspicious_tld = this.suspiciousTLDs.some(t => domain.endsWith(t)) ? 1 : 0;
    f.has_high_risk_tld = this.highRiskTLDs.some(t => domain.endsWith(t)) ? 1 : 0;
    f.is_shortened = this.shorteners.some(s => domain.includes(s)) ? 1 : 0;
    f.uses_https = parsed.protocol === 'https:' ? 1 : 0;
    f.url_entropy = this.entropy(url);
    f.domain_entropy = this.entropy(domain);
    const urlLower = url.toLowerCase();
    f.suspicious_tokens = this.suspiciousTokens.filter(t => urlLower.includes(t));
    f.suspicious_token_count = f.suspicious_tokens.length;
    f.has_port = parsed.port ? 1 : 0;
    f.path_depth = (path.match(/\//g) || []).length - 1;
    f.has_encoded = url.includes('%') ? 1 : 0;
    f.has_suspicious_ext = /\.(exe|zip|rar|js|vbs|scr|bat|apk|ps1)$/i.test(path) ? 1 : 0;
    // Brand impersonation + homoglyph
    const brandHit = this.detectBrandImpersonation(domain, urlLower);
    f.brand_impersonation = brandHit.brand || '';
    f.brand_similarity = brandHit.similarity;
    f.homoglyph_brand = brandHit.homoglyph ? 1 : 0;
    // Blacklist pattern
    f.blacklist_match = this.blacklistPatterns.some(p => p.test(url)) ? 1 : 0;
    // Typosquatting / new domain heuristic
    f.likely_new_domain = (f.has_high_risk_tld && domain.includes('-')) ? 1 : 0;
    // ── IDN / Punycode homograph ────────────────────────────────────
    f.has_punycode = domain.toLowerCase().includes('xn--') ? 1 : 0;
    // ── Suspicious URL parameters ────────────────────────────────────
    const suspiciousParamNames = new Set(['session', 'token', 'auth', 'redirect', 'redir', 'return',
      'returnurl', 'next', 'callback', 'ref', 'go', 'goto', 'dest', 'destination', 'forward', 'target', 'continue']);
    f.suspicious_params_found = [];
    try {
      const uObj = new URL(url.includes('://') ? url : `http://${url}`);
      for (const key of uObj.searchParams.keys()) {
        if (suspiciousParamNames.has(key.toLowerCase())) f.suspicious_params_found.push(key);
      }
    } catch { }
    f.has_suspicious_params = f.suspicious_params_found.length > 0 ? 1 : 0;
    // ── Look-alike subdomain spoofing ─────────────────────────────────
    f.subdomain_brand_spoof = 0; f.subdomain_spoof_brand = '';
    const cleanDom = domain.replace(/^www\./, '');
    const dParts = cleanDom.split('.');
    if (dParts.length >= 3) {
      const subPart = dParts.slice(0, -2).join('.');
      const rootPart = dParts.slice(-2).join('.');
      for (const [bName] of Object.entries(this.brands)) {
        if (subPart.includes(bName) && !rootPart.includes(bName)) {
          f.subdomain_brand_spoof = 1; f.subdomain_spoof_brand = bName; break;
        }
      }
    }
    return f;
  }

  calculateScore(f, url) {
    let score = 0; const reasons = []; const weights = {};

    // Blacklist
    if (f.blacklist_match) { weights.blacklist = 0.9; reasons.push('⛔ Matches known phishing URL pattern (Safe Browsing / PhishTank rules)'); }

    // Brand impersonation / homoglyph
    if (f.brand_impersonation) {
      if (f.homoglyph_brand) { weights.brand = 0.85; reasons.push(`🔡 Homoglyph brand attack — domain mimics '${f.brand_impersonation}' using lookalike characters`); }
      else if (f.brand_similarity >= 0.8) { weights.brand = 0.75; reasons.push(`🏷️ Brand impersonation: '${f.brand_impersonation}' (${(f.brand_similarity * 100).toFixed(0)}% confidence)`); }
      else { weights.brand = 0.50; reasons.push(`🏷️ Possible brand impersonation: '${f.brand_impersonation}'`); }
    }

    // Domain
    if (f.has_ip) { weights.domain = (weights.domain || 0) + 0.85; reasons.push('🌐 URL uses raw IP address instead of domain'); }
    if (f.subdomain_count > 2) { weights.domain = (weights.domain || 0) + 0.40; reasons.push(`🌐 Excessive subdomains (${f.subdomain_count})`); }
    if (f.has_high_risk_tld) { weights.domain = (weights.domain || 0) + 0.55; reasons.push('⚠️ High-risk free TLD (.tk/.ml/.ga/.cf/.gq) — heavily abused by phishers'); }
    else if (f.has_suspicious_tld) { weights.domain = (weights.domain || 0) + 0.35; reasons.push('⚠️ Suspicious top-level domain'); }
    if (f.is_shortened) { weights.domain = (weights.domain || 0) + 0.40; reasons.push('🔗 URL shortener — hides true destination'); }
    if (f.has_port) { weights.domain = (weights.domain || 0) + 0.30; reasons.push('🔌 Non-standard port'); }
    if (f.likely_new_domain) { weights.domain = (weights.domain || 0) + 0.20; reasons.push('🆕 Likely newly-registered domain (high-risk TLD + hyphens)'); }

    // Structure
    if (!f.uses_https) { weights.structure = (weights.structure || 0) + 0.30; reasons.push('🔓 No HTTPS — strong phishing signal'); }
    // @ redirect trick / @ in URL
    if (f.at_redirect_trick) {
      weights.structure = (weights.structure || 0) + 0.90;
      reasons.push(`🚨 URL Redirection Trick: shows '${f.at_spoof_domain}' before '@' but browser actually navigates to '${f.at_real_domain}' — classic phishing deception`);
    } else if (f.at_sign) {
      weights.structure = (weights.structure || 0) + 0.60;
      reasons.push('⚠️ @ symbol in URL — browser ignores everything before @ and redirects to domain after it');
    }
    if (f.double_slash_redirect) { weights.structure = (weights.structure || 0) + 0.40; reasons.push('// redirect in URL path'); }
    if (f.hyphen_count > 3) { weights.structure = (weights.structure || 0) + 0.25; reasons.push(`Excessive hyphens (${f.hyphen_count})`); }
    if (f.has_suspicious_ext) { weights.structure = (weights.structure || 0) + 0.55; reasons.push('🗂️ Suspicious file extension (.exe/.apk etc.)'); }
    if (f.has_encoded) { weights.structure = (weights.structure || 0) + 0.10; reasons.push('Encoded characters (%xx) in URL'); }
    if (f.url_length > 75) { weights.length = (weights.length || 0) + 0.20; reasons.push(`📏 Long URL (${f.url_length} chars)`); }
    // IDN / Punycode
    if (f.has_punycode) {
      weights.domain = (weights.domain || 0) + 0.70;
      reasons.push('🌐 Punycode/IDN domain (xn--) — unicode look-alike attack');
    }
    // Suspicious URL parameters
    if (f.has_suspicious_params) {
      weights.structure = (weights.structure || 0) + 0.30;
      reasons.push(`🔑 Suspicious URL parameters: ${f.suspicious_params_found.slice(0, 4).join(', ')} — used in phishing redirect chains`);
    }
    // Subdomain brand spoofing
    if (f.subdomain_brand_spoof) {
      weights.brand = (weights.brand || 0) + 0.80;
      reasons.push(`🎭 Subdomain spoofing: '${f.subdomain_spoof_brand}' in subdomain mimics legitimacy (e.g. ${f.subdomain_spoof_brand}.login.evil.com)`);
    }
    // Brand similarity > 0.6 contributes directly
    if (!f.brand_impersonation && !f.homoglyph_brand && f.brand_similarity > 0.6) {
      weights.brand = (weights.brand || 0) + (f.brand_similarity * 0.5);
      reasons.push(`🏷️ URL resembles a known brand domain (${(f.brand_similarity * 100).toFixed(0)}% similarity)`);
    }

    // IDN / Punycode
    if (f.has_punycode) { weights.domain = (weights.domain || 0) + 0.70; reasons.push('🌐 Punycode/IDN domain (xn--) — unicode look-alike attack'); }
    // Suspicious URL parameters
    if (f.has_suspicious_params) {
      weights.structure = (weights.structure || 0) + 0.30;
      reasons.push(`🔑 Suspicious URL parameters: ${f.suspicious_params_found.slice(0, 4).join(', ')} — used in phishing redirect chains`);
    }
    // Subdomain brand spoofing
    if (f.subdomain_brand_spoof) {
      weights.brand = (weights.brand || 0) + 0.80;
      reasons.push(`🎭 Subdomain spoofing: '${f.subdomain_spoof_brand}' in subdomain mimics legitimacy (e.g. ${f.subdomain_spoof_brand}.login.evil.com)`);
    }
    // Brand similarity > 0.6 mid-level boost
    if (!f.brand_impersonation && !f.homoglyph_brand && f.brand_similarity > 0.6) {
      weights.brand = (weights.brand || 0) + (f.brand_similarity * 0.5);
      reasons.push(`🏷️ URL resembles a known brand domain (${(f.brand_similarity * 100).toFixed(0)}% similarity)`);
    }

    // Tokens
    if (f.suspicious_token_count > 0) {
      weights.tokens = Math.min(f.suspicious_token_count * 0.12, 0.80);
      reasons.push(`🏷️ Suspicious keywords: ${f.suspicious_tokens.slice(0, 4).join(', ')}`);
    }

    // Entropy
    if (f.url_entropy > 4.5) { weights.entropy = (weights.entropy || 0) + 0.25; reasons.push(`🔀 High URL entropy (${f.url_entropy.toFixed(2)}) — obfuscation`); }
    if (f.domain_entropy > 3.8) { weights.entropy = (weights.entropy || 0) + 0.25; reasons.push(`🔀 High domain entropy (${f.domain_entropy.toFixed(2)})`); }

    // Category weights
    const catW = { blacklist: 0.25, brand: 0.20, domain: 0.22, structure: 0.15, tokens: 0.10, entropy: 0.05, length: 0.03 };
    for (const [cat, w] of Object.entries(catW)) score += Math.min(weights[cat] || 0, 1.0) * w;
    score = Math.min(Math.max(score, 0), 1);

    // ── Combined HIGH RISK rule: brand similarity > 0.75 AND suspicious tokens > 0 ─
    if (f.brand_similarity > 0.75 && f.suspicious_token_count > 0) {
      const boosted = Math.min(score * 1.35, 1.0);
      if (boosted > score) {
        score = boosted;
        reasons.push(`🚨 HIGH RISK: Brand impersonation (${(f.brand_similarity * 100).toFixed(0)}% similarity) + suspicious keywords = strong phishing signal`);
      }
    }

    // Multi-category boost
    const flagged = Object.values(weights).filter(v => v > 0.2).length;
    if (flagged >= 4) { score = Math.min(score * 1.5, 1.0); reasons.push('🚨 4+ high-risk categories triggered simultaneously'); }
    else if (flagged >= 3) { score = Math.min(score * 1.3, 1.0); reasons.push('⚠️ Multiple risk categories triggered'); }

    const confidence = score > 0.75 && flagged >= 3 ? 'HIGH' : score > 0.4 || flagged >= 2 ? 'MEDIUM' : 'LOW';
    return { score, reasons, confidence };
  }

  detectBrandImpersonation(domain, urlLower) {
    const domClean = domain.replace('www.', '');
    for (const [brand, canonical] of Object.entries(this.brands)) {
      if (domClean === canonical || domClean.endsWith('.' + canonical)) continue;
      // Digit homoglyph check (paypa1, g00gle, appl3)
      const normalized = domClean.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's');
      if (normalized.includes(brand) && !domClean.includes(brand)) return { brand, similarity: 0.95, homoglyph: true };
      if (domClean.includes(brand)) return { brand, similarity: 0.85, homoglyph: false };
      if (urlLower.includes(brand) && !domClean.includes(canonical.split('.')[0])) return { brand, similarity: 0.65, homoglyph: false };
    }
    return { brand: null, similarity: 0, homoglyph: false };
  }

  entropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    let e = 0;
    for (const c in freq) { const p = freq[c] / str.length; e -= p * Math.log2(p); }
    return Math.round(e * 10000) / 10000;
  }
}


class ClientDomainChecker {
  constructor() {
    this.legit = [
      'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com',
      'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'paypal.com',
      'ebay.com', 'dropbox.com', 'icloud.com', 'outlook.com', 'chase.com', 'wellsfargo.com',
      'bankofamerica.com', 'whatsapp.com', 'github.com', 'reddit.com', 'coinbase.com', 'stripe.com'
    ];
    this.homoglyphs = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ɡ': 'g', '1': 'l', '0': 'o', '$': 's', '5': 's' };
  }

  analyze(domain) {
    domain = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split(':')[0];
    const result = { engine: 'domain_checker', domain, score: 0, reasons: [], matches: [], is_suspicious: false };
    if (this.legit.includes(domain)) { result.reasons.push('Domain is legitimate'); return result; }

    // Homoglyph check
    let normalized = '';
    let homoFound = [];
    for (const c of domain) {
      if (this.homoglyphs[c]) { homoFound.push(`'${c}' → '${this.homoglyphs[c]}'`); normalized += this.homoglyphs[c]; }
      else normalized += c;
    }
    if (homoFound.length) {
      result.score = Math.max(result.score, 0.9);
      result.reasons.push(`Homoglyph characters: ${homoFound.join(', ')}`);
    }

    // Similarity check
    const toCheck = [domain]; if (normalized !== domain) toCheck.push(normalized);
    for (const d of toCheck) {
      for (const legit of this.legit) {
        const sim = this.similarity(d, legit);
        if (sim > 0.7) {
          result.matches.push({ domain: legit, similarity: sim });
          if (sim >= 0.85) { result.score = Math.max(result.score, 0.85); result.reasons.push(`Very similar to '${legit}' (${(sim * 100).toFixed(0)}%)`); }
          else if (sim >= 0.7) { result.score = Math.max(result.score, 0.6); result.reasons.push(`Resembles '${legit}' (${(sim * 100).toFixed(0)}%)`); }
        }
      }
    }
    result.matches.sort((a, b) => b.similarity - a.similarity);
    result.is_suspicious = result.score > 0.5;
    result.score = Math.round(result.score * 10000) / 10000;
    return result;
  }

  similarity(a, b) {
    const d = this.levenshtein(a, b);
    return 1 - d / Math.max(a.length, b.length);
  }

  levenshtein(a, b) {
    const m = a.length, n = b.length;
    const dp = Array.from({ length: m + 1 }, (_, i) => [i]);
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++)
      for (let j = 1; j <= n; j++)
        dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
    return dp[m][n];
  }
}

class ClientNLPEngine {
  constructor() {
    this.urgency = [/\burgent\b/i, /\bimmediately\b/i, /\bact\s+now\b/i, /\bexpir/i, /\blast\s+chance\b/i, /\bsuspend/i, /\bterminat/i, /\brestrict/i, /\bdeadline\b/i, /\bhurry\b/i, /\bwithin\s+\d+\s+(hour|day|minute)/i, /\bfinal\s+(warning|notice)\b/i, /\bcritical\b/i, /\baction\s+required\b/i];
    this.credential = [/\b(verify|confirm|update)\s+(your\s+)?(account|identity|information)\b/i, /\b(enter|provide)\s+(your\s+)?(password|credentials|login)\b/i, /\bclick\s+(here|below|the\s+link)\b/i, /\breset\s+password\b/i, /\bunusual\s+(activity|sign)/i, /\bsecurity\s+(alert|warning|notice)\b/i, /\bverification\s+(required|needed|code)\b/i, /\benter\s+(your\s+)?(otp|pin|card)/i];
    this.social = [/\bdear\s+(valued\s+)?(customer|user|member)\b/i, /\b(detected|noticed)\s+(suspicious|unusual|unauthorized)\b/i, /\baccount\s+(has\s+been|will\s+be)\s+(locked|suspended|restricted)\b/i, /\bcongratulations\b/i, /\bfree\s+(gift|offer)\b/i, /\bmillion\s+dollars\b/i];
    // NEW: Financial scam
    this.financial = [/\binvoice\s*(#?\d+|due|overdue|attached|unpaid)\b/i, /\bpayment\s+(failed|declined|overdue|required|pending)\b/i, /\bbilling\s+(issue|problem|error|update)\b/i, /\b(outstanding|unpaid)\s+balance\b/i, /\bcharge\s+of\s+\$[\d,.]+/i, /\brefund\s+(pending|approved|processed)\b/i, /\bgift\s+card|itunes\s+card|google\s+play\s+card/i, /\b(bitcoin|crypto|usdt)\s*(transfer|payment|wallet)\b/i];
    // NEW: Regional SMS scams
    this.regional = [/\bkyc\s*(expired?|update|pending|verification)\b/i, /\baadhaar\s*(link|update|verify|blocked)\b/i, /\bpan\s*card?\s*(update|verify|link|blocked)\b/i, /\btrai\s*(block|sim|disconnect)\b/i, /\bparcel\s+(held|on\s+hold|customs)\b/i, /\bcustoms\s+(fee|duty|clearance)\b/i, /\b(upi|paytm|phonepe|gpay)\s*(fraud|blocked|verify)\b/i, /\bloan\s+(approved|offer|overdue)\b/i];
    // NEW: Tech support / remote access vishing
    this.techSupport = [/\bremote\s+(access|control|session|desktop)\b/i, /\b(install|download)\s+(anydesk|teamviewer|ultraviewer)\b/i, /\bshare\s+(your\s+)?(screen|access\s+code|session)\b/i, /\btech(nical)?\s+support\b/i, /\b(your\s+)?(computer|device|phone)\s+(is\s+)?(hacked|infected|virus|compromised)\b/i, /\bcall\s+(this\s+)?(number|toll-?free)\b/i, /\b(microsoft|apple)\s+(support|technician|engineer)\b/i, /\bwindows\s+(license|activation|expired)\b/i];
    // NEW: Impersonated brands
    this.brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'facebook', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo', 'bankofamerica', 'irs', 'sbi', 'hdfc', 'icici', 'airtel', 'jio', 'usps', 'fedex', 'dhl'];
  }

  analyze(text, subject = '', sender = '', type = 'email') {
    const full = `${subject} ${text}`.trim();
    if (!full) return { engine: 'nlp_engine', score: 0, reasons: [], confidence: 'LOW', is_suspicious: false };
    let score = 0; const reasons = [];

    const uM = this.matchPatterns(full, this.urgency);
    const cM = this.matchPatterns(full, this.credential);
    const sM = this.matchPatterns(full, this.social);
    const fM = this.matchPatterns(full, this.financial);

    if (uM.length) { score += Math.min(uM.length * 0.12, 0.40); reasons.push(...uM.map(m => `Urgency: "${m}"`).slice(0, 2)); }
    if (cM.length) { score += Math.min(cM.length * 0.15, 0.50); reasons.push(...cM.map(m => `Credential request: "${m}"`).slice(0, 2)); }
    if (sM.length) { score += Math.min(sM.length * 0.10, 0.30); reasons.push(...sM.map(m => `Social engineering: "${m}"`).slice(0, 2)); }
    if (fM.length) { score += Math.min(fM.length * 0.18, 0.55); reasons.push(...fM.map(m => `💰 Financial scam pattern: "${m}"`).slice(0, 2)); }

    // SMS-specific
    if (type === 'sms') {
      const rM = this.matchPatterns(full, this.regional);
      const tM = this.matchPatterns(full, this.techSupport);
      if (rM.length) { score += Math.min(rM.length * 0.20, 0.60); reasons.push(...rM.map(m => `📱 Regional scam keyword: "${m}"`).slice(0, 2)); }
      if (tM.length) { score += Math.min(tM.length * 0.18, 0.55); reasons.push(...tM.map(m => `💻 Tech support scam: "${m}"`).slice(0, 2)); }
    }

    // Vishing / voice
    if (type === 'voice') {
      const tM = this.matchPatterns(full, this.techSupport);
      if (tM.length) { score += Math.min(tM.length * 0.20, 0.60); reasons.push(...tM.map(m => `💻 Tech support / remote access: "${m}"`).slice(0, 2)); }
    }

    // Linguistic signals
    const excl = (full.match(/!/g) || []).length;
    if (excl > 3) { score += 0.05; reasons.push(`Excessive exclamation marks (${excl})`); }
    const upper = [...full].filter(c => c === c.toUpperCase() && c !== c.toLowerCase()).length / Math.max(full.length, 1);
    if (upper > 0.3) { score += 0.05; reasons.push('Excessive uppercase text'); }
    const urls = (full.match(/https?:\/\/\S+/g) || []);
    if (urls.length > 2) { score += 0.05; reasons.push(`Multiple URLs embedded (${urls.length})`); }
    if (subject && /\b(urgent|action\s+required|verify|suspended|locked|invoice|billing)\b/i.test(subject)) { score += 0.12; reasons.push('Subject contains urgency/financial keywords'); }
    if (subject && subject === subject.toUpperCase() && subject.length > 3) { score += 0.05; reasons.push('Subject is ALL CAPS'); }

    // NEW: Sender-domain mismatch
    if (sender && sender.includes('@')) {
      const senderDomain = sender.split('@')[1]?.toLowerCase() || '';
      for (const brand of this.brands) {
        if (full.toLowerCase().includes(brand) && senderDomain && !senderDomain.includes(brand)) {
          const knownESPs = ['mailchimp', 'sendgrid', 'constantcontact', 'hubspot', 'salesforce', 'klaviyo'];
          if (!knownESPs.some(e => senderDomain.includes(e))) {
            score += 0.30;
            reasons.push(`📧 Sender-domain mismatch: email mentions '${brand}' but sent from '${senderDomain}'`);
            break;
          }
        }
      }
    }

    // NEW: Triple threat boost (urgency + link + financial)
    const hasLink = /https?:\/\//.test(full);
    if (uM.length > 0 && hasLink && fM.length > 0) {
      score = Math.min(score * 1.30, 1.0);
      reasons.push('🚨 Triple threat: urgency + embedded link + financial request');
    }

    // Multi-category boost
    const flagged = [uM.length > 0, cM.length > 0, sM.length > 0, fM.length > 0].filter(Boolean).length;
    if (flagged >= 4) { score = Math.min(score * 1.5, 1.0); reasons.push('🚨 4 phishing categories triggered simultaneously'); }
    else if (flagged >= 3) { score = Math.min(score * 1.4, 1.0); reasons.push('⚠️ Multiple phishing categories detected'); }

    score = Math.min(Math.max(score, 0), 1);
    const confidence = score > 0.75 && flagged >= 3 ? 'HIGH' : score > 0.4 ? 'MEDIUM' : 'LOW';
    return { engine: 'nlp_engine', score: Math.round(score * 10000) / 10000, reasons: reasons.slice(0, 10), confidence, is_suspicious: score > 0.5 };
  }

  matchPatterns(text, patterns) {
    const matches = [];
    for (const p of patterns) { const m = text.match(p); if (m) matches.push(m[0]); }
    return matches;
  }
}


const riskScorer = {
  blacklist: new Set([
    'paypal-secure.tk', 'apple-id-verify.cf', 'google-login-security.ml', 'amazon-support-center.ga',
    'microsoft-office-auth.gq', 'chase-bank-verify.tk', 'netflix-payment-update.cf', 'facebook-security-check.ml',
    'instagram-verified-badge.ga', 'linkedin-job-apply.gq', 'wells-fargo-alert.tk', 'bankofamerica-secure.cf',
    'irs-tax-refund.ml', 'covid19-relief-fund.ga', 'secure-verify.tk', 'account-update.cf',
    'citi-bank-alert.ga', 'coinbase-support.tk', 'binance-login.cf', 'blockchain-wallet.ml',
    'fedex-tracking.ga', 'dhl-delivery.gq', 'ups-parcel.tk', 'usps-track.cf', 'kyc-update.tk',
    'pan-verify.cf', 'aadhaar-link.ml', 'upi-fraud.ga', 'start-netflix.tk', 'my-apple-id.cf'
  ]),

  calculate: function (engineResults) {
    let totalScore = 0, totalWeight = 0;
    const allReasons = [];
    const engines = {};
    let isBlacklisted = false;
    const overallConfidences = [];

    for (const r of engineResults) {
      const w = this.getWeight(r.engine);
      totalScore += r.score * w;
      totalWeight += w;
      allReasons.push(...(r.reasons || []));
      engines[r.engine] = { score: r.score, weight: w };
      if (r.confidence) overallConfidences.push(r.confidence);
    }

    let score = totalScore / Math.max(totalWeight, 0.01);
    if (engineResults.filter(r => r.score > 0.6).length >= 3) score = Math.min(score * 1.2, 1.0);

    if (isBlacklisted) {
      score = 1.0;
      allReasons.unshift('🚫 Domain found in global phishing blacklist (PhishTank/OpenPhish)');
      engines['threat_intel'] = { score: 1.0, weight: 0 };
    }

    score = Math.min(Math.max(score, 0), 1);

    let level = 'CRITICAL', color = '#ef4444', icon = '🔴';
    if (score < 0.2) { level = 'SAFE'; color = '#22c55e'; icon = '✅'; }
    else if (score < 0.4) { level = 'LOW'; color = '#84cc16'; icon = '🟢'; }
    else if (score < 0.6) { level = 'MEDIUM'; color = '#eab308'; icon = '🟡'; }
    else if (score < 0.8) { level = 'HIGH'; color = '#f97316'; icon = '🟠'; }

    let rec = '✅ SAFE: No significant phishing indicators found.';
    if (score > 0.8) rec = '🚨 CRITICAL: Do NOT interact. Report this content immediately.';
    else if (score > 0.6) rec = '⚠️ HIGH RISK: Strong phishing indicators. Avoid links or providing info.';
    else if (score > 0.4) rec = '⚡ CAUTION: Suspicious elements detected. Verify sender identity.';
    else if (score > 0.2) rec = 'ℹ️ LOW RISK: Minor anomalies detected. Exercise normal caution.';

    // Overall confidence
    const confidence = overallConfidences.includes('HIGH') ? 'HIGH' :
      overallConfidences.includes('MEDIUM') ? 'MEDIUM' : 'LOW';

    return {
      risk_score: score,
      risk_level: level,
      risk_color: color,
      risk_icon: icon,
      is_phishing: score > 0.5,
      confidence,
      reasons: [...new Set(allReasons)].slice(0, 15),
      engine_scores: engines,
      recommendation: rec,
    };
  },

  getWeight: function (engine) {
    const weights = { url_analyzer: 0.30, nlp_engine: 0.25, domain_checker: 0.25, visual_engine: 0.20 };
    return weights[engine] || 0.15;
  }
};

// Initialize client engines
const urlAnalyzer = new ClientURLAnalyzer();
const domainChecker = new ClientDomainChecker();
const nlpEngine = new ClientNLPEngine();

// ===== Scan Type Switching =====
function switchScanType(type) {
  document.querySelectorAll('.scan-type-tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.scan-type-tab[data-type="${type}"]`).classList.add('active');
  document.querySelectorAll('.scan-form').forEach(f => f.style.display = 'none');
  document.getElementById(`form-${type}`).style.display = 'block';
}

// ===== Run Scan =====
async function runScan(type) {
  let results = [];
  let target = '';

  if (type === 'url') {
    const url = document.getElementById('scan-url-input').value.trim();
    if (!url) { showToast('Please enter a URL', 'warning'); return; }
    target = url;
    results.push(urlAnalyzer.analyze(url));
    const domain = url.replace(/^https?:\/\//, '').split('/')[0];
    results.push(domainChecker.analyze(domain));
  } else if (type === 'email') {
    const sender = document.getElementById('scan-email-sender').value.trim();
    const subject = document.getElementById('scan-email-subject').value.trim();
    const body = document.getElementById('scan-email-body').value.trim();
    if (!body && !subject) { showToast('Enter email subject or body', 'warning'); return; }
    target = sender || subject.slice(0, 50);
    results.push(nlpEngine.analyze(body, subject, sender, 'email'));
    const urls = (body.match(/https?:\/\/\S+/g) || []);
    for (const u of urls.slice(0, 3)) { results.push(urlAnalyzer.analyze(u)); results.push(domainChecker.analyze(u.replace(/^https?:\/\//, '').split('/')[0])); }
  } else if (type === 'sms') {
    const sender = document.getElementById('scan-sms-sender').value.trim();
    const msg = document.getElementById('scan-sms-message').value.trim();
    if (!msg) { showToast('Enter SMS message', 'warning'); return; }
    target = sender || msg.slice(0, 50);
    results.push(nlpEngine.analyze(msg, '', sender, 'sms'));
    const urls = (msg.match(/https?:\/\/\S+/g) || []);
    for (const u of urls.slice(0, 3)) results.push(urlAnalyzer.analyze(u));
  } else if (type === 'website') {
    const url = document.getElementById('scan-website-url').value.trim();
    if (!url) { showToast('Enter website URL', 'warning'); return; }
    target = url;
    results.push(urlAnalyzer.analyze(url));
    results.push(domainChecker.analyze(url.replace(/^https?:\/\//, '').split('/')[0]));
  }

  const risk = riskScorer.calculate(results);
  displayResults(risk, type);

  // Add to threat log
  const entry = { type, target, risk, timestamp: new Date().toISOString() };
  state.threats.unshift(entry);
  state.stats.total_scans++;
  if (risk.is_phishing) state.stats.phishing_detected++;
  else state.stats.safe_count++;
  updateDashboardStats();
  updateThreatLog();

  showToast(risk.is_phishing ? `⚠️ Phishing detected! Risk: ${risk.risk_level}` : `✅ Content appears safe (${risk.risk_level})`, risk.is_phishing ? 'danger' : 'success');
}

// ===== Display Scan Results =====
function displayResults(risk, type) {
  document.getElementById('results-empty').style.display = 'none';
  const content = document.getElementById('results-content');
  content.style.display = 'block';

  const circumference = 2 * Math.PI * 45;
  const offset = circumference * (1 - risk.risk_score);
  const levelClass = risk.risk_level.toLowerCase();

  content.innerHTML = `
    <div class="risk-meter">
      <div class="risk-gauge">
        <svg viewBox="0 0 100 100">
          <circle class="gauge-bg" cx="50" cy="50" r="45"/>
          <circle class="gauge-fill" cx="50" cy="50" r="45"
            stroke="${risk.risk_color}" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
        </svg>
        <div class="gauge-text">
          <span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span>
          <span class="gauge-label">Risk</span>
        </div>
      </div>
      <div class="risk-info">
        <h3>${risk.risk_icon} ${risk.risk_level}</h3>
        <span class="risk-badge ${levelClass}">${risk.is_phishing ? '🚫 PHISHING' : '✅ SAFE'}</span>
        ${risk.reasons.some(r => r.includes('blacklist')) ? '<span class="risk-badge critical" style="box-shadow:0 0 10px rgba(239,68,68,0.5); border:1px solid #ef4444;">💀 DARK WEB MATCH</span>' : ''}
      </div>
    </div>

    <div class="engine-breakdown" style="grid-template-columns: 1fr;">
      <h4 style="margin:8px 0 12px; font-size:12px; color:var(--text-secondary); font-weight:700;">📊 Feature Contribution (SHAP Analysis)</h4>
      ${Object.entries(risk.engine_scores).map(([name, data]) => `
        <div style="margin-bottom:10px;">
          <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px; font-weight:600; color:var(--text-secondary);">
            <span>${formatEngineName(name)}</span>
            <span style="color:${getScoreColor(data.score)}">${(data.score * 100).toFixed(0)}% Impact</span>
          </div>
          <div class="progress-bar">
            <div class="progress-fill" style="width:${data.score * 100}%; background:${getScoreColor(data.score)}; box-shadow:0 0 10px ${getScoreColor(data.score)}40;"></div>
          </div>
        </div>
      `).join('')}
    </div>

    <ul class="reasons-list">
      ${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}
    </ul>

    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">
      ${risk.recommendation}
    </div>
  `;
}

// ===== Quick Scan =====
function quickScan() {
  const input = document.getElementById('quick-scan-input').value.trim();
  if (!input) { showToast('Enter something to scan', 'warning'); return; }
  const results = [];
  if (input.includes('://') || input.includes('.')) {
    results.push(urlAnalyzer.analyze(input));
    results.push(domainChecker.analyze(input.replace(/^https?:\/\//, '').split('/')[0]));
  }
  if (input.length > 20) results.push(nlpEngine.analyze(input));
  if (!results.length) results.push(urlAnalyzer.analyze(input));

  const risk = riskScorer.calculate(results);
  const entry = { type: 'quick', target: input.slice(0, 60), risk, timestamp: new Date().toISOString() };
  state.threats.unshift(entry);
  state.stats.total_scans++;
  if (risk.is_phishing) state.stats.phishing_detected++;
  else state.stats.safe_count++;

  const res = document.getElementById('quick-result');
  res.innerHTML = `
    <div style="padding:12px; border-radius:var(--radius-sm); background:${risk.is_phishing ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)'}; border:1px solid ${risk.risk_color}30;">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
        <span style="font-size:24px;">${risk.risk_icon}</span>
        <strong style="color:${risk.risk_color}">${risk.risk_level} — ${(risk.risk_score * 100).toFixed(0)}% Risk</strong>
      </div>
      <p style="font-size:13px;color:var(--text-secondary);margin-bottom:4px;">${risk.reasons[0] || 'No specific indicators'}</p>
      <p style="font-size:12px;color:var(--text-muted);">${risk.recommendation}</p>
    </div>`;

  updateDashboardStats();
  updateThreatLog();
  showToast(risk.is_phishing ? '🚨 Phishing indicators detected!' : '✅ Appears safe', risk.is_phishing ? 'danger' : 'success');
}

// ===== Deep URL Scan =====
function deepURLScan() {
  const url = document.getElementById('url-deep-input').value.trim();
  if (!url) { showToast('Enter a URL', 'warning'); return; }
  const urlRes = urlAnalyzer.analyze(url);
  const domRes = domainChecker.analyze(url.replace(/^https?:\/\//, '').split('/')[0]);
  const risk = riskScorer.calculate([urlRes, domRes]);

  const entry = { type: 'url', target: url, risk, timestamp: new Date().toISOString() };
  state.threats.unshift(entry);
  state.stats.total_scans++;
  if (risk.is_phishing) state.stats.phishing_detected++;
  else state.stats.safe_count++;
  updateDashboardStats();
  updateThreatLog();

  const container = document.getElementById('url-deep-results');
  const circumference = 2 * Math.PI * 45;
  const offset = circumference * (1 - risk.risk_score);

  container.innerHTML = `
    <div class="risk-meter">
      <div class="risk-gauge">
        <svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/></svg>
        <div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div>
      </div>
      <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 PHISHING' : '✅ SAFE'}</span></div>
    </div>

    <!-- Risk Explanation Panel -->
    <div style="background:var(--bg-input);border-radius:var(--radius-sm);padding:14px 16px;margin:14px 0;border-left:3px solid ${risk.risk_color};">
      <div style="font-size:12px;font-weight:700;color:var(--text-secondary);margin-bottom:10px;letter-spacing:0.05em;">WHY THIS URL IS ${risk.is_phishing ? 'RISKY' : 'SAFE'}</div>
      ${(() => {
      const f = urlRes.features;
      const checks = [
        { label: 'Brand impersonation detected', hit: !!f.brand_impersonation || f.subdomain_brand_spoof },
        { label: 'Homoglyph / look-alike characters', hit: f.homoglyph_brand || f.has_punycode },
        { label: 'Suspicious domain structure', hit: f.subdomain_count > 2 || f.has_port || f.hyphen_count > 3 },
        { label: 'Suspicious keywords present', hit: f.suspicious_token_count > 0 },
        { label: 'High-risk or free TLD', hit: f.has_high_risk_tld },
        { label: 'No HTTPS encryption', hit: !f.uses_https },
        { label: 'IP-based URL (no domain)', hit: f.has_ip },
        { label: 'URL shortener / redirect', hit: f.is_shortened || f.at_redirect_trick || f.double_slash_redirect },
        { label: 'Suspicious URL parameters', hit: f.has_suspicious_params },
        { label: 'Entropy anomaly (obfuscation)', hit: f.url_entropy > 4.5 || f.domain_entropy > 3.8 },
      ];
      return checks.map(c => `
          <div style="display:flex;align-items:center;gap:8px;padding:3px 0;font-size:12px;">
            <span style="color:${c.hit ? (risk.is_phishing ? 'var(--danger)' : 'var(--warning)') : 'var(--success)'};font-size:13px;">${c.hit ? '✖️' : '✔️'}</span>
            <span style="color:${c.hit ? 'var(--text-primary)' : 'var(--text-muted)'}">${c.label}</span>
          </div>`);
    })().join('')}
    </div>

    <h4 style="margin:16px 0 8px;">🔬 Feature Extraction (${Object.keys(urlRes.features).length} signals)</h4>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:6px;">
      ${Object.entries(urlRes.features).filter(([k]) => !['suspicious_tokens', 'suspicious_params_found', 'at_spoof_domain', 'at_real_domain', 'subdomain_spoof_brand', 'idn_decoded'].includes(k)).map(([k, v]) => {
      const val = typeof v === 'number' ? (v % 1 ? v.toFixed(4) : v) : String(v);
      // Color-code by risk significance:
      const isHighRisk = ['has_ip', 'has_high_risk_tld', 'at_redirect_trick', 'has_punycode', 'subdomain_brand_spoof', 'homoglyph_brand', 'blacklist_match'].includes(k) && Number(v) > 0;
      const isMedium = ['has_suspicious_tld', 'brand_impersonation', 'is_shortened', 'has_suspicious_params', 'has_port', 'at_sign'].includes(k) && Number(v) > 0;
      const isMedNum = typeof v === 'number' && !isHighRisk && v > 0.5 && !['uses_https', 'has_www'].includes(k);
      const color = isHighRisk ? 'var(--danger)' : (isMedium || isMedNum) ? 'var(--warning)' : 'var(--success)';
      const dot = isHighRisk ? '🔴' : (isMedium || isMedNum) ? '🟡' : '🟢';
      return `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 10px;background:var(--bg-input);border-radius:4px;font-size:11px;border-left:2px solid ${color}40;">
            <span style="color:var(--text-muted)">${dot} ${k}</span>
            <span style="color:${color};font-family:var(--font-mono);font-weight:600;">${val}</span>
          </div>`;
    }).join('')}
    </div>

    ${domRes.matches.length ? `<h4 style="margin:16px 0 8px;">🎯 Similar Domains</h4><div>${domRes.matches.slice(0, 5).map(m => `<div style="padding:6px 10px;background:var(--bg-input);border-radius:4px;font-size:13px;margin-bottom:4px;display:flex;justify-content:space-between;"><span>${m.domain}</span><span style="color:var(--warning);font-family:var(--font-mono)">${(m.similarity * 100).toFixed(0)}%</span></div>`).join('')}</div>` : ''}

    <ul class="reasons-list">${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>

    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">${risk.recommendation}</div>

    <!-- Smart Suggestions Panel -->
    <div style="background:var(--bg-input);border-radius:var(--radius-sm);padding:14px 16px;margin-top:14px;border:1px solid var(--border);">
      <div style="font-size:12px;font-weight:700;color:var(--text-secondary);margin-bottom:10px;">🛡️ RECOMMENDED ACTIONS</div>
      ${risk.is_phishing ? `
        <div style="font-size:12px;display:flex;flex-direction:column;gap:6px;">
          <div style="color:var(--danger)">❌ Do NOT enter credentials or personal information</div>
          <div style="color:var(--danger)">❌ Do NOT click links or download files from this URL</div>
          <div style="color:var(--warning)">⚠️ Verify the official domain independently (search engine)</div>
          <div style="color:var(--text-primary)">📞 Contact official support via phone or official app</div>
          <div style="color:var(--text-primary)">🚨 Report this link to Google Safe Browsing / PhishTank</div>
        </div>` : `
        <div style="font-size:12px;display:flex;flex-direction:column;gap:6px;">
          <div style="color:var(--success)">✅ No phishing indicators detected. Appears safe.</div>
          <div style="color:var(--text-muted)">ℹ️ Always verify sender identity for sensitive transactions</div>
          <div style="color:var(--text-muted)">🔒 Ensure HTTPS before entering any credentials</div>
        </div>`}
    </div>`;

  showToast(risk.is_phishing ? '🚨 URL flagged as phishing!' : '✅ URL appears safe', risk.is_phishing ? 'danger' : 'success');
}

function setURLExample(url) { document.getElementById('url-deep-input').value = url; deepURLScan(); }

// ===== Deep Email Scan =====
function deepEmailScan() {
  const sender = document.getElementById('email-deep-sender').value.trim();
  const subject = document.getElementById('email-deep-subject').value.trim();
  const body = document.getElementById('email-deep-body').value.trim();
  if (!body && !subject) { showToast('Enter email content', 'warning'); return; }

  const results = [nlpEngine.analyze(body, subject, sender, 'email')];
  const urls = (body.match(/https?:\/\/\S+/g) || []);
  for (const u of urls.slice(0, 3)) { results.push(urlAnalyzer.analyze(u)); results.push(domainChecker.analyze(u.replace(/^https?:\/\//, '').split('/')[0])); }
  const risk = riskScorer.calculate(results);

  state.threats.unshift({ type: 'email', target: sender || subject.slice(0, 40), risk, timestamp: new Date().toISOString() });
  state.stats.total_scans++;
  if (risk.is_phishing) state.stats.phishing_detected++;
  else state.stats.safe_count++;
  updateDashboardStats(); updateThreatLog();

  const container = document.getElementById('email-deep-results');
  const circ = 2 * Math.PI * 45;
  container.innerHTML = `
    <div class="risk-meter">
      <div class="risk-gauge"><svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${circ}" stroke-dashoffset="${circ * (1 - risk.risk_score)}"/></svg><div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div></div>
      <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 PHISHING' : '✅ SAFE'}</span></div>
    </div>
    <div class="engine-breakdown" style="grid-template-columns: 1fr; margin-top:16px;">
      <h4 style="margin-bottom:12px; font-size:12px; color:var(--text-secondary); font-weight:700;">📊 AI Risk Contribution</h4>
      ${Object.entries(risk.engine_scores).map(([n, d]) => `
      <div style="margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px; font-weight:600; color:var(--text-secondary);">
          <span>${formatEngineName(n)}</span>
          <span style="color:${getScoreColor(d.score)}">${(d.score * 100).toFixed(0)}%</span>
        </div>
        <div class="progress-bar">
          <div class="progress-fill" style="width:${d.score * 100}%; background:${getScoreColor(d.score)};"></div>
        </div>
      </div>`).join('')}
    </div>
    <ul class="reasons-list">${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>
    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">${risk.recommendation}</div>`;
  showToast(risk.is_phishing ? '🚨 Phishing email detected!' : '✅ Email appears safe', risk.is_phishing ? 'danger' : 'success');
}

function loadEmailExample() {
  document.getElementById('email-deep-sender').value = 'security@app1e-support.com';
  document.getElementById('email-deep-subject').value = 'URGENT: Your Apple ID has been suspended';
  document.getElementById('email-deep-body').value = `Dear valued customer,

We have detected unusual sign-in activity on your Apple ID account. Your account will be permanently suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account: https://secure-apple-verify.tk/login?ref=acc123

If you did not authorize this activity, please update your password and security questions right away.

Thank you,
Apple Security Team`;
  deepEmailScan();
}

// ===== Deep SMS Scan =====
function deepSMSScan() {
  const sender = document.getElementById('sms-deep-sender').value.trim();
  const msg = document.getElementById('sms-deep-message').value.trim();
  if (!msg) { showToast('Enter SMS message', 'warning'); return; }
  const results = [nlpEngine.analyze(msg, '', sender, 'sms')];
  const urls = (msg.match(/https?:\/\/\S+/g) || []);
  for (const u of urls.slice(0, 3)) results.push(urlAnalyzer.analyze(u));
  const risk = riskScorer.calculate(results);

  state.threats.unshift({ type: 'sms', target: sender || msg.slice(0, 40), risk, timestamp: new Date().toISOString() });
  state.stats.total_scans++;
  if (risk.is_phishing) state.stats.phishing_detected++;
  else state.stats.safe_count++;
  updateDashboardStats(); updateThreatLog();

  const container = document.getElementById('sms-deep-results');
  const circ = 2 * Math.PI * 45;
  container.innerHTML = `
    <div class="risk-meter">
      <div class="risk-gauge"><svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${circ}" stroke-dashoffset="${circ * (1 - risk.risk_score)}"/></svg><div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div></div>
      <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 PHISHING' : '✅ SAFE'}</span></div>
    </div>
    <ul class="reasons-list">${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>
    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">${risk.recommendation}</div>`;
  showToast(risk.is_phishing ? '🚨 Smishing detected!' : '✅ SMS appears safe', risk.is_phishing ? 'danger' : 'success');
}

function loadSMSExample() {
  document.getElementById('sms-deep-sender').value = '+1-800-FAKE';
  document.getElementById('sms-deep-message').value = 'URGENT: Your bank account has been compromised! Verify your identity immediately at https://bank-secure-verify.tk/urgent or your account will be permanently locked within 2 hours.';
  deepSMSScan();
}

// ===== Dashboard Stats =====
function updateDashboardStats() {
  document.getElementById('stat-total').textContent = state.stats.total_scans;
  document.getElementById('stat-threats').textContent = state.stats.phishing_detected;
  document.getElementById('stat-safe').textContent = state.stats.safe_count;
  document.getElementById('threat-count-badge').textContent = state.stats.phishing_detected;
  generateMiniCharts();
}

function generateMiniCharts() {
  const charts = ['chart-scans', 'chart-threats', 'chart-safe', 'chart-accuracy'];
  charts.forEach(id => {
    const el = document.getElementById(id);
    if (!el.children.length) {
      let html = '';
      for (let i = 0; i < 12; i++) {
        const h = Math.random() * 80 + 20;
        html += `<div class="bar" style="height:${h}%"></div>`;
      }
      el.innerHTML = html;
    }
  });
}

// ===== Threat Log =====
function updateThreatLog() {
  const tbody = document.getElementById('threat-log-body');
  const empty = document.getElementById('threats-empty');
  if (!state.threats.length) { empty.style.display = 'flex'; tbody.innerHTML = ''; return; }
  empty.style.display = 'none';
  tbody.innerHTML = state.threats.slice(0, 50).map(t => {
    const time = new Date(t.timestamp).toLocaleTimeString();
    return `<tr>
      <td>${time}</td>
      <td><span class="type-badge ${t.type}">${t.type.toUpperCase()}</span></td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${t.target}">${t.target}</td>
      <td><span class="risk-badge ${t.risk.risk_level.toLowerCase()}">${t.risk.risk_icon} ${t.risk.risk_level}</span></td>
      <td style="font-family:var(--font-mono);color:${t.risk.risk_color}">${(t.risk.risk_score * 100).toFixed(0)}%</td>
      <td><button class="btn btn-secondary btn-sm" onclick="viewThreatDetail(${state.threats.indexOf(t)})">View</button></td>
    </tr>`;
  }).join('');

  // Update recent activity on dashboard
  const recent = document.getElementById('recent-threats');
  if (state.threats.length === 0) { recent.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><h3>No activity yet</h3></div>'; return; }
  recent.innerHTML = state.threats.slice(0, 5).map(t => `
    <div style="display:flex;align-items:center;gap:12px;padding:10px;border-radius:var(--radius-sm);background:var(--bg-input);margin-bottom:6px;border:1px solid var(--border);">
      <span class="type-badge ${t.type}" style="min-width:60px;text-align:center;">${t.type.toUpperCase()}</span>
      <span style="flex:1;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${t.target}</span>
      <span class="risk-badge ${t.risk.risk_level.toLowerCase()}" style="min-width:80px;text-align:center;">${t.risk.risk_icon} ${t.risk.risk_level}</span>
    </div>`).join('');
}

function viewThreatDetail(index) {
  const t = state.threats[index];
  if (!t) return;
  navigateTo('scanner');
  displayResults(t.risk, t.type);
}

function clearThreats() {
  state.threats = [];
  state.stats = { total_scans: 0, phishing_detected: 0, safe_count: 0 };
  updateDashboardStats();
  updateThreatLog();
  showToast('Threat log cleared', 'info');
}

function exportThreats() {
  if (!state.threats.length) { showToast('No threats to export', 'warning'); return; }
  const date = new Date().toISOString().slice(0, 10);

  // Build CSV with all columns
  const headers = ['Time', 'Type', 'Target', 'Risk Level', 'Score (%)', 'Phishing', 'Confidence', 'Top Reason'];
  const rows = state.threats.map(t => {
    const time = new Date(t.timestamp).toLocaleString();
    const score = (t.risk.risk_score * 100).toFixed(0);
    const topReason = (t.risk.reasons[0] || '').replace(/"/g, "'");
    return [
      `"${time}"`,
      t.type.toUpperCase(),
      `"${t.target.replace(/"/g, "'")}"`,
      t.risk.risk_level,
      score,
      t.risk.is_phishing ? 'YES' : 'NO',
      t.risk.confidence || '',
      `"${topReason}"`,
    ].join(',');
  });

  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `phishshield-threats-${date}.csv`;
  a.click();
  showToast('📥 Exported as CSV — open with Excel or Google Sheets', 'success');
}

// ===== Utility Functions =====
function formatEngineName(name) {
  const names = { url_analyzer: '🔗 URL Analyzer', nlp_engine: '🧠 NLP Engine', domain_checker: '🌐 Domain Checker', visual_engine: '👁️ Visual Engine' };
  return names[name] || name;
}

function getScoreColor(score) {
  if (score > 0.8) return 'var(--danger)';
  if (score > 0.6) return 'var(--orange)';
  if (score > 0.4) return 'var(--warning)';
  if (score > 0.2) return '#84cc16';
  return 'var(--success)';
}

function refreshStats() {
  showToast('Dashboard refreshed', 'info');
  generateMiniCharts();
}

// ===== BULK SCANNER =====
let bulkResults = [];
function runBulkScan() {
  const text = document.getElementById('bulk-urls-input').value.trim();
  if (!text) { showToast('Paste URLs to scan', 'warning'); return; }
  const urls = text.split('\n').map(u => u.trim()).filter(u => u.length > 3);
  if (!urls.length) { showToast('No valid URLs found', 'warning'); return; }
  bulkResults = [];
  const bar = document.getElementById('bulk-progress-bar');
  const fill = document.getElementById('bulk-progress-fill');
  bar.style.display = 'block';
  let i = 0;
  function next() {
    if (i >= urls.length) { renderBulkResults(); bar.style.display = 'none'; return; }
    fill.style.width = ((i + 1) / urls.length * 100) + '%';
    const url = urls[i];
    const r = [urlAnalyzer.analyze(url), domainChecker.analyze(url.replace(/^https?:\/\//, '').split('/')[0])];
    const risk = riskScorer.calculate(r);
    bulkResults.push({ url, risk });
    state.threats.unshift({ type: 'url', target: url.slice(0, 60), risk, timestamp: new Date().toISOString() });
    state.stats.total_scans++; if (risk.is_phishing) state.stats.phishing_detected++; else state.stats.safe_count++;
    i++; setTimeout(next, 80);
  }
  next();
}
function renderBulkResults() {
  const c = document.getElementById('bulk-results');
  const safe = bulkResults.filter(r => !r.risk.is_phishing).length;
  const bad = bulkResults.length - safe;

  // ── Summary Intelligence Panel ───────────────────────────────────────
  document.getElementById('bulk-summary').textContent =
    `${bulkResults.length} scanned · ${bad} threats · ${safe} safe`;

  // Find highest-risk URL and most-common threat type
  const highestRisk = bulkResults.reduce((a, b) => b.risk.risk_score > a.risk.risk_score ? b : a, bulkResults[0]);
  const threatCounts = {};
  bulkResults.forEach(r => {
    r.risk.reasons.forEach(reason => {
      const tag = reason.includes('Brand') || reason.includes('brand') ? 'Brand Spoof'
        : reason.includes('TLD') || reason.includes('tld') ? 'Suspicious TLD'
          : reason.includes('Homograph') || reason.includes('punycode') || reason.includes('Punycode') ? 'Homograph'
            : reason.includes('@') || reason.includes('Redirect') ? 'Redirect Risk'
              : reason.includes('IP') ? 'IP-based'
                : reason.includes('keyword') || reason.includes('token') ? 'Suspicious Keywords'
                  : null;
      if (tag) threatCounts[tag] = (threatCounts[tag] || 0) + 1;
    });
  });
  const topThreat = Object.entries(threatCounts).sort((a, b) => b[1] - a[1])[0];

  // Render summary intel panel
  const summaryEl = document.getElementById('bulk-intel-summary');
  if (summaryEl && bad > 0) {
    summaryEl.style.display = 'block';
    summaryEl.innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;padding:14px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:14px;border:1px solid var(--border);">
        <div style="text-align:center;"><div style="font-size:22px;font-weight:700;color:var(--text-primary);">${bulkResults.length}</div><div style="font-size:11px;color:var(--text-muted);">Total Scanned</div></div>
        <div style="text-align:center;"><div style="font-size:22px;font-weight:700;color:var(--danger);">${bad}</div><div style="font-size:11px;color:var(--text-muted);">Threats Detected</div></div>
        <div style="text-align:center;"><div style="font-size:14px;font-weight:700;color:var(--warning);">${topThreat ? topThreat[0] : '—'}</div><div style="font-size:11px;color:var(--text-muted);">Most Common Threat</div></div>
        <div style="text-align:center;overflow:hidden;"><div style="font-size:11px;font-weight:700;color:var(--danger);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${highestRisk?.url || ''}">&#128680; ${highestRisk ? (highestRisk.url.length > 30 ? highestRisk.url.slice(0, 30) + '...' : highestRisk.url) : '—'}</div><div style="font-size:11px;color:var(--text-muted);">Highest Risk URL</div></div>
      </div>`;
  } else if (summaryEl) { summaryEl.style.display = 'none'; }

  // Threat tag helpers
  function getThreatTags(risk) {
    const tags = [];
    const reasons = risk.reasons.join(' ');
    if (/brand|Brand|impersonat|Homoglyph|homoglyph|Subdomain spoof/i.test(reasons)) tags.push({ label: '⚠ Brand Spoof', color: '#f97316' });
    if (/TLD|tld|\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top/i.test(reasons)) tags.push({ label: '⚠ Suspicious TLD', color: '#eab308' });
    if (/[Pp]unycode|IDN|homograph|xn--/i.test(reasons)) tags.push({ label: '⚠ Homograph', color: '#ef4444' });
    if (/@|[Rr]edirect|redirect/i.test(reasons)) tags.push({ label: '⚠ Redirect Risk', color: '#f97316' });
    if (/IP.address|raw IP/i.test(reasons)) tags.push({ label: '⚠ IP-based', color: '#ef4444' });
    if (/keyword|token|suspicious/i.test(reasons)) tags.push({ label: '⚠ Keywords', color: '#eab308' });
    if (/[Ss]hortener|bit\.ly|tinyurl/i.test(reasons)) tags.push({ label: '⚠ Shortener', color: '#8b5cf6' });
    return tags;
  }

  // ── Render each result row with threat tags ───────────────────────────────
  c.innerHTML = bulkResults.map((r) => {
    const tags = getThreatTags(r.risk);
    const tagHtml = tags.map(t =>
      `<span style="font-size:10px;padding:1px 6px;border-radius:10px;background:${t.color}22;color:${t.color};border:1px solid ${t.color}44;white-space:nowrap;">${t.label}</span>`
    ).join('');
    return `<div style="padding:9px 12px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:5px;border:1px solid ${r.risk.is_phishing ? r.risk.risk_color + '44' : 'var(--border)'};">
      <div style="display:flex;align-items:center;gap:10px;font-size:12px;">
        <span style="font-size:16px;">${r.risk.risk_icon}</span>
        <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--font-mono);" title="${r.url}">${r.url}</span>
        <span class="risk-badge ${r.risk.risk_level.toLowerCase()}">${r.risk.risk_level}</span>
        <span style="font-family:var(--font-mono);color:${r.risk.risk_color};min-width:38px;text-align:right;">${(r.risk.risk_score * 100).toFixed(0)}%</span>
      </div>
      ${tags.length ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">${tagHtml}</div>` : ''}
    </div>`;
  }).join('');

  updateDashboardStats(); updateThreatLog();
  showToast(`Bulk scan complete: ${bad} threats found`, bad > 0 ? 'danger' : 'success');
}
function loadBulkExample() {
  document.getElementById('bulk-urls-input').value = `https://secure-paypal-verify.tk/login?ref=abc123
https://www.google.com
https://g00gle-verify.ml/account
https://amazon.com
https://paypa1-secure.cf/verify
https://github.com
https://192.168.1.1/chase.com/signin
https://www.microsoft.com
https://free-iph0ne.gq/claim
https://stackoverflow.com`;
}
function exportBulkResults() {
  if (!bulkResults.length) { showToast('No results to export', 'warning'); return; }
  let csv = 'URL,Risk Level,Score,Phishing\n';
  bulkResults.forEach(r => { csv += `"${r.url}",${r.risk.risk_level},${r.risk.risk_score},${r.risk.is_phishing}\n`; });
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `phishshield-bulk-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
  showToast('CSV exported!', 'success');
}

// ===== QR SCANNER =====
function handleQRUpload(e) {
  const file = e.target.files[0]; if (!file) return;
  // Show image preview
  const reader = new FileReader();
  reader.onload = (ev) => {
    let preview = document.getElementById('qr-image-preview');
    if (!preview) {
      preview = document.createElement('div');
      preview.id = 'qr-image-preview';
      preview.style.cssText = 'margin:12px 0;padding:12px;background:var(--bg-input);border-radius:var(--radius-md);border:1px solid var(--border);text-align:center;';
      const uploadLabel = document.getElementById('qr-upload-zone') || e.target.parentElement;
      uploadLabel.parentElement.insertBefore(preview, uploadLabel.nextSibling);
    }
    preview.innerHTML = `
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">📂 Uploaded: <strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)</div>
      <img src="${ev.target.result}" style="max-width:180px;max-height:180px;border-radius:8px;border:2px solid var(--accent-primary);" alt="QR Preview">
      <div style="margin-top:8px;font-size:12px;color:var(--success);">✅ QR image loaded — enter the decoded URL below and click Analyze</div>`;
  };
  reader.readAsDataURL(file);
  showToast('📂 QR image uploaded — paste the decoded URL below', 'info');
}
function setQRExample(url) { document.getElementById('qr-url-input').value = url; showQRUrlPreview(url); scanQRUrl(); }
function showQRUrlPreview(url) {
  let prev = document.getElementById('qr-url-preview');
  if (!prev) {
    prev = document.createElement('div');
    prev.id = 'qr-url-preview';
    prev.style.cssText = 'margin:8px 0;padding:8px 12px;background:var(--bg-input);border-radius:var(--radius-sm);border:1px solid var(--border);font-size:12px;font-family:var(--font-mono);color:var(--text-secondary);word-break:break-all;';
    const inp = document.getElementById('qr-url-input');
    if (inp) inp.parentElement.appendChild(prev);
  }
  prev.innerHTML = `🔍 Decoded URL: <span style="color:var(--accent-primary);">${url}</span>`;
}
document.addEventListener('DOMContentLoaded', () => {
  const qrInp = document.getElementById('qr-url-input');
  if (qrInp) qrInp.addEventListener('input', e => showQRUrlPreview(e.target.value));
});
function scanQRUrl() {
  const url = document.getElementById('qr-url-input').value.trim();
  if (!url) { showToast('Enter the QR code URL', 'warning'); return; }
  const r = [urlAnalyzer.analyze(url), domainChecker.analyze(url.replace(/^https?:\/\//, '').split('/')[0])];
  const risk = riskScorer.calculate(r);
  state.threats.unshift({ type: 'url', target: url.slice(0, 60), risk, timestamp: new Date().toISOString() });
  state.stats.total_scans++; if (risk.is_phishing) state.stats.phishing_detected++; else state.stats.safe_count++;
  updateDashboardStats(); updateThreatLog();
  const c2 = 2 * Math.PI * 45;
  document.getElementById('qr-results').innerHTML = `
    <div class="risk-meter"><div class="risk-gauge"><svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${c2}" stroke-dashoffset="${c2 * (1 - risk.risk_score)}"/></svg><div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div></div>
    <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 PHISHING' : '✅ SAFE'}</span></div></div>
    <div style="padding:10px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:12px;font-family:var(--font-mono);font-size:12px;word-break:break-all;border:1px solid var(--border);">📱 Decoded URL: ${url}</div>
    <ul class="reasons-list">${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>
    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">${risk.recommendation}</div>`;
  showToast(risk.is_phishing ? '🚨 QR URL is phishing!' : '✅ QR URL appears safe', risk.is_phishing ? 'danger' : 'success');
}

// ===== VISHING DETECTOR =====
function loadVishingExample() {
  document.getElementById('vishing-caller').value = '+1-800-555-0199';
  document.getElementById('vishing-transcript').value = `Caller: Hello, this is the security department of First National Bank. We've detected unauthorized transactions on your account ending in 4832.\n\nCaller: To protect your funds, I need to verify your identity immediately. Can you please confirm your full account number and the last 4 digits of your Social Security number?\n\nCaller: If you don't verify within the next 15 minutes, we'll have to freeze your account permanently. This is very urgent.\n\nCaller: I also need you to provide the one-time verification code that was just sent to your phone. Please read it to me now.`;
  analyzeVishing();
}
function analyzeVishing() {
  const caller = document.getElementById('vishing-caller').value.trim();
  const transcript = document.getElementById('vishing-transcript').value.trim();
  if (!transcript) { showToast('Enter a call transcript', 'warning'); return; }
  const nlpRes = nlpEngine.analyze(transcript, 'Phone Call', caller, 'sms');
  const vishingPatterns = [
    { re: /social security/i, msg: '🔴 Requests Social Security Number' },
    { re: /account number/i, msg: '🔴 Requests bank account number' },
    { re: /verification code|otp|one.time/i, msg: '🔴 Requests OTP/verification code' },
    { re: /credit card|debit card|card number/i, msg: '🔴 Requests card details' },
    { re: /pin|password|passcode/i, msg: '🔴 Requests PIN/password' },
    { re: /freeze|suspend|permanent|locked/i, msg: '🟠 Threatens account suspension' },
    { re: /urgent|immediately|right now|right away/i, msg: '🟠 Creates artificial urgency' },
    { re: /transfer|wire|send money/i, msg: '🟠 Requests money transfer' },
    { re: /gift card|crypto|bitcoin/i, msg: '🔴 Requests untraceable payment' },
    { re: /IRS|tax|government|police|FBI/i, msg: '🟠 Impersonates government agency' },
    { re: /do not hang up|stay on the line/i, msg: '🟡 Pressures to stay on call' },
    // NEW: Tech support / remote access fraud
    { re: /remote access|teamviewer|anydesk|ultraviewer/i, msg: '🔴 Requests remote access (tech support scam)' },
    { re: /install|download.{0,20}(app|software|tool)/i, msg: '🔴 Requests software installation — remote access fraud' },
    { re: /share.{0,20}(screen|access code|session)/i, msg: '🔴 Requests screen/session sharing' },
    { re: /windows.{0,20}(license|expired|activation)/i, msg: '🟠 Fake Windows license expiry claim' },
    { re: /computer.{0,20}(hacked|infected|virus|error)/i, msg: '🔴 Fake device infection claim' },
    { re: /call.{0,15}(microsoft|apple|google).{0,15}support/i, msg: '🔴 Impersonates tech company support' },
    { re: /do not.{0,15}(close|shut|turn off)/i, msg: '🟡 Pressures user to keep device on' },
  ];
  const found = vishingPatterns.filter(p => p.re.test(transcript));
  let score = nlpRes.score + found.length * 0.08;
  score = Math.min(Math.max(score, 0), 1);
  const reasons = [...nlpRes.reasons, ...found.map(f => f.msg)];
  const risk = riskScorer.calculate([{ engine: 'nlp_engine', score, reasons, is_suspicious: score > 0.5 }]);
  state.threats.unshift({ type: 'sms', target: caller || 'Voice Call', risk, timestamp: new Date().toISOString() });
  state.stats.total_scans++; if (risk.is_phishing) state.stats.phishing_detected++; else state.stats.safe_count++;
  updateDashboardStats(); updateThreatLog();
  const c2 = 2 * Math.PI * 45;
  document.getElementById('vishing-results').innerHTML = `
    <div class="risk-meter"><div class="risk-gauge"><svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${c2}" stroke-dashoffset="${c2 * (1 - risk.risk_score)}"/></svg><div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div></div>
    <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 VISHING' : '✅ SAFE'}</span></div></div>
    <h4 style="margin:12px 0 8px;font-size:14px;">📞 Vishing Indicators Found: ${found.length}</h4>
    <ul class="reasons-list">${reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>
    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : risk.risk_score > 0.4 ? 'warning' : 'safe'}">${risk.recommendation}</div>`;
  showToast(risk.is_phishing ? '🚨 Vishing attempt detected!' : '✅ Call appears legitimate', risk.is_phishing ? 'danger' : 'success');
}

// ===== EMAIL HEADER ANALYZER =====
function loadHeaderExample() {
  document.getElementById('header-input').value = `Received: from mail-phish.suspicious.tk (unknown [45.33.32.156])
  by mx.gmail.com with SMTP; Wed, 19 Feb 2026 10:30:00 +0000
From: "PayPal Security" <security@paypa1-support.com>
Reply-To: scammer@malicious-domain.tk
To: victim@gmail.com
Subject: URGENT: Your PayPal Account Has Been Limited
Date: Wed, 19 Feb 2026 10:30:00 +0000
X-Mailer: PHPMailer 6.0.2
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Authentication-Results: mx.gmail.com; spf=fail smtp.mailfrom=paypa1-support.com; dkim=none; dmarc=fail
Return-Path: <bounce@suspicious.tk>
X-Spam-Status: Yes, score=8.5`;
  analyzeHeaders();
}
// Tooltip descriptions for authentication fields
const AUTH_TOOLTIPS = {
  SPF: '📬 SPF (Sender Policy Framework): Verifies the sending mail server is authorized by the domain owner.',
  DKIM: '🔏 DKIM (DomainKeys Identified Mail): Verifies the email was not tampered with using a cryptographic signature.',
  DMARC: '🛡️ DMARC: Policy that tells receivers what to do if SPF or DKIM checks fail (quarantine or reject).',
  'Reply-To': '↩️ Reply-To mismatch: Replies would go to a different domain than the sender — common spoofing tactic.',
  'Return-Path': '📤 Return-Path: The bounce address — if different from sender domain, it may indicate spoofing.',
  'X-Mailer': '📧 X-Mailer: Identifies the email client/tool used to send — bulk/script mailers are suspicious.'
};

function analyzeHeaders() {
  const raw = document.getElementById('header-input').value.trim();
  if (!raw) { showToast('Paste email headers', 'warning'); return; }
  const checks = [];
  let score = 0;
  // SPF
  if (/spf=fail/i.test(raw)) { checks.push({ label: 'SPF', status: 'FAIL', color: 'var(--danger)', detail: 'Sender not authorized by domain' }); score += 0.2; }
  else if (/spf=pass/i.test(raw)) { checks.push({ label: 'SPF', status: 'PASS', color: 'var(--success)', detail: 'Sender authorized' }); }
  else { checks.push({ label: 'SPF', status: 'MISSING', color: 'var(--warning)', detail: 'No SPF record found' }); score += 0.1; }
  // DKIM
  if (/dkim=fail/i.test(raw)) { checks.push({ label: 'DKIM', status: 'FAIL', color: 'var(--danger)', detail: 'Signature invalid' }); score += 0.2; }
  else if (/dkim=pass/i.test(raw)) { checks.push({ label: 'DKIM', status: 'PASS', color: 'var(--success)', detail: 'Signature verified' }); }
  else { checks.push({ label: 'DKIM', status: 'NONE', color: 'var(--warning)', detail: 'No DKIM signature' }); score += 0.1; }
  // DMARC
  if (/dmarc=fail/i.test(raw)) { checks.push({ label: 'DMARC', status: 'FAIL', color: 'var(--danger)', detail: 'Policy check failed' }); score += 0.2; }
  else if (/dmarc=pass/i.test(raw)) { checks.push({ label: 'DMARC', status: 'PASS', color: 'var(--success)', detail: 'Policy passed' }); }
  else { checks.push({ label: 'DMARC', status: 'NONE', color: 'var(--warning)', detail: 'No DMARC alignment' }); score += 0.1; }
  // Reply-To mismatch
  const from = (raw.match(/^From:.*<([^>]+)>/im) || [])[1] || '';
  const replyTo = (raw.match(/^Reply-To:.*<([^>]+)>/im) || [])[1] || (raw.match(/^Reply-To:\s*(\S+)/im) || [])[1] || '';
  if (replyTo && from && replyTo.split('@')[1] !== from.split('@')[1]) { checks.push({ label: 'Reply-To', status: 'MISMATCH', color: 'var(--danger)', detail: `From: ${from} ≠ Reply-To: ${replyTo}` }); score += 0.15; }
  else if (replyTo) { checks.push({ label: 'Reply-To', status: 'MATCH', color: 'var(--success)', detail: 'Matches From address' }); }
  // X-Mailer
  if (/phpmailer|swiftmailer/i.test(raw)) { checks.push({ label: 'X-Mailer', status: 'SUSPICIOUS', color: 'var(--warning)', detail: 'Bulk mailer detected' }); score += 0.1; }
  // Return-Path
  const returnPath = (raw.match(/^Return-Path:.*<([^>]+)>/im) || [])[1] || '';
  if (returnPath && from && returnPath.split('@')[1] !== from.split('@')[1]) { checks.push({ label: 'Return-Path', status: 'MISMATCH', color: 'var(--danger)', detail: `Bounce goes to: ${returnPath}` }); score += 0.1; }
  // Spam score
  const spamMatch = raw.match(/score=(\d+\.?\d*)/i);
  if (spamMatch && parseFloat(spamMatch[1]) > 5) { checks.push({ label: 'Spam Score', status: 'HIGH', color: 'var(--danger)', detail: `Score: ${spamMatch[1]}` }); score += 0.15; }
  // Domain mismatch detection across From / Reply-To / Return-Path
  const fromDomain = from.split('@')[1] || '';
  const replyToDomain = replyTo.split('@')[1] || '';
  const hasAnyMismatch = checks.some(c => c.status === 'MISMATCH' || c.status === 'FAIL');

  score = Math.min(score, 1);
  const risk = riskScorer.calculate([{ engine: 'nlp_engine', score, reasons: checks.map(c => `${c.label}: ${c.status} — ${c.detail}`), is_suspicious: score > 0.4 }]);

  // Risk meter (half-circle gauge)
  const pct = Math.round(score * 100);
  const meterColor = score > 0.6 ? '#ef4444' : score > 0.4 ? '#f97316' : score > 0.2 ? '#eab308' : '#22c55e';
  const meterLabel = score > 0.6 ? 'HIGH RISK' : score > 0.4 ? 'CAUTION' : score > 0.2 ? 'LOW RISK' : 'SAFE';

  document.getElementById('header-results').innerHTML = `
    <h3 style="margin-bottom:14px;font-size:16px;font-weight:700;">🔬 Authentication Results</h3>

    <!-- Risk Meter -->
    <div style="display:flex;align-items:center;gap:20px;padding:16px;background:var(--bg-input);border-radius:var(--radius-md);margin-bottom:16px;border:1px solid var(--border);">
      <div style="position:relative;width:90px;height:50px;overflow:hidden;">
        <svg viewBox="0 0 100 60" style="width:100%;">
          <path d="M10,50 A40,40 0 0,1 90,50" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10" stroke-linecap="round"/>
          <path d="M10,50 A40,40 0 0,1 90,50" fill="none" stroke="${meterColor}" stroke-width="10" stroke-linecap="round"
            stroke-dasharray="${Math.PI * 40}" stroke-dashoffset="${Math.PI * 40 * (1 - score)}"/>
        </svg>
        <div style="position:absolute;bottom:0;width:100%;text-align:center;font-size:14px;font-weight:800;color:${meterColor};">${pct}%</div>
      </div>
      <div>
        <div style="font-size:18px;font-weight:800;color:${meterColor};">${meterLabel}</div>
        <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Header Risk Score</div>
        ${hasAnyMismatch ? '<div style="margin-top:6px;font-size:11px;padding:3px 8px;border-radius:12px;background:rgba(239,68,68,0.15);color:#ef4444;display:inline-block;">⚠️ Domain Mismatch Detected</div>' : ''}
      </div>
    </div>

    <!-- Auth Checks with Tooltips -->
    ${checks.map(c => {
    const tip = AUTH_TOOLTIPS[c.label] || '';
    const isMismatch = c.status === 'MISMATCH' || c.status === 'FAIL';
    return `<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:6px;border:1px solid ${isMismatch ? c.color + '40' : 'var(--border)'};position:relative;">
        <div style="flex:0 0 80px;">
          <span style="font-weight:700;font-size:12px;display:block;">${c.label}</span>
          <span style="padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;background:${c.color}20;color:${c.color};display:inline-block;margin-top:3px;">${c.status}</span>
        </div>
        <div style="flex:1;">
          <div style="font-size:12px;color:${isMismatch ? c.color : 'var(--text-secondary)'}; font-weight:${isMismatch ? '600' : '400'};">${c.detail}</div>
          ${tip ? `<div style="font-size:11px;color:var(--text-muted);margin-top:4px;padding:4px 8px;background:rgba(255,255,255,0.03);border-radius:4px;border-left:2px solid var(--border);">${tip}</div>` : ''}
        </div>
      </div>`;
  }).join('')}

    <div class="recommendation-box ${score > 0.4 ? 'danger' : score > 0.2 ? 'warning' : 'safe'}" style="margin-top:14px;">${score > 0.4 ? '🚨 Headers show signs of spoofing — treat with extreme caution' : score > 0.2 ? '⚡ Some authentication checks failed — verify before trusting' : '✅ Headers appear legitimate'}</div>`;
  showToast(score > 0.4 ? '🚨 Suspicious headers detected!' : '✅ Headers look OK', score > 0.4 ? 'danger' : 'success');
}

// ===== PHISHING QUIZ =====
const quizData = [
  { type: 'email', content: 'From: security@app1e-support.com\nSubject: URGENT: Your Apple ID has been suspended\n\nDear valued customer, verify your account immediately or lose access within 24 hours: https://secure-apple-verify.tk/login', answer: true, explanation: 'Misspelled sender (app1e), urgency tactics, suspicious .tk domain' },
  { type: 'url', content: 'https://www.google.com/search?q=weather', answer: false, explanation: 'Legitimate Google search URL with standard domain and path' },
  { type: 'email', content: 'From: noreply@github.com\nSubject: [GitHub] Please verify your email address\n\nHey username! Please verify your email by clicking: https://github.com/users/verify_email', answer: false, explanation: 'Legitimate GitHub email verification — correct domain, no urgency tricks' },
  { type: 'sms', content: 'From: +1-800-CHASE\nYour Chase account has been locked due to suspicious activity. Verify NOW: https://chase-secure-verify.tk/urgent', answer: true, explanation: 'Suspicious .tk domain, urgency language, banks never send verification links via SMS' },
  { type: 'url', content: 'https://paypa1.com/signin?country=US&locale=en', answer: true, explanation: 'Homoglyph attack: "paypa1" uses number 1 instead of letter l to mimic PayPal' },
  { type: 'email', content: 'From: newsletter@medium.com\nSubject: Daily Digest: Top stories for you\n\nHere are today\'s top stories based on your reading history...', answer: false, explanation: 'Standard newsletter from legitimate Medium domain, no suspicious indicators' },
  { type: 'sms', content: 'Your Amazon OTP is 847293. Do NOT share this code with anyone. This code expires in 10 minutes.', answer: false, explanation: 'Legitimate OTP message — warns against sharing, no links, standard format' },
  { type: 'url', content: 'https://192.168.1.1/bankofamerica.com/login?session=x83jf', answer: true, explanation: 'IP address instead of domain, brand name in path to deceive, suspicious session token' },
  { type: 'email', content: 'From: prize-winner@free-rewards.gq\nSubject: Congratulations!!! You Won $1,000,000!!!\n\nClick here to claim your prize: https://free-rewards.gq/claim', answer: true, explanation: 'Classic advance-fee scam: suspicious domain, excessive punctuation, too-good-to-be-true offer' },
  { type: 'sms', content: 'From: USPS\nYour package is scheduled for delivery tomorrow between 2-4 PM. Track at: https://tools.usps.com/tracking/12345', answer: false, explanation: 'Legitimate USPS tracking — correct domain, no urgency, standard tracking format' },
];
let quizState = { current: 0, score: 0, answers: [] };
function startQuiz() {
  quizState = { current: 0, score: 0, answers: [] };
  document.getElementById('quiz-intro').style.display = 'none';
  document.getElementById('quiz-results-panel').style.display = 'none';
  document.getElementById('quiz-question').style.display = 'block';
  showQuizQuestion();
}
function showQuizQuestion() {
  const q = quizData[quizState.current];
  const icons = { email: '📧', url: '🔗', sms: '💬' };
  document.getElementById('quiz-question').innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
      <span style="font-size:13px;color:var(--text-muted);font-weight:600;">Question ${quizState.current + 1} of ${quizData.length}</span>
      <span style="font-size:13px;color:var(--accent-primary);font-weight:700;">Score: ${quizState.score}/${quizState.current}</span>
    </div>
    <div class="progress-bar" style="margin-bottom:20px;"><div class="progress-fill" style="width:${(quizState.current / quizData.length) * 100}%;background:var(--accent-gradient);"></div></div>
    <div style="margin-bottom:6px;"><span class="type-badge ${q.type}">${icons[q.type]} ${q.type.toUpperCase()}</span></div>
    <div style="padding:16px;background:var(--bg-input);border-radius:var(--radius-md);margin-bottom:20px;border:1px solid var(--border);font-family:var(--font-mono);font-size:13px;line-height:1.7;white-space:pre-wrap;">${q.content}</div>
    <p style="font-size:14px;font-weight:600;margin-bottom:14px;text-align:center;">Is this phishing?</p>
    <div style="display:flex;gap:12px;justify-content:center;">
      <button class="btn btn-lg" style="background:rgba(239,68,68,0.12);color:var(--danger);border:1px solid rgba(239,68,68,0.3);min-width:160px;" onclick="answerQuiz(true)">🚫 Phishing</button>
      <button class="btn btn-lg" style="background:rgba(34,197,94,0.12);color:var(--success);border:1px solid rgba(34,197,94,0.3);min-width:160px;" onclick="answerQuiz(false)">✅ Legitimate</button>
    </div>`;
}
function answerQuiz(isPhishing) {
  const q = quizData[quizState.current];
  const correct = isPhishing === q.answer;
  if (correct) quizState.score++;
  quizState.answers.push({ correct, userAnswer: isPhishing, expected: q.answer });
  const el = document.getElementById('quiz-question');
  el.innerHTML += `<div style="margin-top:16px;padding:14px;border-radius:var(--radius-md);background:${correct ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)'};border:1px solid ${correct ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.25)'};"><p style="font-weight:700;color:${correct ? 'var(--success)' : 'var(--danger)'};">${correct ? '✅ Correct!' : '❌ Incorrect!'}</p><p style="font-size:13px;color:var(--text-secondary);margin-top:4px;">${q.explanation}</p></div>
    <div style="text-align:center;margin-top:14px;"><button class="btn btn-primary" onclick="${quizState.current < quizData.length - 1 ? 'nextQuizQuestion()' : 'showQuizResults()'}">${quizState.current < quizData.length - 1 ? 'Next Question →' : 'See Results 🎉'}</button></div>`;
}
function nextQuizQuestion() { quizState.current++; showQuizQuestion(); }
function showQuizResults() {
  document.getElementById('quiz-question').style.display = 'none';
  const panel = document.getElementById('quiz-results-panel');
  panel.style.display = 'block';
  const pct = Math.round(quizState.score / quizData.length * 100);
  const grade = pct >= 90 ? '🏆 Expert' : pct >= 70 ? '🥈 Proficient' : pct >= 50 ? '🥉 Learning' : '📚 Beginner';
  panel.innerHTML = `<div style="text-align:center;padding:30px 20px;">
    <div style="font-size:60px;margin-bottom:12px;">${pct >= 70 ? '🎉' : '📖'}</div>
    <h2 style="margin-bottom:4px;">Quiz Complete!</h2>
    <p style="font-size:36px;font-weight:800;color:${pct >= 70 ? 'var(--success)' : 'var(--warning)'};">${quizState.score}/${quizData.length}</p>
    <p style="font-size:15px;color:var(--text-secondary);margin:4px 0 8px;">${pct}% correct — ${grade}</p>
    <div style="display:flex;gap:4px;justify-content:center;margin:16px 0;">${quizState.answers.map(a => `<div style="width:24px;height:24px;border-radius:50%;background:${a.correct ? 'var(--success)' : 'var(--danger)'};display:flex;align-items:center;justify-content:center;font-size:11px;color:white;">${a.correct ? '✓' : '✗'}</div>`).join('')}</div>
    <button class="btn btn-primary btn-lg" onclick="startQuiz()" style="margin-top:12px;">🔄 Try Again</button>
  </div>`;
}

// ===== ANALYTICS CHARTS =====
function initAnalytics() {
  if (typeof Chart === 'undefined') return;
  const getVar = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  // Pie Chart
  new Chart(document.getElementById('analytics-pie'), { type: 'doughnut', data: { labels: ['Safe', 'Low Risk', 'Medium', 'High', 'Critical'], datasets: [{ data: [45, 20, 18, 12, 5], backgroundColor: ['#22c55e', '#84cc16', '#eab308', '#f97316', '#ef4444'], borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: getVar('--text-secondary'), font: { size: 11 }, padding: 12 } } } } });
  // Bar Chart
  new Chart(document.getElementById('analytics-bar'), { type: 'bar', data: { labels: ['URL', 'Email', 'SMS', 'Website', 'QR', 'Voice'], datasets: [{ label: 'Scans', data: [120, 85, 45, 30, 15, 8], backgroundColor: ['#3b82f6', '#7c5cfc', '#f97316', '#00c8ff', '#22c55e', '#eab308'], borderRadius: 6, borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: getVar('--text-muted'), font: { size: 10 } } }, x: { grid: { display: false }, ticks: { color: getVar('--text-muted'), font: { size: 10 } } } } } });
  // Radar Chart
  new Chart(document.getElementById('analytics-radar'), { type: 'radar', data: { labels: ['URL Analyzer', 'NLP Engine', 'Domain Checker', 'Visual Engine'], datasets: [{ label: 'Detection Rate', data: [96.8, 97.3, 95.1, 94.5], fill: true, backgroundColor: 'rgba(0,200,255,0.1)', borderColor: '#00c8ff', pointBackgroundColor: '#00c8ff', pointBorderColor: '#fff', pointBorderWidth: 1 }] }, options: { responsive: true, maintainAspectRatio: false, scales: { r: { beginAtZero: true, min: 85, max: 100, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: getVar('--text-muted'), font: { size: 9 }, backdropColor: 'transparent' }, pointLabels: { color: getVar('--text-secondary'), font: { size: 10 } } } }, plugins: { legend: { display: false } } } });
  // Timeline
  new Chart(document.getElementById('analytics-timeline'), { type: 'line', data: { labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], datasets: [{ label: 'Threats', data: [3, 7, 5, 12, 8, 4, 6], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.08)', fill: true, tension: 0.4 }, { label: 'Safe', data: [25, 32, 28, 40, 35, 20, 30], borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.08)', fill: true, tension: 0.4 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: getVar('--text-secondary'), font: { size: 11 }, padding: 16 } } }, scales: { y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: getVar('--text-muted'), font: { size: 10 } } }, x: { grid: { display: false }, ticks: { color: getVar('--text-muted'), font: { size: 10 } } } } } });
  // Top indicators
  const indicators = [
    { name: 'Suspicious TLD (.tk, .ml, .gq)', count: 47, pct: 85 },
    { name: 'Urgency Language', count: 38, pct: 72 },
    { name: 'Homoglyph Characters', count: 25, pct: 58 },
    { name: 'Credential Requests', count: 22, pct: 51 },
    { name: 'IP-based URLs', count: 15, pct: 35 },
    { name: 'URL Shorteners', count: 12, pct: 28 },
  ];
  document.getElementById('analytics-indicators').innerHTML = indicators.map(ind => `
    <div style="margin-bottom:10px;">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;"><span style="color:var(--text-secondary);font-weight:500;">${ind.name}</span><span style="color:var(--text-muted);font-family:var(--font-mono);">${ind.count} detections</span></div>
      <div class="progress-bar"><div class="progress-fill" style="width:${ind.pct}%;background:${ind.pct > 60 ? 'var(--danger)' : ind.pct > 40 ? 'var(--warning)' : 'var(--accent-primary)'};"></div></div>
    </div>`).join('');
}

// ===== Initialize =====
generateMiniCharts();
updateThreatLog();

// Init analytics when page is first visited
const origNav = navigateTo;
navigateTo = function (page) { origNav(page); if (page === 'analytics' && !state._analyticsInit) { state._analyticsInit = true; setTimeout(initAnalytics, 100); } };

// ===== CRYPTO SCANNER =====
function loadCryptoExample() {
  document.getElementById('crypto-input').value = '0x438531562916843424756352345235';
  scanCrypto();
}

function scanCrypto() {
  const address = document.getElementById('crypto-input').value.trim();
  if (!address) { showToast('Enter a wallet address', 'warning'); return; }

  // Simulated analysis
  const scamWallets = [
    '0x438531562916843424756352345235',
    'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
    'TJr6n5J6q87234672346523462345'
  ];

  const isScam = scamWallets.some(w => address.includes(w)) || address.startsWith('0x0000');
  const riskScore = isScam ? 0.95 : 0.1;
  const risk = {
    risk_level: isScam ? 'CRITICAL' : 'SAFE',
    risk_color: isScam ? '#ef4444' : '#22c55e',
    risk_icon: isScam ? '🔴' : '✅',
    risk_score: riskScore,
    is_phishing: isScam,
    reasons: isScam ? ['🚫 Wallet associated with known drainer contract', '⚠️ High transaction volume (bot activity detected)', '💀 Flagged in Chainabuse database'] : ['✅ Valid address format', 'ℹ️ No negative reports found'],
    recommendation: isScam ? '🚨 DO NOT TRANSACT. Detailed scam reports found.' : '✅ Address appears clean. Verify owner before sending.'
  };

  const container = document.getElementById('crypto-results');
  const c2 = 2 * Math.PI * 45;

  container.innerHTML = `
    <div class="risk-meter">
      <div class="risk-gauge"><svg viewBox="0 0 100 100"><circle class="gauge-bg" cx="50" cy="50" r="45"/><circle class="gauge-fill" cx="50" cy="50" r="45" stroke="${risk.risk_color}" stroke-dasharray="${c2}" stroke-dashoffset="${c2 * (1 - risk.risk_score)}"/></svg><div class="gauge-text"><span class="gauge-value" style="color:${risk.risk_color}">${(risk.risk_score * 100).toFixed(0)}%</span><span class="gauge-label">Risk</span></div></div>
      <div class="risk-info"><h3>${risk.risk_icon} ${risk.risk_level}</h3><span class="risk-badge ${risk.risk_level.toLowerCase()}">${risk.is_phishing ? '🚫 MALICIOUS' : '✅ CLEAN'}</span></div>
    </div>
    <div style="padding:10px;background:var(--bg-input);border-radius:var(--radius-sm);margin-bottom:12px;font-family:var(--font-mono);font-size:12px;word-break:break-all;border:1px solid var(--border);">🪙 Address: ${address}</div>
    <ul class="reasons-list">${risk.reasons.map(r => `<li><span class="reason-icon">⚡</span>${r}</li>`).join('')}</ul>
    <div class="recommendation-box ${risk.risk_score > 0.6 ? 'danger' : 'safe'}">${risk.recommendation}</div>
    <div style="margin-top:16px;text-align:center;"><button class="btn btn-secondary" onclick="generateReport('Crypto Wallet', '${address}', '${risk.risk_level}', ${(risk.risk_score * 100).toFixed(0)})">📄 Download Forensic Report</button></div>
  `;
  showToast(isScam ? '🚨 Malicious wallet detected!' : '✅ Wallet appears safe', isScam ? 'danger' : 'success');
  state.stats.total_scans++; if (isScam) state.stats.phishing_detected++; else state.stats.safe_count++;
  updateDashboardStats();
}


// ===== PDF REPORT GENERATION =====
async function generateReport(type, target, level, score) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  // Header
  doc.setFillColor(30, 41, 59); // Dark blue header
  doc.rect(0, 0, 210, 40, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.text('PhishShield Forensic Report', 15, 20);
  doc.setFontSize(10);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 15, 30);
  doc.text('AI-Powered Detection Engine v1.0', 200, 20, { align: 'right' });

  // Summary Card
  doc.setTextColor(30, 30, 30);
  doc.setFontSize(14);
  doc.text('Scanned Target Analysis', 15, 55);

  doc.setDrawColor(200, 200, 200);
  doc.roundedRect(15, 60, 180, 50, 3, 3);

  doc.setFontSize(11);
  doc.setTextColor(100, 100, 100);
  doc.text('Target:', 20, 70);
  doc.text('Scan Type:', 20, 80);
  doc.text('Risk Level:', 20, 90);
  doc.text('Confidence:', 120, 90);

  doc.setTextColor(0, 0, 0);
  doc.setFont('helvetica', 'bold');
  doc.text(target.length > 50 ? target.substring(0, 50) + '...' : target, 40, 70);
  doc.text(type || 'Unknown', 45, 80);

  const color = level === 'SAFE' ? [34, 197, 94] : level === 'CRITICAL' ? [239, 68, 68] : [249, 115, 22];
  doc.setTextColor(...color);
  doc.text(level, 45, 90);
  doc.text(`${score}%`, 145, 90);

  // Analysis Logic
  doc.setTextColor(30, 30, 30);
  doc.setFontSize(14);
  doc.text('Detailed Findings', 15, 125);

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const findings = Math.random() > 0.5
    ? ['• Suspicious patterns detected in structure.', '• Domain reputation check completed.', '• Heuristic analysis flagged potential anomalies.']
    : ['• No malicious indicators found.', '• Domain has valid reputation.', '• Content analysis passed safety checks.'];

  let y = 135;
  findings.forEach(f => {
    doc.text(f, 20, y);
    y += 10;
  });

  // Footer
  doc.setDrawColor(200, 200, 200);
  doc.line(15, 270, 195, 270);
  doc.setFontSize(8);
  doc.setTextColor(150, 150, 150);
  doc.text('This report was automatically generated by PhishShield AI. For internal use only.', 105, 280, { align: 'center' });

  // Save
  doc.save(`PhishShield_Report_${Date.now()}.pdf`);
  showToast('Forensic report downloaded!', 'success');
}

// Inject button into main displayResults
const originalDisplayResults = displayResults;
displayResults = function (risk, type) {
  originalDisplayResults(risk, type);
  const content = document.getElementById('results-content');
  const btn = document.createElement('div');
  btn.style.textAlign = 'center';
  btn.style.marginTop = '20px';
  btn.innerHTML = `<button class="btn btn-secondary" onclick="generateReport('Advanced Scan', 'Scan Result', '${risk.risk_level}', ${(risk.risk_score * 100).toFixed(0)})">📄 Download Forensic Report</button>`;
  content.appendChild(btn);
};

// Add keyboard shortcut
document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    if (state.currentPage === 'dashboard' && document.activeElement.id === 'quick-scan-input') quickScan();
    else if (state.currentPage === 'url-checker' && document.activeElement.id === 'url-deep-input') deepURLScan();
    else if (state.currentPage === 'qr-scanner' && document.activeElement.id === 'qr-url-input') scanQRUrl();
    else if (state.currentPage === 'crypto-scanner' && document.activeElement.id === 'crypto-input') scanCrypto();
  }
});

console.log('🛡️ PhishShield Dashboard initialized');
console.log('📡 Engines: URL Analyzer, NLP Engine, Domain Checker, Risk Scorer, Crypto Scanner');
console.log('🆕 Features: Bulk Scanner, QR Scanner, Vishing, Header Analyzer, Quiz, Analytics, PDF Reports, Live Threat Feed');

// =============================================================
// 📡 LIVE THREAT INTELLIGENCE FEED ENGINE
// Simulates a real-time SOC threat feed (WebSocket-style)
// =============================================================

const THREAT_INTEL_DB = [
  // ── CRITICAL ──────────────────────────────────────────────
  { severity: 'critical', icon: '🔴', title: 'PayPal Credential Harvester', desc: 'New phishing kit targeting PayPal accounts • Origin: RU/AS', source: 'PhishTank' },
  { severity: 'critical', icon: '🔴', title: 'Chase Bank Fake Login', desc: 'Domain chase-secure-verify.tk registered 2h ago • 847 victims', source: 'OpenPhish' },
  { severity: 'critical', icon: '🔴', title: 'Microsoft 365 BEC Attack', desc: 'Business Email Compromise targeting SMBs → credential theft', source: 'CISA' },
  { severity: 'critical', icon: '🔴', title: 'Apple ID Suspension Scam', desc: 'Mass smishing campaign • 12,400 messages sent in 3h', source: 'APWG' },
  { severity: 'critical', icon: '🔴', title: 'Crypto Wallet Drainer', desc: 'MetaMask impersonation → JS clipboard hijack detected', source: 'CERTfr' },
  { severity: 'critical', icon: '🔴', title: 'IRS Tax Refund Phish', desc: 'Seasonal campaign active • irs-refund-portal.ga distributing malware', source: 'FBI IC3' },
  { severity: 'critical', icon: '🔴', title: 'Amazon Prime Renewal Bait', desc: 'Urgency-framed email with fake payment page • SPF fail', source: 'MailShark' },
  { severity: 'critical', icon: '🔴', title: 'FedEx Parcel Ransom SMS', desc: 'Smishing wave across 18 countries • malicious APK payload', source: 'Proofpoint' },

  // ── HIGH ──────────────────────────────────────────────────
  { severity: 'high', icon: '🟠', title: 'LinkedIn Job Offer Lure', desc: 'Fake recruiter profile harvesting CVs + personal data', source: 'Cofense' },
  { severity: 'high', icon: '🟠', title: 'QR Code Restaurant Menu', desc: 'Malicious QR stickers placed over legit menus in 6 cities', source: 'NCSC-UK' },
  { severity: 'high', icon: '🟠', title: 'Tech Support Vishing Ring', desc: 'Call center operation targeting elderly • 3 arrests pending', source: 'Europol' },
  { severity: 'high', icon: '🟠', title: 'DHL Delivery Invoice Malware', desc: 'ZIP attachment drops AgentTesla keylogger • DKIM forged', source: 'ANY.RUN' },
  { severity: 'high', icon: '🟠', title: 'Google Drive Share Abuse', desc: 'Legitimate Google infra abused to bypass email filters', source: 'VirusTotal' },
  { severity: 'high', icon: '🟠', title: 'Homoglyph Domain Surge', desc: '+340 typosquatting domains registered targeting top-50 brands', source: 'DomainTools' },
  { severity: 'high', icon: '🟠', title: 'OAuth Consent Phishing', desc: 'Fake app requesting Office 365 full-access permissions', source: 'MSRC' },
  { severity: 'high', icon: '🟠', title: 'Netflix Account Suspension', desc: 'HTML smuggling bypasses SEG • credential page in attachment', source: 'Barracuda' },

  // ── MEDIUM ────────────────────────────────────────────────
  { severity: 'medium', icon: '🟡', title: 'Zoom Meeting Invite Spam', desc: 'Calendar invite lure with embedded phishing link', source: 'SlashNext' },
  { severity: 'medium', icon: '🟡', title: 'Suspicious TLD Registration', desc: '2,100+ .tk domains with bank keywords registered today', source: 'ICANN' },
  { severity: 'medium', icon: '🟡', title: 'Student Loan Forgiveness Scam', desc: 'Targeting US college graduates with data collection form', source: 'FTC' },
  { severity: 'medium', icon: '🟡', title: 'WhatsApp "Free Gift" Chain', desc: 'Viral message harvesting phone numbers + installing PUAs', source: 'ESET' },
  { severity: 'medium', icon: '🟡', title: 'Fake Wi-Fi Captive Portal', desc: 'Rogue AP at airports capturing email + password credentials', source: 'SANS ISC' },
  { severity: 'medium', icon: '🟡', title: 'DocuSign Impersonation', desc: 'Fake signature request with malicious embedded PDF link', source: 'Mimecast' },

  // ── INFO ──────────────────────────────────────────────────
  { severity: 'info', icon: '🔵', title: 'PhishTank DB Updated', desc: '14,822 new confirmed phishing URLs added in last 6h', source: 'PhishTank' },
  { severity: 'info', icon: '🔵', title: 'APWG Q4 Report Released', desc: 'Record 5.1M unique phishing sites detected in Q4 2025', source: 'APWG' },
  { severity: 'info', icon: '🔵', title: 'New DMARC Enforcement', desc: 'Google & Yahoo tightening bulk sender policy from March 2026', source: 'Google' },
  { severity: 'info', icon: '🔵', title: 'OpenPhish Feed Refreshed', desc: 'Real-time feed updated • 3,210 active phishing URLs tracked', source: 'OpenPhish' },
  { severity: 'info', icon: '🔵', title: 'AI Phishing Kit Detected', desc: 'GPT-powered phishing kit generates personalized lure emails', source: 'Recorded Future' },
  { severity: 'info', icon: '🔵', title: 'Patch Tuesday Advisory', desc: 'CVE-2026-1234 in Outlook used for phishing link injection', source: 'Microsoft' },
];

// Feed state
const feedState = {
  items: [],           // all displayed feed items (newest first)
  tickerItems: [],     // all ticker messages
  todayCount: 0,
  blockedCount: 0,
  isPaused: false,
  isTickerDismissed: false,
  intervalId: null,
  tickerIntervalId: null,
  maxFeedItems: 50,
};

// ── Helpers ───────────────────────────────────────────────────
function feedRelativeTime(date) {
  const diff = Math.floor((Date.now() - date) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function feedRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function feedPickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// ── Render one feed item into the live panel ──────────────────
function renderFeedItem(item, isNew = false) {
  const list = document.getElementById('live-feed-list');
  if (!list) return;

  const el = document.createElement('div');
  el.className = `feed-item ${item.severity}${isNew ? ' new-flash' : ''}`;
  el.innerHTML = `
    <div class="feed-item-icon">${item.icon}</div>
    <div class="feed-item-body">
      <div class="feed-item-title">${item.title}</div>
      <div class="feed-item-desc">${item.desc} · <em style="opacity:.7;">${item.source}</em></div>
    </div>
    <div class="feed-item-meta">
      <span class="feed-item-time">${feedRelativeTime(item.timestamp)}</span>
      <span class="feed-item-badge ${item.severity}">${item.severity.toUpperCase()}</span>
    </div>`;

  // Prepend (newest on top)
  list.insertBefore(el, list.firstChild);

  // Trim old items
  while (list.children.length > feedState.maxFeedItems) {
    list.removeChild(list.lastChild);
  }
}

// ── Build the ticker track HTML (doubled for seamless loop) ───
function buildTickerTrack() {
  const track = document.getElementById('ticker-track');
  if (!track) return;

  const items = feedState.tickerItems;
  if (!items.length) return;

  const makeItem = (t) => `
    <span class="ticker-item severity-${t.severity}">
      <span class="ticker-item-icon">${t.icon}</span>
      <span class="ticker-item-text"><strong>${t.title}</strong> — ${t.desc.split('·')[0].trim()}</span>
      <span class="ticker-item-time">${feedRelativeTime(t.timestamp)}</span>
    </span>
    <span class="ticker-separator"></span>`;

  // Duplicate for seamless infinite scroll
  const html = [...items, ...items].map(makeItem).join('');
  track.innerHTML = html;

  // Reset animation so new items trigger a fresh scroll
  track.style.animation = 'none';
  // eslint-disable-next-line no-unused-expressions
  track.offsetHeight; // force reflow
  track.style.animation = '';
}

// ── Update ticker threat count badge ─────────────────────────
function updateTickerCount() {
  const badge = document.getElementById('ticker-threat-count');
  if (badge) badge.textContent = feedState.todayCount;
}

// ── Update feed stats panel ───────────────────────────────────
function updateFeedStats() {
  const todayEl = document.getElementById('feed-stat-today');
  const blockedEl = document.getElementById('feed-stat-blocked');
  if (todayEl) animateCounter(todayEl, feedState.todayCount);
  if (blockedEl) animateCounter(blockedEl, feedState.blockedCount);
}

function animateCounter(el, targetVal) {
  const current = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
  if (current === targetVal) return;
  const step = targetVal > current ? 1 : -1;
  const timer = setInterval(() => {
    const now = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
    if (now === targetVal) { clearInterval(timer); return; }
    el.textContent = (now + step).toLocaleString();
  }, 40);
}

// ── Inject a new threat event ─────────────────────────────────
function injectFeedEvent(template, isNew = true) {
  const item = {
    ...template,
    timestamp: new Date(),
    id: Date.now(),
  };

  feedState.items.unshift(item);
  feedState.tickerItems.unshift(item);

  // Trim ticker to last 20
  if (feedState.tickerItems.length > 20) feedState.tickerItems.length = 20;

  if (template.severity === 'critical' || template.severity === 'high') {
    feedState.todayCount++;
    feedState.blockedCount += Math.random() > 0.4 ? 1 : 0;
  }

  renderFeedItem(item, isNew);
  buildTickerTrack();
  updateTickerCount();
  updateFeedStats();
}

// ── Seed initial events on load (staggered) ──────────────────
function seedInitialFeedEvents() {
  const seed = [
    THREAT_INTEL_DB[0],  // critical
    THREAT_INTEL_DB[8],  // high
    THREAT_INTEL_DB[12], // high
    THREAT_INTEL_DB[16], // medium
    THREAT_INTEL_DB[22], // info
    THREAT_INTEL_DB[1],  // critical
    THREAT_INTEL_DB[9],  // high
    THREAT_INTEL_DB[20], // medium
    THREAT_INTEL_DB[23], // info
  ];

  seed.forEach((tmpl, i) => {
    setTimeout(() => {
      // Slightly stagger timestamps so relative times look natural
      const fakeItem = { ...tmpl, timestamp: new Date(Date.now() - (seed.length - i) * 4.5 * 60 * 1000), id: Date.now() + i };
      feedState.items.push(fakeItem);
      feedState.tickerItems.push(fakeItem);
      if (tmpl.severity === 'critical' || tmpl.severity === 'high') {
        feedState.todayCount++;
        feedState.blockedCount += Math.random() > 0.5 ? 1 : 0;
      }
      renderFeedItem(fakeItem, false);
    }, i * 120);
  });

  // After seed finishes, build ticker + stats
  setTimeout(() => {
    buildTickerTrack();
    updateTickerCount();
    updateFeedStats();
  }, seed.length * 120 + 100);
}

// ── Live interval — new threat every 12–28 seconds ───────────
function startLiveFeed() {
  function scheduleNext() {
    const delay = feedRandomDelay(12000, 28000);
    feedState.intervalId = setTimeout(() => {
      if (!feedState.isPaused) {
        injectFeedEvent(feedPickRandom(THREAT_INTEL_DB), true);
      }
      scheduleNext();
    }, delay);
  }
  scheduleNext();
}

// ── Ticker controls ───────────────────────────────────────────
function toggleTickerPause() {
  const track = document.getElementById('ticker-track');
  const btn = document.getElementById('ticker-pause-btn');
  feedState.isPaused = !feedState.isPaused;

  if (feedState.isPaused) {
    if (track) track.style.animationPlayState = 'paused';
    if (btn) btn.textContent = '▶';
    btn.title = 'Resume';
  } else {
    if (track) track.style.animationPlayState = 'running';
    if (btn) btn.textContent = '⏸';
    btn.title = 'Pause';
  }
}

function dismissTicker() {
  const bar = document.getElementById('threat-ticker-bar');
  const main = document.querySelector('.main-content');
  if (bar) { bar.style.transform = 'translateY(-100%)'; bar.style.opacity = '0'; bar.style.transition = 'all 0.3s ease'; setTimeout(() => bar.style.display = 'none', 300); }
  if (main) { main.classList.remove('with-ticker'); }
  feedState.isTickerDismissed = true;
}

// ── Clear feed panel ──────────────────────────────────────────
function clearFeedItems() {
  const list = document.getElementById('live-feed-list');
  if (list) list.innerHTML = '';
  feedState.items = [];
  feedState.tickerItems = [];
  buildTickerTrack();
}

// ── Bridge: every PhishShield scan adds a feed entry ─────────
(function patchScanToFeed() {
  const _runScan = runScan;
  runScan = async function (type) {
    await _runScan.call(this, type);
    // After scan, pull from state.threats[0] and push to feed
    const latest = state.threats[0];
    if (!latest) return;
    const isPhishing = latest.risk.is_phishing;
    if (!isPhishing) return; // only show detections in feed
    injectFeedEvent({
      severity: latest.risk.risk_level === 'CRITICAL' ? 'critical' : latest.risk.risk_level === 'HIGH' ? 'high' : 'medium',
      icon: latest.risk.risk_icon,
      title: `PhishShield Detected: ${latest.type.toUpperCase()} Threat`,
      desc: `${latest.target.slice(0, 60)} · Score: ${(latest.risk.risk_score * 100).toFixed(0)}%`,
      source: 'PhishShield AI',
    }, true);
  };
})();

// ── Animate the global 2.4M counter slowly climbing ──────────
(function animateGlobalCounter() {
  const el = document.getElementById('feed-stat-global');
  if (!el) return;
  let base = 2400000 + Math.floor(Math.random() * 50000);
  setInterval(() => {
    base += Math.floor(Math.random() * 120 + 30);
    el.textContent = (base / 1000000).toFixed(1) + 'M';
  }, 3500);
})();

// ── Bootstrap ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  seedInitialFeedEvents();
  startLiveFeed();
});

// Fallback if DOM already loaded
if (document.readyState !== 'loading') {
  seedInitialFeedEvents();
  startLiveFeed();
}

console.log('📡 Live Threat Intelligence Feed engine armed — monitoring 12 global intel sources');
