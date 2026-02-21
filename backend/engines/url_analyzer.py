"""
PhishShield URL Analyzer Engine v2.0
Enhanced with:
- Stronger scoring for non-HTTPS, suspicious TLDs, shorteners
- Homoglyph brand impersonation detection
- Blacklist simulation (Google Safe Browsing / PhishTank style patterns)
- Domain age heuristics
- Financial brand impersonation detection
- Improved cross-category risk amplification (up to 1.5x)
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from typing import Any, List
from urllib.parse import urlparse, parse_qs

# Suspicious keywords commonly found in phishing URLs
SUSPICIOUS_TOKENS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'update', 'secure',
    'account', 'banking', 'confirm', 'password', 'credential', 'authenticate',
    'wallet', 'payment', 'paypal', 'apple', 'microsoft', 'google', 'amazon',
    'netflix', 'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'icloud', 'outlook', 'office365', 'wellsfargo', 'chase', 'bankofamerica',
    'citibank', 'usbank', 'submit', 'validate', 'restore', 'unlock', 'suspend',
    'unusual', 'activity', 'limited', 'expire', 'urgent', 'immediately',
    'click', 'here', 'free', 'gift', 'prize', 'winner', 'congratulations',
    'security', 'alert', 'warning', 'notice', 'action', 'required',
    # New financial/billing tokens
    'invoice', 'billing', 'refund', 'overdue', 'unpaid', 'kyc', 'aadhaar',
    'pan', 'parcel', 'delivery', 'shipment', 'claim', 'reward', 'otp',
]

# High-risk TLDs (scoring increased in v2)
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online',
    '.site', '.website', '.space', '.pw', '.cc', '.buzz', '.icu', '.rest',
    '.fit', '.cam', '.surf', '.monster', '.quest', '.cyou', '.cfd', '.lol',
]

# Free-tier / highest-abused TLDs (extra penalty)
HIGH_RISK_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq']

# Known URL shorteners
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'tiny.cc', 'shorturl.at', 'cutt.ly', 'rb.gy', 'v.gd',
    'qr.ae', 'short.io', 'bl.ink', 'snip.ly',
]

# Legitimate brand names and their canonical domains
BRAND_DOMAINS = {
    'paypal':   'paypal.com',
    'google':   'google.com',
    'apple':    'apple.com',
    'microsoft':'microsoft.com',
    'amazon':   'amazon.com',
    'netflix':  'netflix.com',
    'facebook': 'facebook.com',
    'instagram':'instagram.com',
    'twitter':  'twitter.com',
    'linkedin': 'linkedin.com',
    'chase':    'chase.com',
    'wellsfargo':'wellsfargo.com',
    'bankofamerica':'bankofamerica.com',
    'citibank': 'citibank.com',
    'usbank':   'usbank.com',
    'dropbox':  'dropbox.com',
    'icloud':   'icloud.com',
    'coinbase': 'coinbase.com',
    'binance':  'binance.com',
    'dhl':      'dhl.com',
    'fedex':    'fedex.com',
    'ups':      'ups.com',
    'usps':     'usps.com',
    'irs':      'irs.gov',
}

# Homoglyph substitutions for brand attack detection
BRAND_HOMOGLYPHS = {
    '0': 'o', 'o': '0',
    '1': 'l', 'l': '1', 'i': 'l',
    '3': 'e', 'e': '3',
    '4': 'a', 'a': '4',
    '5': 's', 's': '5',
    '6': 'b', 'b': '6',
    '7': 't', 't': '7',
    '8': 'b',
    'rn': 'm', 'cl': 'd', 'vv': 'w', 'nn': 'm',
}

# Patterns that simulate blacklist hits (known phishing URL patterns)
BLACKLIST_PATTERNS = [
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',           # Raw IP
    r'https?://[^/]+(paypal|apple|microsoft|amazon|google|chase|irs)[^/]*\.(tk|ml|ga|cf|gq|xyz|top|pw)',
    r'secure.{0,15}login|login.{0,15}secure',                   # Fake secure-login combos
    r'(verify|update|confirm).{0,20}(account|identity|info)',   # Verify-account pattern
    r'https?://[^/]+/[^/]*(phish|hack|steal|malware)',          # Obvious malicious paths
    r'https?://[^/]*(-secure|-login|-verify|-update)\.',        # Hyphenated brand tricks
]


class URLAnalyzer:
    """
    Comprehensive URL analysis engine v2.0 for phishing detection.
    Extracts 40+ features and applies multi-layer scoring.
    """

    def __init__(self):
        self.name = "url_analyzer"
        self.version = "2.0.0"

    def analyze(self, url: str) -> dict[str, Any]:
        try:
            features = self.extract_features(url)
            score, reasons, confidence = self._calculate_score(features, url)

            return {
                "engine": self.name,
                "score": int(score * 10000) / 10000.0,
                "features": features,
                "reasons": reasons,
                "confidence": confidence,
                "is_suspicious": score > 0.5
            }
        except Exception as e:
            return {
                "engine": self.name,
                "score": 0.5,
                "features": {},
                "reasons": [f"Analysis error: {str(e)}"],
                "confidence": "LOW",
                "is_suspicious": True
            }

    def extract_features(self, url: str) -> dict[str, Any]:
        """Extract 40+ features from a URL for phishing detection."""
        parsed = urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        path = parsed.path
        query = parsed.query

        features: dict[str, Any] = {}

        # === Length-based features ===
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)

        # === Character-based features ===
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')
        features['underscore_count'] = url.count('_')
        features['slash_count'] = url.count('/')
        features['at_sign'] = 1 if '@' in url else 0
        # ── @ Redirection trick detection ────────────────────────────────
        # Pattern: http://trusted.com@evil.com/path → browser visits evil.com
        # Everything before @ is ignored by browsers; real destination is after @
        features['at_redirect_trick'] = 0
        features['at_spoof_domain']   = ''   # the fake/decoy domain shown before @
        features['at_real_domain']    = ''   # the actual destination domain after @
        if '@' in url:
            # Strip scheme to isolate authority portion
            authority_part = re.sub(r'^https?://', '', url).split('/')[0]
            if '@' in authority_part:
                at_idx = authority_part.rfind('@')
                decoy  = authority_part[:at_idx]    # type: ignore[index]  # e.g. "google.com"
                real   = authority_part[at_idx+1:]  # type: ignore[index]  # e.g. "evil.com"
                # Confirm it's a redirect trick: decoy looks like a domain/brand
                # (contains a dot or a known brand keyword) and real differs
                known_brands = ['google', 'paypal', 'apple', 'microsoft', 'amazon',
                                'facebook', 'instagram', 'netflix', 'linkedin',
                                'chase', 'wellsfargo', 'bankofamerica', 'coinbase']
                decoy_looks_like_domain = '.' in decoy or any(b in decoy.lower() for b in known_brands)
                if decoy_looks_like_domain and real and decoy.lower() != real.lower():
                    features['at_redirect_trick'] = 1
                    features['at_spoof_domain']   = decoy
                    features['at_real_domain']    = real
                else:
                    # Plain @ present but not a clear redirect trick
                    features['at_sign'] = 1
        features['double_slash_redirect'] = 1 if '//' in url[8:] else 0  # type: ignore[index]
        features['digit_count'] = sum(c.isdigit() for c in url)
        features['special_char_count'] = sum(c in string.punctuation for c in url)
        features['digit_ratio'] = features['digit_count'] / max(len(url), 1)
        features['letter_ratio'] = sum(c.isalpha() for c in url) / max(len(url), 1)

        # === Domain-based features ===
        features['has_ip_address'] = 1 if self._has_ip_address(domain) else 0
        features['subdomain_count'] = max(domain.count('.') - 1, 0)
        features['has_suspicious_tld'] = 1 if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0
        features['has_high_risk_tld'] = 1 if any(domain.endswith(tld) for tld in HIGH_RISK_TLDS) else 0
        features['is_shortened'] = 1 if any(s in domain for s in URL_SHORTENERS) else 0
        features['domain_has_digits'] = 1 if any(c.isdigit() for c in domain.split('.')[0]) else 0
        features['has_port'] = 1 if ':' in domain and not domain.startswith('[') else 0

        # === Entropy features ===
        features['url_entropy'] = self._calculate_entropy(url)
        features['domain_entropy'] = self._calculate_entropy(domain)
        features['path_entropy'] = self._calculate_entropy(path) if path else 0

        # === Token-based features ===
        url_lower = url.lower()
        suspicious_found = [token for token in SUSPICIOUS_TOKENS if token in url_lower]
        features['suspicious_token_count'] = len(suspicious_found)
        features['suspicious_tokens_found'] = suspicious_found[:5]  # type: ignore[index]

        # === Protocol features ===
        features['uses_https'] = 1 if parsed.scheme == 'https' else 0
        features['has_www'] = 1 if domain.startswith('www.') else 0

        # === Path features ===
        features['path_depth'] = path.count('/') - 1 if path else 0
        features['has_file_extension'] = 1 if re.search(r'\.\w{2,4}$', path) else 0
        features['has_php'] = 1 if '.php' in path.lower() else 0
        features['has_suspicious_extension'] = 1 if re.search(
            r'\.(exe|zip|rar|js|vbs|scr|bat|cmd|ps1|dmg|apk)$', path.lower()
        ) else 0

        # === Query features ===
        query_params = parse_qs(query)
        features['query_param_count'] = len(query_params)
        features['has_encoded_chars'] = 1 if '%' in url else 0

        # ── Suspicious URL parameters ─────────────────────────────────────
        SUSPICIOUS_PARAMS = {'session', 'token', 'auth', 'redirect', 'redir', 'return',
                             'returnurl', 'next', 'callback', 'ref', 'go', 'goto',
                             'dest', 'destination', 'forward', 'target', 'continue'}
        found_sus_params: List[str] = [
            p for p in query_params if p.lower() in SUSPICIOUS_PARAMS
        ]
        features['has_suspicious_params'] = 1 if found_sus_params else 0
        features['suspicious_params_found'] = found_sus_params

        # ── IDN / Punycode homograph detection ────────────────────────────
        # Punycode domains (xn--) are used to encode unicode chars that visually
        # mimic Latin characters (e.g. pаypal.com with Cyrillic 'а')
        features['has_punycode'] = 1 if 'xn--' in domain.lower() else 0
        features['idn_decoded'] = ''
        if features['has_punycode']:
            try:
                decoded = domain.encode('ascii').decode('idna')
                features['idn_decoded'] = decoded
            except Exception:
                features['idn_decoded'] = domain

        # ── Look-alike subdomain spoofing ─────────────────────────────────
        # Pattern: paypal.login.secure-domain.com  — brand in subdomain, not TLD
        features['subdomain_brand_spoof'] = 0
        features['subdomain_spoof_brand'] = ''
        domain_parts = domain.lower().replace('www.', '').split('.')
        if len(domain_parts) >= 3:
            # Root domain is last two parts; everything else is subdomain
            subdomains = '.'.join(domain_parts[:-2])  # type: ignore[index]
            root_domain = '.'.join(domain_parts[-2:])  # type: ignore[index]
            for brand_name in BRAND_DOMAINS:
                # Brand in subdomain but root domain is NOT the brand
                if brand_name in subdomains and brand_name not in root_domain:
                    features['subdomain_brand_spoof'] = 1
                    features['subdomain_spoof_brand'] = brand_name
                    break

        # === Statistical features ===
        features['consecutive_consonants_max'] = self._max_consecutive_consonants(domain)
        features['vowel_ratio'] = self._vowel_ratio(domain)

        # === NEW v2: Brand impersonation / homoglyph ===
        brand_hit = self._detect_brand_impersonation(domain, url_lower)
        features['brand_impersonation'] = brand_hit['brand'] or ''
        features['brand_similarity'] = brand_hit['similarity']
        features['homoglyph_brand_attack'] = 1 if brand_hit['homoglyph'] else 0

        # === NEW v2: Blacklist pattern match ===
        features['blacklist_pattern_match'] = 1 if self._check_blacklist(url) else 0

        # === NEW v2: Domain age heuristic ===
        features['likely_new_domain'] = 1 if self._likely_new_domain(domain) else 0

        return features

    def _calculate_score(self, features: dict[str, Any], url: str) -> tuple[float, list[str], str]:
        """Calculate phishing risk score. Returns (score, reasons, confidence)."""
        score = 0.0
        reasons = []
        weights = {
            'length': 0.0,
            'structure': 0.0,
            'tokens': 0.0,
            'entropy': 0.0,
            'domain': 0.0,
            'blacklist': 0.0,
            'brand': 0.0,
        }

        # ── Blacklist / Pattern match (highest priority) ──────────────────
        if features['blacklist_pattern_match']:
            weights['blacklist'] += 0.9
            reasons.append("⛔ Matches known phishing URL pattern (Safe Browsing / PhishTank rules)")

        # ── Brand impersonation ───────────────────────────────────────────
        if features['brand_impersonation']:
            brand = features['brand_impersonation']
            sim = features['brand_similarity']
            if features['homoglyph_brand_attack']:
                weights['brand'] += 0.85
                reasons.append(f"🔡 Homoglyph brand attack: domain mimics '{brand}' using lookalike characters")
            elif sim >= 0.8:
                weights['brand'] += 0.75
                reasons.append(f"🏷️ High-confidence brand impersonation: '{brand}' ({sim:.0%} similarity)")
            else:
                weights['brand'] += 0.5
                reasons.append(f"🏷️ Possible brand impersonation: '{brand}' detected in URL")

        # ── Length analysis ───────────────────────────────────────────────
        if features['url_length'] > 75:
            weights['length'] += 0.25
            reasons.append(f"📏 Unusually long URL ({features['url_length']} chars)")
        if features['url_length'] > 150:
            weights['length'] += 0.25
            reasons.append("📏 Extremely long URL — common obfuscation tactic")

        # ── Domain analysis ───────────────────────────────────────────────
        if features['has_ip_address']:
            weights['domain'] += 0.85
            reasons.append("🌐 URL uses raw IP address instead of domain name")
        if features['subdomain_count'] > 2:
            weights['domain'] += 0.4
            reasons.append(f"🌐 Excessive subdomains ({features['subdomain_count']}) — common in free-hosting phishing")
        if features['has_high_risk_tld']:
            weights['domain'] += 0.55          # Increased from 0.4
            reasons.append("⚠️ High-risk free TLD (.tk/.ml/.ga/.cf/.gq) — heavily abused by phishers")
        elif features['has_suspicious_tld']:
            weights['domain'] += 0.40
            reasons.append("⚠️ Suspicious top-level domain")
        if features['is_shortened']:
            weights['domain'] += 0.40          # Increased from 0.3
            reasons.append("🔗 URL shortener detected — hides true destination, high phishing indicator")
        if features['domain_has_digits']:
            weights['domain'] += 0.2
            reasons.append("🔢 Domain contains digits (brand-mimicry pattern)")
        if features['has_port']:
            weights['domain'] += 0.35
            reasons.append("🔌 Non-standard port in URL")
        if features['likely_new_domain']:
            weights['domain'] += 0.25
            reasons.append("🆕 Domain appears newly registered (age heuristic) — high phishing risk")

        # ── Structure analysis ────────────────────────────────────────────
        # ── @ Redirection trick / @ in URL ───────────────────────────────
        if features['at_redirect_trick']:
            weights['structure'] += 0.90
            spoof  = features['at_spoof_domain']
            real   = features['at_real_domain']
            reasons.append(
                f"🚨 URL Redirection Trick: displays '{spoof}' before '@' but actually "
                f"sends browser to '{real}' — classic phishing deception"
            )
        elif features['at_sign']:
            weights['structure'] += 0.60
            reasons.append("⚠️ @ symbol in URL — browser treats everything before @ as credentials "
                           "and redirects to the domain after it")
        if features['double_slash_redirect']:
            weights['structure'] += 0.4
            reasons.append("// redirect detected in URL path")
        if features['hyphen_count'] > 3:
            weights['structure'] += 0.3
            reasons.append(f"Excessive hyphens ({features['hyphen_count']}) — phishing domain pattern")
        if features['dot_count'] > 4:
            weights['structure'] += 0.3
            reasons.append(f"Excessive dots ({features['dot_count']})")
        if not features['uses_https']:
            weights['structure'] += 0.30       # Increased from 0.2
            reasons.append("🔓 No HTTPS — unencrypted connection, strong phishing signal")

        # ── Token analysis ────────────────────────────────────────────────
        if features['suspicious_token_count'] > 0:
            token_score = min(features['suspicious_token_count'] * 0.15, 0.85)
            weights['tokens'] += token_score
            tokens_str = ', '.join(features.get('suspicious_tokens_found', [])[:4])
            reasons.append(f"🏷️ Suspicious keywords in URL: {tokens_str}")

        # ── Suspicious URL parameters ─────────────────────────────────────
        if features['has_suspicious_params']:
            weights['structure'] += 0.30
            params_str = ', '.join(features['suspicious_params_found'][:4])
            reasons.append(f"🔑 Suspicious URL parameters detected: {params_str} — used in phishing redirect chains")

        # ── IDN / Punycode homograph ──────────────────────────────────────
        if features['has_punycode']:
            weights['domain'] += 0.70
            decoded = features['idn_decoded']
            reasons.append(
                f"🌐 Punycode/IDN domain detected (xn--) — used to create unicode look-alike domains"
                + (f": decoded as '{decoded}'" if decoded else "")
            )

        # ── Subdomain brand spoofing ──────────────────────────────────────
        if features['subdomain_brand_spoof']:
            spoof_brand = features['subdomain_spoof_brand']
            weights['brand'] += 0.80
            reasons.append(
                f"🎭 Subdomain spoofing: '{spoof_brand}' used as subdomain to appear legitimate "
                f"(e.g. {spoof_brand}.login.evil.com) — actual domain is different"
            )

        # ── Combined HIGH RISK rule: brand impersonation + suspicious tokens ─
        sim = features['brand_similarity']
        tok = features['suspicious_token_count']
        if sim > 0.75 and tok > 0:
            score_boost = min(score * 1.35, 1.0)
            if score_boost > score:
                score = score_boost
                brand_name = features['brand_impersonation']
                reasons.append(
                    f"🚨 HIGH RISK: Brand impersonation ('{brand_name}', {sim:.0%} similarity) "
                    f"combined with {tok} suspicious keyword(s) — strong phishing signal"
                )

        # ── Entropy analysis ──────────────────────────────────────────────
        if features['url_entropy'] > 4.5:
            weights['entropy'] += 0.3
            reasons.append(f"🔀 High URL entropy ({features['url_entropy']:.2f}) — possible character obfuscation")
        if features['domain_entropy'] > 3.8:
            weights['entropy'] += 0.3
            reasons.append(f"🔀 High domain entropy ({features['domain_entropy']:.2f}) — random/generated domain")

        # ── Other indicators ──────────────────────────────────────────────
        if features['has_encoded_chars']:
            weights['structure'] += 0.15
            reasons.append("Encoded characters (%xx) in URL")
        if features['has_suspicious_extension']:
            weights['structure'] += 0.55
            reasons.append("🗂️ Suspicious file extension (.exe/.apk/.ps1 etc.)")
        if features['consecutive_consonants_max'] > 4:
            weights['domain'] += 0.2
            reasons.append("Domain contains unusual consonant clusters")

        # ── Weighted final score ──────────────────────────────────────────
        category_weights = {
            'blacklist': 0.25,
            'brand':     0.20,
            'domain':    0.22,
            'structure': 0.15,
            'tokens':    0.10,
            'entropy':   0.05,
            'length':    0.03,
        }

        for category, w in category_weights.items():
            score += min(weights[category], 1.0) * w

        score = min(max(score, 0.0), 1.0)

        # ── Multi-category amplification ──────────────────────────────────
        flagged = sum(1 for v in weights.values() if v > 0.2)
        if flagged >= 4:
            score = min(score * 1.5, 1.0)
            reasons.append("🚨 Multiple high-risk categories triggered simultaneously")
        elif flagged >= 3:
            score = min(score * 1.3, 1.0)
            reasons.append("⚠️ Multiple risk categories triggered")

        # Confidence rating
        if score > 0.75 and flagged >= 3:
            confidence = "HIGH"
        elif score > 0.4 or flagged >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return score, reasons, confidence

    # ── New v2 helpers ─────────────────────────────────────────────────────

    def _detect_brand_impersonation(self, domain: str, url_lower: str) -> dict:
        """Detect brand impersonation via exact match, substring, and homoglyph."""
        domain_clean = domain.lower().replace('www.', '')
        result = {'brand': None, 'similarity': 0.0, 'homoglyph': False}

        for brand, canonical in BRAND_DOMAINS.items():
            canonical_domain = canonical.split('.')[0]
            # Already the real domain — skip
            if domain_clean == canonical or domain_clean.endswith('.' + canonical):
                return result

            # Check if brand keyword exists in domain but domain isn't the legit one
            if brand in domain_clean and canonical not in domain_clean:
                result = {'brand': brand, 'similarity': 0.85, 'homoglyph': False}
                return result

            # Homoglyph check: normalize digits/chars and compare
            normalized = self._normalize_homoglyphs(domain_clean)
            if brand in normalized and brand not in domain_clean:
                result = {'brand': brand, 'similarity': 0.95, 'homoglyph': True}
                return result

            # Check brand in path/query (e.g., fake login pages)
            if brand in url_lower and canonical not in domain_clean:
                result = {'brand': brand, 'similarity': 0.65, 'homoglyph': False}

        return result

    @staticmethod
    def _normalize_homoglyphs(text: str) -> str:
        """Normalize common digit/char substitutions used in homoglyph attacks."""
        result = text
        for char, replacement in BRAND_HOMOGLYPHS.items():
            result = result.replace(char, replacement)
        return result

    @staticmethod
    def _check_blacklist(url: str) -> bool:
        """Check URL against known phishing pattern signatures."""
        for pattern in BLACKLIST_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _likely_new_domain(domain: str) -> bool:
        """
        Heuristic to flag likely newly-registered domains.
        Real implementation would call WHOIS; here we use structural signals:
        - Random-looking domain with suspicious TLD
        - Short domain with high digit ratio
        - Hyphenated + suspicious TLD combo
        """
        base = domain.split('.')[0] if '.' in domain else domain
        digit_ratio = sum(c.isdigit() for c in base) / max(len(base), 1)
        has_suspicious = any(domain.endswith(tld) for tld in HIGH_RISK_TLDS)
        hyphen_and_suspicious = '-' in domain and any(
            domain.endswith(tld) for tld in SUSPICIOUS_TLDS
        )
        return (digit_ratio > 0.3 and has_suspicious) or hyphen_and_suspicious

    # ── Existing helpers ───────────────────────────────────────────────────

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
        return int(entropy * 10000) / 10000.0

    @staticmethod
    def _has_ip_address(domain: str) -> bool:
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}$|'
            r'^\[([0-9a-fA-F:]+)\]$|'
            r'^0x[0-9a-fA-F]+$'
        )
        return bool(ip_pattern.match(domain))

    @staticmethod
    def _max_consecutive_consonants(text: str) -> int:
        vowels = set('aeiouAEIOU')
        max_count = 0
        current = 0
        for c in text:
            if c.isalpha() and c not in vowels:
                current += 1
                max_count = max(max_count, current)
            else:
                current = 0
        return max_count

    @staticmethod
    def _vowel_ratio(text: str) -> float:
        if not text:
            return 0.0
        vowels = sum(1 for c in text if c.lower() in 'aeiou')
        letters = sum(1 for c in text if c.isalpha())
        return vowels / max(letters, 1)
