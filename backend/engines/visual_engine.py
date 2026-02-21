"""
PhishShield Visual Analysis Engine v2.0
Enhanced with:
- OTP and credit card input field detection
- External form action detection
- Stronger brand impersonation scoring
- Fake login page fingerprinting
- Expanded brand list (banks, crypto, delivery)
- Confidence scoring
"""

import re
from typing import Any, Dict, List, Optional


SPOOFED_BRANDS = {
    'google': {
        'logos': ['google-logo', 'google_logo', 'google.svg', 'google-icon'],
        'elements': ['gmail', 'google account', 'sign in with google', 'google drive', 'google pay']
    },
    'microsoft': {
        'logos': ['microsoft-logo', 'msft-logo', 'office-logo', 'ms-logo'],
        'elements': ['microsoft', 'outlook', 'office 365', 'office365', 'windows live', 'azure']
    },
    'apple': {
        'logos': ['apple-logo', 'apple-icon'],
        'elements': ['apple id', 'icloud', 'find my', 'apple store']
    },
    'facebook': {
        'logos': ['facebook-logo', 'fb-logo', 'meta-logo'],
        'elements': ['facebook', 'log into facebook', 'meta', 'instagram login', 'connect with facebook']
    },
    'paypal': {
        'logos': ['paypal-logo', 'paypal-icon'],
        'elements': ['paypal', 'pay with paypal', 'paypal checkout', 'log in to paypal']
    },
    'amazon': {
        'logos': ['amazon-logo', 'amazon-icon'],
        'elements': ['amazon', 'sign-in', 'amazon prime', 'aws console', 'amazon web services']
    },
    'netflix': {
        'logos': ['netflix-logo'],
        'elements': ['netflix', 'continue watching', 'your netflix account']
    },
    'chase': {
        'logos': ['chase-logo'],
        'elements': ['chase bank', 'jpmorgan chase', 'sign in to chase']
    },
    'wellsfargo': {
        'logos': ['wellsfargo-logo'],
        'elements': ['wells fargo', 'sign on to wells fargo']
    },
    'coinbase': {
        'logos': ['coinbase-logo'],
        'elements': ['coinbase', 'sign into coinbase', 'coinbase wallet']
    },
    'metamask': {
        'logos': ['metamask-logo', 'fox-logo'],
        'elements': ['metamask', 'connect wallet', 'seed phrase', 'recovery phrase', 'private key']
    },
    'dhl': {
        'logos': ['dhl-logo'],
        'elements': ['dhl express', 'track your shipment', 'dhl delivery']
    },
    'sbi': {
        'logos': ['sbi-logo'],
        'elements': ['state bank of india', 'sbi net banking', 'onlinesbi']
    },
    'hdfc': {
        'logos': ['hdfc-logo'],
        'elements': ['hdfc bank', 'hdfc netbanking', 'hdfc credit card']
    },
}

# Patterns for dangerous form inputs
DANGEROUS_INPUT_PATTERNS = [
    r'type=["\']?password["\']?',
    r'name=["\']?(pin|otp|cvv|cvc|card.?number|pan.[card]?|aadhaar|ssn|routing)["\']?',
    r'placeholder=["\']?(enter (your )?(otp|pin|cvv|card number|credit card))',
    r'autocomplete=["\']?(cc-number|cc-csc|cc-exp)',
]


class VisualEngine:
    """
    HTML visual analysis engine v2.0.
    Detects fake login pages, credential harvesting forms, and brand impersonation.
    """

    def __init__(self):
        # type: () -> None
        self.name = "visual_engine"
        self.version = "2.0.0"

    def analyze(self, html_content="", url="", page_title=""):
        # type: (str, str, str) -> Dict[str, Any]
        reasons = []       # type: List[str]
        brand_detected = None  # type: Optional[str]
        features = {}      # type: Dict[str, Any]

        if not html_content:
            reasons.append("No HTML content available")
            return {
                "engine": self.name, "score": 0.3, "reasons": reasons,
                "brand_detected": brand_detected, "features": features,
                "is_suspicious": False, "confidence": "LOW"
            }

        html = html_content.lower()
        score = 0.0

        # ── Form analysis ─────────────────────────────────────────────
        has_password = bool(re.search(r'type=["\']?password["\']?', html))
        has_otp      = bool(re.search(r'(otp|one.?time.?pass|verification\s*code)', html))
        has_cc       = bool(re.search(r'(credit.?card|debit.?card|card.?number|cvv|cvc|cc-number)', html))
        has_pan      = bool(re.search(r'(pan\s*card|aadhaar|ssn|social.?security)', html))
        has_pin      = bool(re.search(r'name=["\']?pin["\']?|placeholder=["\']?.*pin', html))
        has_cred_form = sum(1 for p in ['login', 'password', 'username', 'email', 'signin'] if p in html) >= 2

        # External form action
        form_actions = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)', html)
        form_external = False
        if url and form_actions:
            host = url.replace('https://', '').replace('http://', '').split('/')[0]
            form_external = any(
                a.startswith('http') and host and host not in a
                for a in form_actions
            )

        hidden_count = len(re.findall(r'type\s*=\s*["\']hidden["\']', html))

        # ── Dangerous input field scoring ─────────────────────────────
        if has_password:
            score += 0.20
            reasons.append("🔑 Password input field detected")
        if has_otp:
            score += 0.30
            reasons.append("🔢 OTP / one-time code input field detected")
        if has_cc:
            score += 0.45
            reasons.append("💳 Credit / debit card input field detected — high phishing risk")
        if has_pan:
            score += 0.40
            reasons.append("🪪 Sensitive ID field (PAN/Aadhaar/SSN) detected")
        if has_pin:
            score += 0.30
            reasons.append("🔐 PIN input field detected")
        if has_cred_form:
            score += 0.20
            reasons.append("📋 Credential collection form detected")
        if form_external:
            score += 0.55
            reasons.append("🚨 Form submits credentials to external domain — data exfiltration risk!")
        if hidden_count > 3:
            score += 0.20
            reasons.append(f"🕵️ Multiple hidden fields ({hidden_count}) — possible data collection")

        # ── Dangerous input pattern scanning ─────────────────────────
        for pat in DANGEROUS_INPUT_PATTERNS:
            if re.search(pat, html, re.IGNORECASE) and not has_cc and not has_pin:
                score += 0.15
                reasons.append(f"⚠️ Sensitive input pattern detected")
                break

        # ── Brand spoofing ============================================
        for brand_name, info in SPOOFED_BRANDS.items():
            element_hits = sum(1 for e in info['elements'] if e in html)
            logo_hits    = sum(1 for lg in info['logos'] if lg in html)
            title_hit    = 1 if brand_name in page_title.lower() else 0
            total_hits   = element_hits + logo_hits + title_hit

            if total_hits >= 2 and url and brand_name not in url.lower():
                penalty = min(0.4 + element_hits * 0.1, 0.75)
                score += penalty
                reasons.append(f"🏷️ Brand impersonation detected: '{brand_name.title()}' (elements: {element_hits}, logos: {logo_hits})")
                brand_detected = brand_name
                break

        # ── Fake login page fingerprint ───────────────────────────────
        login_keywords = sum(1 for kw in ['forgot password', 'remember me', 'keep me signed in',
                                           'create account', 'sign up', 'register'] if kw in html)
        if login_keywords >= 2 and has_password and not any(  # type: ignore[index]
            legit in (url or '') for legit in ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
        ):
            score += 0.25
            reasons.append("🔒 Fake login page fingerprint (login UI on non-legitimate domain)")

        # ── Page structure analysis ───────────────────────────────────
        is_minimal = '<nav' not in html and '<footer' not in html and len(html) < 5000
        if is_minimal and has_password:
            score += 0.25
            reasons.append("📄 Minimal page (no nav/footer) with login form — classic phishing template")
        if '<iframe' in html:
            score += 0.15
            reasons.append("Iframe embedded — potential content injection")

        # ── JavaScript threat indicators ──────────────────────────────
        scripts = ' '.join(re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL))
        if re.search(r'(eval\s*\(|unescape\s*\(|atob\s*\(|fromCharCode)', scripts):
            score += 0.25
            reasons.append("🔀 Obfuscated JavaScript (eval/atob/fromCharCode)")
        if re.search(r'(onkeypress|onkeydown|addEventListener.*key)', scripts):
            score += 0.60
            reasons.append("⌨️ Keylogger pattern detected in JavaScript!")
        if re.search(r'(clipboard|navigator\.clipboard|document\.execCommand.*copy)', scripts):
            score += 0.40
            reasons.append("📋 Clipboard access detected — possible crypto wallet drainer")
        if 'oncontextmenu' in html and 'return false' in html:
            score += 0.15
            reasons.append("Right-click disabled on page")

        # ── Anti-analysis indicators ──────────────────────────────────
        if re.search(r'(disable|prevent)\s*(select|copy|paste|inspect)', html, re.IGNORECASE):
            score += 0.20
            reasons.append("🚫 Anti-inspection measures detected")

        clamped = min(max(score, 0.0), 1.0)
        final_score = int(clamped * 10000) / 10000.0
        is_suspicious = final_score > 0.5
        confidence = "HIGH" if final_score > 0.75 else "MEDIUM" if final_score > 0.4 else "LOW"

        return {
            "engine": self.name,
            "score": final_score,
            "reasons": reasons,
            "brand_detected": brand_detected,
            "features": {
                "has_password": has_password,
                "has_otp": has_otp,
                "has_credit_card": has_cc,
                "has_sensitive_id": has_pan,
                "form_external": form_external,
                "hidden_count": hidden_count,
                "brand_impersonated": brand_detected,
            },
            "is_suspicious": is_suspicious,
            "confidence": confidence,
        }
