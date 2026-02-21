"""
PhishShield NLP Engine v2.0
Enhanced with:
- Financial scam detection (invoice, payment failed, billing)
- Sender-domain mismatch detection
- Brand impersonation / spoofed domain detection
- Region-specific SMS keywords (KYC, Aadhaar, PAN, parcel, TRAI)
- Tech support & remote access vishing patterns
- Urgency + link + financial request triple-trigger boost
- Improved confidence scoring
"""

import re
import math
from collections import Counter
from typing import Any, Dict, List, Tuple

# ── Phishing patterns ──────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\basap\b', r'\bright\s+now\b',
    r'\bact\s+now\b', r'\bdon\'?t\s+delay\b', r'\bexpir(e|es|ed|ing)\b',
    r'\blast\s+chance\b', r'\blimited\s+time\b', r'\btime\s+sensitive\b',
    r'\bhurry\b', r'\bfinal\s+(warning|notice)\b', r'\bwithin\s+\d+\s+(hour|day|minute)s?\b',
    r'\bsuspend(ed)?\b', r'\bterminat(e|ed|ion)\b', r'\brestrict(ed)?\b',
    r'\bdeadline\b', r'\bcritical\b', r'\baction\s+required\b', r'\bdo\s+not\s+ignore\b',
]

CREDENTIAL_PATTERNS = [
    r'\b(verify|confirm|update|validate)\s+(your\s+)?(account|identity|information|details)\b',
    r'\b(enter|provide|submit|type)\s+(your\s+)?(password|credentials|login|ssn|credit\s+card)\b',
    r'\b(sign|log)\s*(in|on)\s+(to\s+)?(verify|confirm|update)\b',
    r'\bclick\s+(here|below|the\s+link)\b',
    r'\b(reset|change|update)\s+password\b',
    r'\bunusual\s+(activity|sign[- ]?in|login)\b',
    r'\bsecurity\s+(alert|warning|notice|update)\b',
    r'\bverification\s+(required|needed|code)\b',
    r'\bconfirm\s+(your\s+)?identity\b',
    r'\benter\s+(your\s+)?(otp|one[- ]time\s+password|pin)\b',
]

SOCIAL_ENGINEERING_PATTERNS = [
    r'\b(dear\s+)?(valued\s+)?(customer|user|member|client)\b',
    r'\b(we\s+)?(have\s+)?(detected|noticed|found)\s+(suspicious|unusual|unauthorized)\b',
    r'\bif\s+you\s+(did\s+)?not\s+(authorize|recognize|initiate)\b',
    r'\byour\s+account\s+(has\s+been|will\s+be|is)\s+(locked|suspended|restricted|disabled)\b',
    r'\bwin(ner)?\b.*\b(prize|gift|reward|lottery)\b',
    r'\bcongratulations\b',
    r'\bfree\s+(gift|offer|trial)\b',
    r'\binheritance\b',
    r'\b(prince|princess|royalty|diplomat)\b',
    r'\bmillion\s+dollars?\b',
]

IMPERSONATION_PATTERNS = [
    r'\b(support|help|service)\s*@',
    r'\b(team|department|division)\s+at\s',
    r'\b(official|authorized|certified)\s+(notice|communication|message)\b',
    r'\bdo\s+not\s+reply\b',
    r'\bautomated\s+message\b',
    r'\bthis\s+is\s+(a\s+)?(reminder|notification|alert)\b',
]

# ── NEW v2: Financial scam patterns ────────────────────────────────────────
FINANCIAL_SCAM_PATTERNS = [
    r'\binvoice\s+(#?\d+|attached|due|overdue|unpaid)\b',
    r'\bpayment\s+(failed|declined|pending|overdue|required)\b',
    r'\bbilling\s+(issue|problem|error|update)\b',
    r'\b(outstanding|unpaid)\s+balance\b',
    r'\byour\s+(subscription|plan)\s+(has\s+)?(expired|renewal|charge)\b',
    r'\bcharge\s+of\s+\$[\d,.]+\b',
    r'\btransaction\s+(failed|declined|blocked|flagged)\b',
    r'\brefund\s+(pending|approved|processed|request)\b',
    r'\bbank\s+(transfer|wire|deposit)\b',
    r'\b(gift\s+card|google\s+play|itunes|amazon)\s+(code|card|payment)\b',
    r'\bcrypto|bitcoin|ethereum|usdt\s+(transfer|payment|wallet)\b',
]

# ── NEW v2: Region-specific SMS scam keywords (India-focused + global) ─────
REGIONAL_SMS_PATTERNS = [
    # India-specific
    r'\bkyc\s*(expired?|update|pending|verification)\b',
    r'\baadhaar\s*(link|update|verify|blocked)\b',
    r'\bpan\s*(card)?\s*(update|verify|link|blocked)\b',
    r'\btrai\s*(block|sim|disconnect)\b',
    r'\bsim\s+(blocked|suspended|deactivat)\b',
    r'\b(upi|paytm|phonepe|gpay|bhim)\s*(fraud|blocked|verify)\b',
    r'\bincome\s+tax\s+(notice|refund|demand)\b',
    # Global parcel/delivery
    r'\bparcel\s+(held|on\s+hold|detention|pending\s+customs)\b',
    r'\bcustoms\s+(fee|duty|clearance|charge)\b',
    r'\bredelivery\s+(fee|charge|attempt)\b',
    # Financial  
    r'\b(loan|emi)\s+(approved|offer|overdue|pending)\b',
    r'\binsurance\s+(claim|expire|renewal)\b',
    r'\b(cashback|reward|bonus)\s+(credited|expire|claim)\b',
]

# ── NEW v2: Tech support / remote access vishing ───────────────────────────
TECH_SUPPORT_PATTERNS = [
    r'\bremote\s+(access|control|session|desktop)\b',
    r'\b(install|download|open)\s+(anydesk|teamviewer|ultraviewer|remote\s*pc)\b',
    r'\bshare\s+(your\s+)?(screen|access\s+code|session\s+code|control)\b',
    r'\btech(nical)?\s+support\b',
    r'\bwindows\s+(license|has\s+expired|activation)\b',
    r'\b(your\s+)?computer\s+(is\s+)?(hacked|infected|virus|compromised)\b',
    r'\bcall\s+(this\s+)?(number|toll[- ]?free)\b',
    r'\b(microsoft|apple|google)\s+(support|technician|engineer)\b',
    r'\ballow\s+(me|us)\s+to\s+(access|connect|fix)\b',
    r'\bdo\s+not\s+(close|shut|turn\s+off)\b',
]

LEGITIMATE_INDICATORS = [
    r'\bunsubscribe\b',
    r'\bprivacy\s+policy\b',
    r'\bterms\s+(of|and)\s+(service|use)\b',
    r'\bmanage\s+(your\s+)?preferences\b',
    r'\bview\s+in\s+browser\b',
    r'\bopt[- ]?out\b',
]

# Known brands used by impersonators
IMPERSONATED_BRANDS: List[str] = [
    'paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'facebook',
    'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'usbank', 'dhl', 'fedex', 'usps', 'ups', 'irs', 'sbi', 'hdfc',
    'icici', 'axis', 'airtel', 'jio', 'vodafone', 'trai',
]


class NLPEngine:
    """
    NLP-based phishing text analysis engine v2.0.
    Multi-channel: email, SMS, voice transcripts.
    """

    def __init__(self) -> None:
        self.name = "nlp_engine"
        self.version = "2.0.0"

    def analyze(self, text: str, subject: str = "", sender: str = "", content_type: str = "email") -> Dict[str, Any]:
        reasons: List[str] = []
        categories: Dict[str, Any] = {}
        features: Dict[str, Any] = {}

        full_text = str(subject + " " + text).strip()

        if not full_text:
            reasons.append("Empty text content")
            return {
                "engine": self.name, "content_type": content_type,
                "score": 0.0, "reasons": reasons, "categories": categories,
                "features": features, "is_suspicious": False, "confidence": "LOW"
            }

        features = self._extract_features(full_text, sender)

        # Core pattern analysis — each returns (float, List[str])
        urgency_score,       urgency_reasons       = self._analyze_patterns(full_text, URGENCY_PATTERNS, "Urgency")
        credential_score,    credential_reasons    = self._analyze_patterns(full_text, CREDENTIAL_PATTERNS, "Credential Request")
        social_score,        social_reasons        = self._analyze_patterns(full_text, SOCIAL_ENGINEERING_PATTERNS, "Social Engineering")
        impersonation_score, impersonation_reasons = self._analyze_patterns(full_text, IMPERSONATION_PATTERNS, "Impersonation")
        financial_score,     financial_reasons     = self._analyze_patterns(full_text, FINANCIAL_SCAM_PATTERNS, "Financial Scam")

        # Sender & subject analysis
        sender_score,  sender_reasons  = self._analyze_sender(sender, full_text)
        subject_score: float = 0.0
        subject_reasons_list: List[str] = []
        if subject:
            subject_score, subject_reasons_list = self._analyze_subject(subject)

        linguistic_score, linguistic_reasons = self._analyze_linguistic_features(features)

        # SMS-specific: regional keywords
        sms_regional_score: float = 0.0
        sms_regional_reasons: List[str] = []
        if content_type == "sms":
            sms_regional_score, sms_regional_reasons = self._analyze_patterns(
                full_text, REGIONAL_SMS_PATTERNS, "Regional SMS Scam"
            )

        # Tech support / vishing
        tech_support_score: float = 0.0
        tech_support_reasons: List[str] = []
        if content_type in ("sms", "voice"):
            tech_support_score, tech_support_reasons = self._analyze_patterns(
                full_text, TECH_SUPPORT_PATTERNS, "Tech Support Scam"
            )

        # Brand impersonation in text body
        brand_score, brand_reasons = self._detect_brand_impersonation(full_text, sender)

        # Build categories
        categories = {
            "urgency":            {"score": urgency_score,       "indicators": urgency_reasons},
            "credential_request": {"score": credential_score,    "indicators": credential_reasons},
            "social_engineering": {"score": social_score,        "indicators": social_reasons},
            "impersonation":      {"score": impersonation_score, "indicators": impersonation_reasons},
            "financial_scam":     {"score": financial_score,     "indicators": financial_reasons},
            "sender_analysis":    {"score": sender_score,        "indicators": sender_reasons},
            "linguistic":         {"score": linguistic_score,    "indicators": linguistic_reasons},
            "brand_impersonation":{"score": brand_score,         "indicators": brand_reasons},
        }  # type: Dict[str, Any]
        if subject:
            categories["subject_analysis"] = {"score": subject_score, "indicators": subject_reasons_list}  # type: ignore[assignment]
        if content_type == "sms":
            categories["regional_keywords"] = {"score": sms_regional_score, "indicators": sms_regional_reasons}  # type: ignore[assignment]
            categories["tech_support"]       = {"score": tech_support_score, "indicators": tech_support_reasons}  # type: ignore[assignment]

        # Legitimate indicator reduction
        legit_count = sum(
            1 for p in LEGITIMATE_INDICATORS if re.search(p, full_text, re.IGNORECASE)
        )
        legit_reduction = min(legit_count * 0.05, 0.15)

        # Weighted scoring by channel
        if content_type == "sms":
            weights = {
                'urgency': 0.20, 'credential': 0.20, 'social': 0.10,
                'financial': 0.15, 'sender': 0.10, 'linguistic': 0.05,
                'regional': 0.10, 'tech': 0.05, 'brand': 0.05,
            }  # type: Dict[str, float]
        else:  # email / voice
            weights = {
                'urgency': 0.15, 'credential': 0.20, 'social': 0.10,
                'impersonation': 0.08, 'financial': 0.15, 'sender': 0.12,
                'subject': 0.05, 'linguistic': 0.08, 'brand': 0.07,
            }

        score = (
            urgency_score      * weights.get('urgency', 0.0) +
            credential_score   * weights.get('credential', 0.0) +
            social_score       * weights.get('social', 0.0) +
            impersonation_score* weights.get('impersonation', 0.0) +
            financial_score    * weights.get('financial', 0.0) +
            sender_score       * weights.get('sender', 0.0) +
            subject_score      * weights.get('subject', 0.0) +
            linguistic_score   * weights.get('linguistic', 0.0) +
            brand_score        * weights.get('brand', 0.0) +
            sms_regional_score * weights.get('regional', 0.0) +
            tech_support_score * weights.get('tech', 0.0)
        )

        score = max(score - legit_reduction, 0.0)

        # Multi-category amplification
        flagged_scores = [
            urgency_score, credential_score, social_score,
            financial_score, sender_score, brand_score
        ]
        flagged = sum(1 for s in flagged_scores if s > 0.3)
        if flagged >= 4:
            score = min(score * 1.5, 1.0)
            reasons.append("🚨 Multiple phishing categories simultaneously triggered")
        elif flagged >= 3:
            score = min(score * 1.4, 1.0)
            reasons.append("⚠️ Multiple phishing indicator categories detected")

        # ── NEW: Triple threat boost (urgency + link + financial request) ──
        has_link = bool(re.search(r'https?://', full_text))
        if urgency_score > 0.3 and has_link and financial_score > 0.3:
            score = min(score * 1.3, 1.0)
            reasons.append("🚨 Triple threat: urgency + embedded link + financial request detected")

        final_score = min(max(score, 0.0), 1.0)
        final_score = int(final_score * 10000) / 10000.0
        is_suspicious = final_score > 0.5

        # Compile top reasons — flatten all reason lists explicitly
        all_reasons: List[str] = []
        for r in urgency_reasons:       all_reasons.append(r)
        for r in credential_reasons:    all_reasons.append(r)
        for r in social_reasons:        all_reasons.append(r)
        for r in impersonation_reasons: all_reasons.append(r)
        for r in financial_reasons:     all_reasons.append(r)
        for r in sender_reasons:        all_reasons.append(r)
        for r in linguistic_reasons:    all_reasons.append(r)
        for r in brand_reasons:         all_reasons.append(r)
        for r in sms_regional_reasons:  all_reasons.append(r)
        for r in tech_support_reasons:  all_reasons.append(r)
        top_reasons: List[str] = list(all_reasons)[:10]  # type: ignore[index]
        for r in reasons:
            top_reasons.append(r)

        confidence = "HIGH" if final_score > 0.75 and flagged >= 3 else "MEDIUM" if final_score > 0.4 else "LOW"

        return {
            "engine": self.name,
            "content_type": content_type,
            "score": final_score,
            "reasons": top_reasons,
            "categories": categories,
            "features": features,
            "is_suspicious": is_suspicious,
            "confidence": confidence,
        }

    # ── Feature extraction ─────────────────────────────────────────────────

    def _extract_features(self, text, sender=""):
        # type: (str, str) -> Dict[str, Any]
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        return {
            "word_count":        len(words),
            "char_count":        len(text),
            "sentence_count":    len([s for s in sentences if s.strip()]),
            "avg_word_length":   sum(len(w) for w in words) / max(len(words), 1),
            "exclamation_count": text.count('!'),
            "question_count":    text.count('?'),
            "uppercase_ratio":   sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "url_count":         len(re.findall(r'https?://\S+', text)),
            "email_count":       len(re.findall(r'\S+@\S+\.\S+', text)),
            "phone_count":       len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text)),
            "money_references":  len(re.findall(r'\$[\d,]+(\.\d{2})?|\d+\s*(dollars?|USD|£|€|₹|INR)', text)),
            "has_html":          1 if re.search(r'<[^>]+>', text) else 0,
            "link_text_mismatch":self._check_link_text_mismatch(text),
            "sender_domain_free":1 if re.search(r'@(gmail|yahoo|hotmail|outlook|aol)\.', sender) else 0,
        }

    def _analyze_patterns(self, text: str, patterns: List[str], category: str) -> Tuple[float, List[str]]:
        matches: List[str] = []
        for pattern in patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            if found:
                first = found[0]
                match_text: str = first if isinstance(first, str) else str(first[0])  # type: ignore[index]
                matches.append(match_text.strip())
        if not matches:
            return 0.0, []
        pat_score: float = min(len(matches) * 0.25, 1.0)
        pat_reasons: List[str] = []
        for mi in range(min(len(matches), 3)):
            pat_reasons.append(str(category) + ": '" + str(matches[mi]) + "' detected")
        return pat_score, pat_reasons

    def _analyze_sender(self, sender: str, full_text: str = "") -> Tuple[float, List[str]]:
        if not sender:
            return 0.0, []

        sender_score: float = 0.0
        sender_rsns: List[str] = []

        # Display name brand spoofing
        if re.search(r'[<>]', sender):
            display_name = re.match(r'([^<]+)<', sender)
            if display_name:
                name: str = display_name.group(1).strip()
                for brand in IMPERSONATED_BRANDS:
                    if brand in name.lower():  # type: ignore[operator]
                        email_part = re.search(r'<(.+)>', sender)
                        if email_part and brand not in email_part.group(1).lower():
                            sender_score += 0.75  # type: ignore[operator]
                            sender_rsns.append(
                                f"\U0001f6a8 Sender display name contains '{brand}' but email domain doesn't match \u2014 spoofing!"
                            )

        # Suspicious digit patterns
        if re.search(r'\d{3,}@', sender):
            sender_score += 0.3
            sender_rsns.append("Sender has many digits before @ — auto-generated address")

        # No-reply from unknown domains
        if re.search(r'(noreply|no-reply|donotreply).*@(?!google|apple|microsoft|amazon)',
                     sender, re.IGNORECASE):
            sender_score += 0.2
            sender_rsns.append("No-reply address from unrecognized domain")

        # ── Sender-domain mismatch detection ─────────────────────────────
        sender_domain: str = ""
        m = re.search(r'@([^\s>]+)', sender)
        if m:
            sender_domain = str(m.group(1)).lower()

        # Check if body mentions a brand but sender domain doesn't match
        if sender_domain:
            sd = sender_domain  # explicit str binding for type checker
            for brand in IMPERSONATED_BRANDS:
                if brand in full_text.lower():
                    expected: List[str] = [brand + '.com', brand + '.org', brand + '.gov']
                    known_esps: List[str] = [
                        'mailchimp', 'sendgrid', 'constantcontact', 'hubspot',
                        'salesforce', 'marketo', 'klaviyo', 'mailgun'
                    ]
                    domain_match = any(part in sd for part in expected)
                    esp_match    = any(esp  in sd for esp  in known_esps)
                    if not domain_match and not esp_match:
                        sender_score += 0.35  # type: ignore[operator]
                        sender_rsns.append(
                            f"📧 Sender-domain mismatch: email mentions '{brand}' but sent from '{sd}'"
                        )
                        break

        return min(sender_score, 1.0), sender_rsns

    def _analyze_subject(self, subject):
        # type: (str) -> Tuple[float, List[str]]
        score = 0.0
        reasons = []  # type: List[str]

        if subject.isupper():
            score += 0.3
            reasons.append("Subject line is ALL CAPS")
        if subject.count('!') > 1:
            score += 0.2
            reasons.append("Multiple exclamation marks in subject")
        if re.search(r'\b(urgent|action\s+required|verify|suspended|locked|frozen|invoice|billing)\b',
                     subject, re.IGNORECASE):
            score += 0.4
            reasons.append("Subject contains urgency/action keywords")
        if re.search(r'\bre:\s', subject, re.IGNORECASE) and len(subject) < 20:
            score += 0.15
            reasons.append("Short reply-format subject (fake thread)")

        return min(score, 1.0), reasons

    def _analyze_linguistic_features(self, features):
        # type: (Dict[str, Any]) -> Tuple[float, List[str]]
        score = 0.0
        reasons = []  # type: List[str]

        if features['uppercase_ratio'] > 0.3:
            score += 0.2
            reasons.append("Excessive use of uppercase letters")
        if features['exclamation_count'] > 3:
            score += 0.15
            reasons.append(f"Excessive exclamation marks ({features['exclamation_count']})")
        if features['url_count'] > 3:
            score += 0.2
            reasons.append(f"Multiple embedded URLs ({features['url_count']})")
        if features['money_references'] > 0:
            score += 0.15
            reasons.append("Contains monetary references")
        if features['link_text_mismatch']:
            score += 0.4
            reasons.append("Link display text doesn't match actual URL (deceptive)")
        if features['has_html'] and features['url_count'] > 0:
            score += 0.1
            reasons.append("HTML content with embedded links")

        return min(score, 1.0), reasons

    def _detect_brand_impersonation(self, text, sender=""):
        # type: (str, str) -> Tuple[float, List[str]]
        """Detect brand impersonation in text body."""
        score = 0.0
        reasons = []  # type: List[str]
        text_lower = text.lower()
        sender_lower = sender.lower()

        for brand in IMPERSONATED_BRANDS:
            if brand in text_lower:
                # High confidence: brand in text but not in sender domain
                if sender_lower and '@' in sender_lower:
                    s_domain = sender_lower.split('@')[-1]
                    if brand not in s_domain:
                        score += 0.45
                        reasons.append(f"🏷️ Brand impersonation: '{brand.title()}' mentioned in body but not sender domain")
                        break
                # Brand + credential request in same message
                if re.search(r'(verify|confirm|sign.?in|login|password|account)', text_lower):
                    score += 0.35
                    reasons.append(f"🏷️ '{brand.title()}' impersonation + credential request")
                    break

        return min(score, 1.0), reasons

    @staticmethod
    def _check_link_text_mismatch(text):
        # type: (str) -> bool
        pattern = r'<a[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
        matches = re.findall(pattern, text, re.IGNORECASE)
        for href, display in matches:
            if re.match(r'https?://', display):
                href_domain = re.search(r'://([^/]+)', href)
                display_domain = re.search(r'://([^/]+)', display)
                if href_domain and display_domain:
                    if href_domain.group(1) != display_domain.group(1):
                        return True
        return False
