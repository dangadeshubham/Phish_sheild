"""
PhishShield Domain Similarity & Homoglyph Detection Engine
Detects domain spoofing through edit distance analysis and Unicode homoglyph detection.
"""

import re
from typing import Any, Dict, List, Optional

# Unicode homoglyph mappings (characters that look similar)
HOMOGLYPH_MAP = {
    'a': ['а', 'ɑ', 'α', 'ạ', 'ä', 'à', 'á', 'â', 'ã', 'å'],
    'b': ['Ь', 'ḃ', 'ɓ', 'ƀ'],
    'c': ['с', 'ç', 'ć', 'ĉ', 'ċ'],
    'd': ['ԁ', 'ḋ', 'ɗ', 'đ'],
    'e': ['е', 'ë', 'é', 'è', 'ê', 'ẹ', 'ė', 'ę'],
    'f': ['ƒ'],
    'g': ['ɡ', 'ĝ', 'ğ', 'ġ', 'ģ'],
    'h': ['һ', 'ĥ', 'ħ'],
    'i': ['і', 'ı', 'ì', 'í', 'î', 'ï', 'ĩ', 'ɪ', 'ị', 'ł'],
    'j': ['ϳ', 'ĵ'],
    'k': ['κ', 'ḳ', 'ḵ'],
    'l': ['ӏ', 'ĺ', 'ļ', 'ľ', 'ŀ', '1', '|'],
    'm': ['м', 'ṁ'],
    'n': ['п', 'ñ', 'ń', 'ņ', 'ŋ'],
    'o': ['о', 'ö', 'ó', 'ò', 'ô', 'õ', 'ọ', '0', 'ø'],
    'p': ['р', 'ṗ'],
    'q': ['ԛ'],
    'r': ['г', 'ŕ', 'ř'],
    's': ['ѕ', 'ś', 'š', 'ş', '$', '5'],
    't': ['τ', 'ṫ', 'ţ', 'ŧ'],
    'u': ['υ', 'ú', 'ù', 'û', 'ü', 'ũ', 'ụ', 'μ'],
    'v': ['ν', 'ṿ'],
    'w': ['ω', 'ẁ', 'ẃ', 'ẅ'],
    'x': ['х', 'ẋ', 'ẍ'],
    'y': ['у', 'ý', 'ÿ', 'ŷ'],
    'z': ['ź', 'ż', 'ž']
}

# Popular target domains for phishing
LEGITIMATE_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'netflix.com', 'paypal.com', 'ebay.com', 'dropbox.com', 'icloud.com',
    'outlook.com', 'office365.com', 'chase.com', 'wellsfargo.com', 'bank.com',
    'bankofamerica.com', 'citibank.com', 'usbank.com', 'americanexpress.com',
    'whatsapp.com', 'telegram.org', 'signal.org', 'zoom.us', 'slack.com',
    'github.com', 'gitlab.com', 'stackoverflow.com', 'reddit.com',
    'coinbase.com', 'binance.com', 'kraken.com', 'blockchain.com',
    'adobe.com', 'salesforce.com', 'stripe.com', 'shopify.com',
    'wordpress.com', 'godaddy.com', 'cloudflare.com', 'aws.amazon.com',
    'yahoo.com', 'aol.com', 'hotmail.com', 'live.com', 'msn.com',
    'fidelity.com', 'schwab.com', 'vanguard.com', 'robinhood.com',
    'dhl.com', 'fedex.com', 'ups.com', 'usps.com'
]

# Common typosquatting patterns
TYPO_PATTERNS = [
    ('rn', 'm'),    # rn looks like m
    ('cl', 'd'),    # cl looks like d
    ('nn', 'm'),    # nn looks like m
    ('vv', 'w'),    # vv looks like w
    ('ii', 'u'),    # ii can look like u
]


class DomainChecker:
    """
    Domain similarity and homoglyph detection engine.
    Detects domain spoofing, typosquatting, and homoglyph attacks.
    """

    def __init__(self, legitimate_domains=None):
        # type: (Optional[List[str]]) -> None
        self.name = "domain_checker"
        self.version = "1.0.0"
        self.legitimate_domains = legitimate_domains or LEGITIMATE_DOMAINS
        self.reverse_homoglyph = {}  # type: Dict[str, str]
        self._build_homoglyph_reverse_map()

    def _build_homoglyph_reverse_map(self):
        # type: () -> None
        """Build reverse mapping from homoglyph to original character."""
        for original, homoglyphs in HOMOGLYPH_MAP.items():
            for h in homoglyphs:
                self.reverse_homoglyph[h] = original

    def analyze(self, domain):
        # type: (str) -> Dict[str, Any]
        """
        Analyze a domain for spoofing and similarity to legitimate domains.

        Args:
            domain: The domain to analyze

        Returns:
            dict with score, matched domains, and reasons
        """
        # Clean domain
        domain = self._clean_domain(domain)

        # Use separate typed variables — avoids Pyre2 union-type confusion
        score = 0.0
        reasons = []  # type: List[str]
        matches = []  # type: List[Dict[str, Any]]
        homoglyph_detected = False
        typosquatting_detected = False

        # Check if it's a legitimate domain
        if domain in self.legitimate_domains:
            reasons.append("Domain is in legitimate whitelist")
            return {
                "engine": self.name, "domain": domain, "score": 0.0,
                "reasons": reasons, "matches": matches,
                "homoglyph_detected": False, "typosquatting_detected": False,
                "is_suspicious": False
            }

        # Check for homoglyph characters
        homoglyph_result = self._detect_homoglyphs(domain)
        if homoglyph_result['has_homoglyphs']:
            homoglyph_detected = True
            score = max(score, 0.9)
            reasons.append(
                "Homoglyph characters detected: {}".format(homoglyph_result['details'])
            )

        # Check similarity to legitimate domains
        similar_domains = self._find_similar_domains(domain)
        if similar_domains:
            best_match = similar_domains[0]
            for si in range(min(len(similar_domains), 5)):
                matches.append(similar_domains[si])

            # High similarity = high phishing probability
            similarity = best_match['similarity']
            if similarity >= 0.85:
                score = max(score, 0.85)
                reasons.append(
                    "Very similar to legitimate domain '{}' (similarity: {:.0%})".format(
                        best_match['domain'], similarity
                    )
                )
            elif similarity >= 0.7:
                score = max(score, 0.6)
                reasons.append(
                    "Moderately similar to '{}' (similarity: {:.0%})".format(
                        best_match['domain'], similarity
                    )
                )

        # Check for typosquatting patterns
        typosquat_result = self._detect_typosquatting(domain)
        if typosquat_result:
            typosquatting_detected = True
            score = max(score, 0.8)
            reasons.append(
                "Typosquatting pattern detected: resembles '{}'".format(typosquat_result)
            )

        # Check for brand name in subdomain
        brand_in_subdomain = self._check_brand_in_subdomain(domain)
        if brand_in_subdomain:
            score = max(score, 0.7)
            reasons.append(
                "Brand name '{}' found in subdomain".format(brand_in_subdomain)
            )

        # Check for excessive subdomain depth
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 2:
            score = max(score, 0.4)
            reasons.append(
                "Excessive subdomain depth ({} levels)".format(subdomain_count)
            )

        is_suspicious = score > 0.5
        score_rounded = int(score * 10000) / 10000.0

        return {
            "engine": self.name,
            "domain": domain,
            "score": score_rounded,
            "reasons": reasons,
            "matches": matches,
            "homoglyph_detected": homoglyph_detected,
            "typosquatting_detected": typosquatting_detected,
            "is_suspicious": is_suspicious
        }

    def _clean_domain(self, domain):
        # type: (str) -> str
        """Clean and normalize domain string."""
        domain = domain.lower().strip()
        if '://' in domain:
            parts = domain.split('://')
            domain = parts[1]
        domain = domain.split('/')[0]
        domain = domain.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain

    def _detect_homoglyphs(self, domain):
        # type: (str) -> Dict[str, Any]
        """Detect homoglyph (look-alike Unicode) characters in domain."""
        found = []  # type: List[Dict[str, Any]]
        normalized = []  # type: List[str]

        domain_chars = list(domain)
        for ci in range(len(domain_chars)):
            char = str(domain_chars[ci])
            lookup = self.reverse_homoglyph.get(char, '')
            if lookup:
                found.append({
                    'original': char,
                    'looks_like': lookup,
                    'position': len(normalized)
                })
                normalized.append(str(lookup))  # type: ignore[arg-type]
            else:
                normalized.append(str(char))  # type: ignore[arg-type]

        normalized_domain = ''.join(normalized)

        details = ''
        if found:
            detail_parts = []  # type: List[str]
            for h in found:
                orig = str(h.get('original', ''))
                like = str(h.get('looks_like', ''))
                msg = str("'" + orig + "' looks like '" + like + "'")
                detail_parts.append(msg)  # type: ignore[arg-type]
            details = '; '.join(detail_parts)

        return {
            'has_homoglyphs': len(found) > 0,
            'normalized_domain': normalized_domain,
            'details': details,
            'count': len(found)
        }

    def _find_similar_domains(self, domain):
        # type: (str) -> List[Dict[str, Any]]
        """Find legitimate domains similar to the given domain."""
        similarities = []  # type: List[Dict[str, Any]]

        # Normalize domain for comparison
        homoglyph_result = self._detect_homoglyphs(domain)
        check_domains = [domain]  # type: List[str]
        if homoglyph_result['has_homoglyphs']:
            check_domains.append(str(homoglyph_result['normalized_domain']))

        for legit_domain in self.legitimate_domains:
            for check_domain in check_domains:
                similarity = self._calculate_similarity(check_domain, legit_domain)
                if similarity > 0.5:
                    sim_rounded = int(similarity * 10000) / 10000.0
                    similarities.append({
                        'domain': legit_domain,
                        'similarity': sim_rounded,
                        'edit_distance': self._levenshtein_distance(
                            check_domain, legit_domain
                        )
                    })

        # Sort by similarity descending
        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        return similarities

    def _detect_typosquatting(self, domain):
        # type: (str) -> Optional[str]
        """Detect common typosquatting patterns."""
        base_domain = domain.split('.')[0]
        bd_chars = [str(c) for c in base_domain]  # type: List[str]

        for legit in self.legitimate_domains:
            legit_base = legit.split('.')[0]
            lb_chars = [str(c) for c in legit_base]  # type: List[str]

            # Check character swap (transposition)
            bd_len = len(bd_chars)
            for i in range(bd_len - 1):
                c_at_i = bd_chars[i]  # type: ignore[index]
                c_at_i1 = bd_chars[i + 1]  # type: ignore[index]
                parts = []  # type: List[str]
                for j in range(bd_len):
                    if j == i:
                        parts.append(c_at_i1)
                    elif j == i + 1:
                        parts.append(c_at_i)
                    else:
                        parts.append(bd_chars[j])  # type: ignore[index]
                swapped = ''.join(parts)
                if swapped == legit_base:
                    return legit

            # Check missing character (omission)
            lb_len = len(lb_chars)
            for i in range(lb_len):
                parts = []  # type: List[str]
                for j in range(lb_len):
                    if j != i:
                        parts.append(lb_chars[j])  # type: ignore[index]
                omitted = ''.join(parts)
                if omitted == base_domain:
                    return legit

            # Check double character (insertion)
            for i in range(bd_len - 1):
                if bd_chars[i] == bd_chars[i + 1]:  # type: ignore[index]
                    parts = []  # type: List[str]
                    for j in range(bd_len):
                        if j != i:
                            parts.append(bd_chars[j])  # type: ignore[index]
                    deduped = ''.join(parts)
                    if deduped == legit_base:
                        return legit

            # Check typo patterns (rn->m, cl->d, etc.)
            for pattern, replacement in TYPO_PATTERNS:
                if pattern in base_domain:
                    replaced = base_domain.replace(pattern, replacement)
                    if replaced == legit_base:
                        return legit

        return None

    def _check_brand_in_subdomain(self, domain):
        # type: (str) -> Optional[str]
        """Check if a legitimate brand name appears as a subdomain."""
        parts = domain.split('.')
        if len(parts) <= 2:
            return None

        # Join all parts except the last two as subdomains
        subdomain_parts = []  # type: List[str]
        for pi in range(len(parts) - 2):
            subdomain_parts.append(parts[pi])
        subdomains = '.'.join(subdomain_parts)

        main_part = parts[len(parts) - 2]
        for legit in self.legitimate_domains:
            brand = legit.split('.')[0]
            if brand in subdomains and brand not in main_part:
                return brand

        return None

    @staticmethod
    def _levenshtein_distance(s1, s2):
        # type: (str, str) -> int
        """Calculate Levenshtein (edit) distance between two strings."""
        if len(s1) < len(s2):
            return DomainChecker._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[len(prev_row) - 1]

    @staticmethod
    def _calculate_similarity(s1, s2):
        # type: (str, str) -> float
        """Calculate similarity ratio between two strings (0-1)."""
        distance = DomainChecker._levenshtein_distance(s1, s2)
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1 - (distance / max_len)
