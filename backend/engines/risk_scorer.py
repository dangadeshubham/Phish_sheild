"""
PhishShield Risk Scoring Engine
Combines outputs from all detection engines into a final risk assessment
with explainable AI (XAI) output.
"""


RISK_LEVELS = {
    (0.0, 0.2): {"level": "SAFE", "color": "#22c55e", "icon": "✅"},
    (0.2, 0.4): {"level": "LOW", "color": "#84cc16", "icon": "🟢"},
    (0.4, 0.6): {"level": "MEDIUM", "color": "#eab308", "icon": "🟡"},
    (0.6, 0.8): {"level": "HIGH", "color": "#f97316", "icon": "🟠"},
    (0.8, 1.01): {"level": "CRITICAL", "color": "#ef4444", "icon": "🔴"}
}

ENGINE_WEIGHTS = {
    "url_analyzer": 0.30,
    "nlp_engine": 0.25,
    "domain_checker": 0.25,
    "visual_engine": 0.20
}


class RiskScorer:
    def __init__(self):
        self.name = "risk_scorer"
        self.version = "1.0.0"

    def calculate_risk(self, engine_results: list) -> dict:
        weighted_score = 0.0
        total_weight = 0.0
        all_reasons = []
        engine_scores = {}

        for result in engine_results:
            engine = result.get("engine", "unknown")
            score = result.get("score", 0.0)
            reasons = result.get("reasons", [])
            weight = ENGINE_WEIGHTS.get(engine, 0.15)
            weighted_score += score * weight
            total_weight += weight
            all_reasons.extend(reasons)
            engine_scores[engine] = {"score": score, "weight": weight}

        final_score = weighted_score / max(total_weight, 0.01)

        # Multi-engine consensus boost
        high_scores = sum(1 for r in engine_results if r.get("score", 0) > 0.6)
        if high_scores >= 3:
            final_score = min(final_score * 1.2, 1.0)
            all_reasons.append("Multiple engines agree on high risk")

        clamped = min(max(final_score, 0.0), 1.0)
        final_score = int(clamped * 10000) / 10000.0
        risk_info = self._get_risk_level(final_score)

        # Deduplicate reasons
        seen = set()
        unique_reasons = []
        for r in all_reasons:
            if r not in seen:
                seen.add(r)
                unique_reasons.append(r)

        return {
            "risk_score": final_score,
            "risk_level": risk_info["level"],
            "risk_color": risk_info["color"],
            "risk_icon": risk_info["icon"],
            "is_phishing": final_score > 0.6,
            "engine_scores": engine_scores,
            "reasons": list(unique_reasons[0:min(len(unique_reasons), 15)]),  # type: ignore[index]
            "explanation": self._generate_explanation(
                final_score, risk_info, engine_scores, unique_reasons
            ),
            "recommendation": self._get_recommendation(final_score)
        }

    def _get_risk_level(self, score):
        for (low, high), info in RISK_LEVELS.items():
            if low <= score < high:
                return info
        return RISK_LEVELS[(0.8, 1.01)]

    def _generate_explanation(self, score, risk_info, engines, reasons):
        parts = [f"Risk Assessment: {risk_info['level']} ({score:.0%} confidence).\n"]
        if score > 0.6:
            parts.append("⚠️ This content exhibits strong phishing indicators:\n")
        for i, reason in enumerate(reasons[:5], 1):
            parts.append(f"  {i}. {reason}")
        parts.append(f"\nEngine breakdown:")
        for eng, data in engines.items():
            parts.append(f"  • {eng}: {data['score']:.0%}")
        return "\n".join(parts)

    def _get_recommendation(self, score):
        if score > 0.8:
            return "🚨 CRITICAL: Do NOT interact. Report as phishing immediately."
        elif score > 0.6:
            return "⚠️ HIGH RISK: Avoid clicking links or providing information. Verify sender through official channels."
        elif score > 0.4:
            return "⚡ CAUTION: Some suspicious indicators found. Verify the source before proceeding."
        elif score > 0.2:
            return "ℹ️ LOW RISK: Minor indicators detected. Exercise normal caution."
        return "✅ SAFE: No significant phishing indicators detected."
