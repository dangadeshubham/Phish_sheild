"""
PhishShield Backend API Server
Flask-based REST API for real-time phishing detection.
"""

import json
import re
import sys
import os
import traceback
from datetime import datetime

# Ensure the backend directory is in the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify  # type: ignore[import-untyped]
from flask_cors import CORS  # type: ignore[import-untyped]

from engines.url_analyzer import URLAnalyzer  # type: ignore[import-not-found]
from engines.nlp_engine import NLPEngine  # type: ignore[import-not-found]
from engines.domain_checker import DomainChecker  # type: ignore[import-not-found]
from engines.visual_engine import VisualEngine  # type: ignore[import-not-found]
from engines.risk_scorer import RiskScorer  # type: ignore[import-not-found]

app = Flask(__name__)
CORS(app)

# Initialize engines
url_analyzer = URLAnalyzer()
nlp_engine = NLPEngine()
domain_checker = DomainChecker()
visual_engine = VisualEngine()
risk_scorer = RiskScorer()

# In-memory threat log (use BigQuery in production)
threat_log = []  # type: ignore[var-annotated]


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "service": "PhishShield API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "engines": {
            "url_analyzer": url_analyzer.version,
            "nlp_engine": nlp_engine.version,
            "domain_checker": domain_checker.version,
            "visual_engine": visual_engine.version,
        }
    })


@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        url_result = url_analyzer.analyze(url)
        domain = url.split('://')[1].split('/')[0] if '://' in url else url.split('/')[0]
        domain_result = domain_checker.analyze(domain)

        results = [url_result, domain_result]
        risk = risk_scorer.calculate_risk(results)

        entry = {
            "type": "url", "target": url,
            "risk": risk, "timestamp": datetime.utcnow().isoformat()
        }
        threat_log.append(entry)

        return jsonify({
            "success": True,
            "scan_type": "url",
            "target": url,
            **risk,
            "details": {"url_analysis": url_result, "domain_analysis": domain_result}
        })
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500


@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    data = request.get_json()
    subject = data.get('subject', '')
    body = data.get('body', '')
    sender = data.get('sender', '')
    if not body and not subject:
        return jsonify({"error": "Email subject or body is required"}), 400

    try:
        nlp_result = nlp_engine.analyze(body, subject, sender, "email")
        results = [nlp_result]

        # Extract and scan URLs from body
        found_urls = re.findall(r'https?://\S+', body)
        url_results = []
        for i in range(min(len(found_urls), 5)):
            u = found_urls[i]
            ur = url_analyzer.analyze(u)
            url_results.append(ur)
            results.append(ur)

        risk = risk_scorer.calculate_risk(results)

        entry = {
            "type": "email", "target": sender or subject[:50],
            "risk": risk, "timestamp": datetime.utcnow().isoformat()
        }
        threat_log.append(entry)

        return jsonify({
            "success": True, "scan_type": "email",
            **risk,
            "details": {
                "nlp_analysis": nlp_result,
                "url_analyses": url_results
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/sms', methods=['POST'])
def scan_sms():
    data = request.get_json()
    message = data.get('message', '')
    sender = data.get('sender', '')
    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        nlp_result = nlp_engine.analyze(message, "", sender, "sms")
        results = [nlp_result]

        found_urls = re.findall(r'https?://\S+', message)
        for i in range(min(len(found_urls), 3)):
            results.append(url_analyzer.analyze(found_urls[i]))

        risk = risk_scorer.calculate_risk(results)

        entry = {
            "type": "sms", "target": sender or message[:50],
            "risk": risk, "timestamp": datetime.utcnow().isoformat()
        }
        threat_log.append(entry)

        return jsonify({"success": True, "scan_type": "sms", **risk,
                        "details": {"nlp_analysis": nlp_result}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/scan/website', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get('url', '')
    html = data.get('html_content', '')
    title = data.get('page_title', '')
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        url_result = url_analyzer.analyze(url)
        domain = url.split('://')[1].split('/')[0] if '://' in url else url.split('/')[0]
        domain_result = domain_checker.analyze(domain)
        visual_result = visual_engine.analyze(html, url, title)

        results = [url_result, domain_result, visual_result]
        risk = risk_scorer.calculate_risk(results)

        entry = {
            "type": "website", "target": url,
            "risk": risk, "timestamp": datetime.utcnow().isoformat()
        }
        threat_log.append(entry)

        return jsonify({"success": True, "scan_type": "website", **risk,
                        "details": {
                            "url_analysis": url_result,
                            "domain_analysis": domain_result,
                            "visual_analysis": visual_result
                        }})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/threats', methods=['GET'])
def get_threats():
    limit = request.args.get('limit', 100, type=int)
    start = max(len(threat_log) - limit, 0)
    recent = []
    for i in range(len(threat_log) - 1, start - 1, -1):
        recent.append(threat_log[i])
    return jsonify({
        "threats": recent,
        "total": len(threat_log)
    })


@app.route('/api/stats', methods=['GET'])
def get_stats():
    total = len(threat_log)
    phishing_flags = []  # type: ignore[var-annotated]
    by_type = {}  # type: ignore[var-annotated]
    for i in range(total):
        t = threat_log[i]
        risk_data = t.get('risk')
        if isinstance(risk_data, dict) and risk_data.get('is_phishing'):
            phishing_flags.append(True)
        tp = str(t.get('type', 'unknown'))
        by_type[tp] = by_type.get(tp, 0) + 1
    phishing_count = len(phishing_flags)
    safe_count = total - phishing_count
    rate = float(phishing_count) / float(max(total, 1)) * 100.0
    return jsonify({
        "total_scans": total,
        "phishing_detected": phishing_count,
        "safe_count": safe_count,
        "detection_rate": int(rate * 10) / 10.0,
        "by_type": by_type
    })


if __name__ == '__main__':
    print("🛡️  PhishShield API Server starting...")
    print("📡 Endpoints:")
    print("   POST /api/scan/url      - Scan a URL")
    print("   POST /api/scan/email    - Scan an email")
    print("   POST /api/scan/sms      - Scan an SMS")
    print("   POST /api/scan/website  - Scan a website")
    print("   GET  /api/threats       - Get threat log")
    print("   GET  /api/stats         - Get statistics")
    print("   GET  /api/health        - Health check")
    app.run(host='0.0.0.0', port=5000, debug=True)
