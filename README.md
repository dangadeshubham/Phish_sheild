# 🛡️ PhishShield - Real-Time AI/ML-Based Phishing Detection System

![PhishShield](https://img.shields.io/badge/PhishShield-v1.0-blue?style=for-the-badge)
![AI Powered](https://img.shields.io/badge/AI-Powered-green?style=for-the-badge)
![Real Time](https://img.shields.io/badge/Real--Time-Detection-red?style=for-the-badge)

## 🎯 Overview

PhishShield is a comprehensive, real-time AI/ML-powered phishing detection and prevention system that protects users across **Email**, **SMS**, **Messaging platforms**, and **Websites**. It combines NLP deep learning, computer vision, and advanced URL analysis to detect and prevent phishing attacks — including zero-day threats.

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        PhishShield Architecture                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Chrome Ext.  │  │  Email API   │  │   SMS API    │  │  Web Hook  │  │
│  │  (Browser)   │  │  (IMAP/API)  │  │  (Twilio)    │  │  (Custom)  │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                 │                 │                 │          │
│         └────────────┬────┴────────┬────────┴────────┬───────┘          │
│                      │             │                 │                   │
│              ┌───────▼─────────────▼─────────────────▼──────────┐       │
│              │           API Gateway (Cloud Functions)           │       │
│              │         /api/scan/url  /api/scan/email            │       │
│              │         /api/scan/sms  /api/scan/website          │       │
│              └───────────────────┬───────────────────────────────┘       │
│                                  │                                       │
│              ┌───────────────────▼───────────────────────────────┐       │
│              │            Detection Engine Pipeline               │       │
│              │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐ │       │
│              │  │  NLP    │ │  URL    │ │ Visual  │ │ Domain │ │       │
│              │  │ Engine  │ │Analyzer │ │ Engine  │ │Checker │ │       │
│              │  │(BERT/   │ │(Feature │ │  (CNN)  │ │(Edit   │ │       │
│              │  │ LSTM)   │ │Extract) │ │         │ │Distance│ │       │
│              │  └────┬────┘ └────┬────┘ └────┬────┘ └───┬────┘ │       │
│              │       └──────┬────┴──────┬────┴──────┬───┘      │       │
│              │              │           │           │           │       │
│              │       ┌──────▼───────────▼───────────▼──────┐   │       │
│              │       │      Risk Scoring Engine             │   │       │
│              │       │   (Weighted Ensemble + XAI)          │   │       │
│              │       └──────────────┬──────────────────────┘   │       │
│              └──────────────────────┼──────────────────────────┘       │
│                                     │                                   │
│              ┌──────────────────────▼──────────────────────────┐       │
│              │              Gemini API (LLM Analysis)          │       │
│              │         Natural Language Threat Explanation      │       │
│              └──────────────────────┬──────────────────────────┘       │
│                                     │                                   │
│         ┌───────────────────────────┼───────────────────────────┐       │
│         │                           │                           │       │
│  ┌──────▼──────┐  ┌────────────────▼────────────┐  ┌──────────▼────┐  │
│  │  Firebase   │  │        BigQuery             │  │   Dashboard   │  │
│  │ Real-time   │  │    Threat Analytics         │  │   (Web UI)    │  │
│  │   Alerts    │  │    & Logging                │  │               │  │
│  └─────────────┘  └────────────────────────────┘  └───────────────┘  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🔍 Detection Capabilities

| Threat Type | Detection Method | Model/Technique |
|---|---|---|
| Phishing Emails | NLP Deep Learning | BERT / LSTM |
| Malicious URLs | Feature Engineering | Random Forest + Neural Net |
| SMS Phishing | Text Classification | BERT Fine-tuned |
| Fake Websites | Visual Analysis | CNN (ResNet50) |
| Domain Spoofing | String Analysis | Levenshtein + Homoglyph |
| Zero-day Attacks | Anomaly Detection | Isolation Forest + Gemini |
| Redirect Chains | Chain Analysis | Graph-based Traversal |

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Python 3.9+
- Google Cloud SDK
- Chrome Browser (for extension)

### Installation

```bash
# Clone the repository
git clone https://github.com/dangadeshubham/Phish_sheild.git
cd Phish_sheild

# Install dashboard dependencies
cd dashboard
npm install
npm run dev

# Install backend dependencies  
cd ../backend
pip install -r requirements.txt
python app.py

# Load Chrome Extension
# Open chrome://extensions → Enable Developer Mode → Load Unpacked → Select /extension folder
```

## 📁 Project Structure

```
phishshield/
├── dashboard/           # Web Dashboard (HTML/CSS/JS)
│   ├── index.html       # Main dashboard
│   ├── css/             # Stylesheets
│   ├── js/              # Dashboard logic
│   └── assets/          # Images & icons
├── backend/             # Python Backend API
│   ├── app.py           # Flask API server
│   ├── engines/         # Detection engines
│   │   ├── nlp_engine.py
│   │   ├── url_analyzer.py
│   │   ├── visual_engine.py
│   │   └── domain_checker.py
│   ├── models/          # ML Models
│   ├── utils/           # Utilities
│   └── requirements.txt
├── extension/           # Chrome Extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── background.js
│   └── content.js
├── ml-pipeline/         # ML Training Pipeline
│   ├── train_nlp.py
│   ├── train_url.py
│   ├── train_visual.py
│   └── datasets/
├── cloud/               # GCP Deployment
│   ├── cloudfunctions/
│   ├── terraform/
│   └── deploy.sh
├── docs/                # Documentation
│   ├── architecture.md
│   ├── api-reference.md
│   ├── ml-models.md
│   └── deployment.md
└── README.md
```

## 🧠 ML Models & Training

### 1. NLP Phishing Detection (BERT)
- **Dataset**: Nazario phishing corpus, APWG eCrime dataset
- **Architecture**: BERT-base fine-tuned for binary classification
- **Features**: Email subject, body text, sender patterns
- **Accuracy**: ~97.3%

### 2. URL Analysis (Ensemble)
- **Dataset**: PhishTank, OpenPhish, Alexa Top 1M
- **Architecture**: Random Forest + Neural Network ensemble
- **Features**: 30+ URL features (entropy, length, special chars, etc.)
- **Accuracy**: ~96.8%

### 3. Visual Website Classification (CNN)
- **Dataset**: Custom screenshots of legitimate vs phishing sites
- **Architecture**: ResNet50 transfer learning
- **Features**: Screenshot image analysis
- **Accuracy**: ~94.5%

## 📊 API Reference

### Scan URL
```http
POST /api/scan/url
Content-Type: application/json

{
  "url": "https://suspicious-site.com/login"
}
```

### Scan Email
```http
POST /api/scan/email
Content-Type: application/json

{
  "subject": "Urgent: Verify your account",
  "body": "Click here to verify...",
  "sender": "support@g00gle.com",
  "headers": {}
}
```

### Response Format
```json
{
  "risk_score": 0.92,
  "risk_level": "CRITICAL",
  "is_phishing": true,
  "detections": [
    {
      "engine": "url_analyzer",
      "score": 0.95,
      "reasons": ["Suspicious domain pattern", "High URL entropy"]
    },
    {
      "engine": "nlp_engine", 
      "score": 0.89,
      "reasons": ["Urgency language detected", "Credential request pattern"]
    }
  ],
  "explanation": "This URL mimics a legitimate banking site using homoglyph characters...",
  "recommendation": "Do not click. Report as phishing."
}
```

## ☁️ Google Cloud Deployment

1. **Vertex AI** — Model training & serving
2. **Cloud Functions** — Serverless API endpoints
3. **Firebase** — Real-time alerts & dashboard hosting
4. **BigQuery** — Threat logging & analytics
5. **Cloud Run** — Container deployment
6. **Gemini API** — Natural language threat analysis

## 🔮 Future Enhancements

- [ ] Multi-language phishing detection
- [ ] Browser fingerprinting analysis
- [ ] Social media phishing detection
- [ ] Federated learning for privacy-preserving training
- [ ] Mobile app (React Native)
- [ ] Threat intelligence feed integration
- [ ] Automated phishing takedown requests

## 👥 Team

Made with <3

Shubham Dangade
Alok kale
Arya Pathak
Athrva Bawage

## 📄 License

MIT License — see [LICENSE](LICENSE) for details
