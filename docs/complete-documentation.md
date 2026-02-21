# PhishShield — Complete Technical Documentation

## 1. System Architecture Diagram Explanation

### High-Level Architecture

PhishShield uses a **microservices-based architecture** with 4 layers:

#### Input Layer (Data Collection)
- **Chrome Extension**: Monitors browsing in real-time, scans URLs and page content
- **Email API Gateway**: Receives emails via IMAP/API integration
- **SMS API (Twilio)**: Processes incoming SMS messages for smishing detection
- **Webhooks**: Custom integrations for messaging platforms (Slack, Teams, etc.)

#### Processing Layer (Detection Engines)
- **API Gateway**: Cloud Functions receive requests and route to engines
- **4 Detection Engines** run in parallel:
  - NLP Engine (BERT/LSTM) — text classification
  - URL Analyzer — feature extraction & ML classification
  - Domain Checker — homoglyph & similarity analysis
  - Visual Engine (CNN) — screenshot/HTML analysis
- **Risk Scorer**: Weighted ensemble combining all engine outputs
- **Gemini API**: LLM-powered natural language threat explanation

#### Output Layer
- **Dashboard (Web UI)**: Real-time threat visualization
- **Firebase Alerts**: Push notifications for detected threats
- **BigQuery**: Threat logging and historical analytics

#### Data Flow
```
User Input → API Gateway → [Engine 1, Engine 2, Engine 3, Engine 4]
                                    ↓
                              Risk Scorer → Gemini XAI → Response
                                    ↓
                        [Firebase, BigQuery, Dashboard]
```

---

## 2. ML Models Required & Training Workflow

### Model 1: NLP Phishing Classifier (BERT)
- **Architecture**: bert-base-uncased, fine-tuned with classification head
- **Input**: Email/SMS text content (max 256 tokens)
- **Output**: Binary classification (phishing/legitimate) with confidence
- **Training**: 5 epochs, AdamW optimizer, lr=2e-5
- **Dataset**: 10,000+ samples (Nazario corpus + SpamAssassin + synthetic)
- **Expected Accuracy**: 97.3%

### Model 2: URL Feature Classifier (Ensemble)
- **Architecture**: Random Forest (300 trees) + Gradient Boosting ensemble
- **Input**: 22 extracted URL features
- **Output**: Phishing probability 0-1
- **Training**: Standard sklearn pipeline with StandardScaler
- **Dataset**: PhishTank + Alexa Top 1M URLs
- **Expected Accuracy**: 96.8%

### Model 3: Visual Screenshot Classifier (CNN)
- **Architecture**: ResNet50 transfer learning with custom classifier head
- **Input**: 224x224 webpage screenshots
- **Output**: Binary classification
- **Training**: 10 epochs, Adam optimizer, lr=1e-4
- **Dataset**: Custom screenshot collection (5000+ per class)
- **Expected Accuracy**: 94.5%

### Model 4: Anomaly Detector (Isolation Forest)
- **Purpose**: Zero-day attack detection
- **Architecture**: Isolation Forest
- **Input**: Feature vectors from all engines
- **Output**: Anomaly score for novel threats

### Training Workflow
```
Raw Data → Preprocessing → Feature Engineering → Train/Val/Test Split
    → Model Training → Evaluation → Export → Vertex AI Deployment
    → A/B Testing → Production
```

---

## 3. Dataset Sources

| Dataset | Type | Size | URL |
|---|---|---|---|
| PhishTank | Phishing URLs | 300K+ | phishtank.org |
| OpenPhish | Active phishing feeds | Live | openphish.com |
| Alexa Top 1M | Legitimate URLs | 1M | alexa.com |
| Nazario Corpus | Phishing emails | 4K+ | monkey.org/~jose/phishing |
| SpamAssassin | Mixed emails | 6K+ | spamassassin.apache.org |
| Enron Dataset | Legitimate emails | 500K | cs.cmu.edu/~enron |
| SMS Spam (UCI) | SMS messages | 5.5K | archive.ics.uci.edu |
| PhishIntention | Screenshots | 30K+ | github.com/lindsey98/PhishIntention |

---

## 4. Feature Engineering

### URL Features (30+)
| Feature | Description | Category |
|---|---|---|
| url_length | Total URL character count | Length |
| domain_length | Domain name length | Length |
| dot_count | Number of dots in URL | Structure |
| hyphen_count | Number of hyphens | Structure |
| at_sign | Presence of @ symbol | Structure |
| double_slash_redirect | // in path (redirect trick) | Structure |
| has_ip_address | IP instead of domain | Domain |
| subdomain_count | Number of subdomains | Domain |
| has_suspicious_tld | Uses .tk, .ml, etc. | Domain |
| is_shortened | URL shortener detected | Domain |
| url_entropy | Shannon entropy of URL | Statistical |
| domain_entropy | Shannon entropy of domain | Statistical |
| suspicious_token_count | Count of phishing keywords | Token |
| digit_ratio | Ratio of digits to total chars | Character |
| uses_https | HTTPS protocol check | Security |
| path_depth | URL path depth (/ count) | Structure |
| has_encoded_chars | URL-encoded characters | Obfuscation |
| query_param_count | Number of query parameters | Structure |
| consecutive_consonants | Max consonant cluster | Linguistic |
| vowel_ratio | Vowel to letter ratio | Linguistic |

### Text Features (NLP)
| Feature | Description |
|---|---|
| urgency_count | Urgency language patterns |
| credential_request_count | Credential solicitation |
| social_engineering_count | Manipulation patterns |
| uppercase_ratio | Excessive CAPS usage |
| exclamation_count | Multiple exclamation marks |
| url_count | Embedded URLs count |
| link_text_mismatch | Deceiptive link text |
| sender_domain_free | Free email provider sender |

---

## 5. Real-Time Detection Pipeline

```
1. Input Received (URL/Email/SMS/HTML)
        ↓
2. Preprocessing & Normalization (< 5ms)
        ↓
3. Parallel Engine Execution (< 100ms)
   ├── URL Analyzer   → Feature extraction + ML classification
   ├── NLP Engine      → Pattern matching + BERT inference
   ├── Domain Checker  → Homoglyph + similarity analysis
   └── Visual Engine   → HTML structure + brand spoofing check
        ↓
4. Risk Score Calculation (< 5ms)
   - Weighted ensemble of engine outputs
   - Multi-engine consensus boosting
        ↓
5. Explainable AI Generation (< 50ms)
   - Reason aggregation from all engines
   - Gemini API for natural language explanation
        ↓
6. Response (Total: < 200ms)
   - Risk score (0-1)
   - Risk level (SAFE/LOW/MEDIUM/HIGH/CRITICAL)
   - Detection reasons list
   - Actionable recommendation
        ↓
7. Async: Logging & Alerts
   - BigQuery threat log
   - Firebase real-time notification
   - Dashboard update
```

### Performance Targets
- **P99 Latency**: < 200ms
- **Throughput**: 1000 scans/second
- **Availability**: 99.9%

---

## 6. Chrome Extension Workflow

```
User navigates to URL
        ↓
Background Service Worker triggers
        ↓
Quick local analysis (< 10ms)
   - TLD check, IP detection, token analysis
        ↓
Risk > 0.3? → Send to backend API for deep analysis
        ↓
Content Script scans page HTML
   - Password fields, login forms, hidden fields
   - External form submissions
   - JavaScript obfuscation, keylogger patterns
        ↓
Results combined in popup
        ↓
Risk > 0.5? → Inject warning banner on page
Risk > 0.8? → Show browser notification
        ↓
All results logged to chrome.storage
```

---

## 7. API Design

### Base URL
`https://phishshield-api-xxxxx.run.app/api`

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | /api/scan/url | Scan a URL for phishing |
| POST | /api/scan/email | Analyze email content |
| POST | /api/scan/sms | Check SMS for smishing |
| POST | /api/scan/website | Analyze website content |
| GET | /api/threats | Retrieve threat log |
| GET | /api/stats | Get detection statistics |
| GET | /api/health | Service health check |

### Authentication (Production)
```
Authorization: Bearer <API_KEY>
```

### Rate Limits
- Free tier: 100 scans/day
- Pro tier: 10,000 scans/day
- Enterprise: Unlimited

---

## 8. Explainable AI (XAI) Logic

### How XAI Works in PhishShield

1. **Per-Engine Reasoning**: Each engine provides specific, human-readable reasons
   - URL Analyzer: "Suspicious TLD detected (.tk)"
   - Domain Checker: "Homoglyph 'о' → 'o' found in domain"
   - NLP Engine: "Urgency pattern: 'act now' detected"

2. **Weighted Score Explanation**: Shows contribution of each engine
   - URL Analyzer: 30% weight → 87% score
   - Domain Checker: 25% weight → 92% score
   - NLP Engine: 25% weight → 75% score

3. **Natural Language Summary**: Gemini API generates human-readable explanation
   - "This URL mimics PayPal's login page using a look-alike domain..."

4. **Recommendation Engine**: Actionable advice based on risk level
   - CRITICAL: "Do NOT interact. Report immediately."
   - HIGH: "Verify through official channels."

---

## 9. Deployment Steps (Google Cloud)

### Prerequisites
```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
npm install -g firebase-tools
firebase login
```

### Step-by-Step Deployment

1. **Enable APIs**
```bash
gcloud services enable cloudfunctions.googleapis.com run.googleapis.com \
  aiplatform.googleapis.com bigquery.googleapis.com firebase.googleapis.com
```

2. **Deploy Backend to Cloud Run**
```bash
cd backend
gcloud builds submit --tag gcr.io/PROJECT_ID/phishshield-api
gcloud run deploy phishshield-api --image gcr.io/PROJECT_ID/phishshield-api \
  --platform managed --region us-central1 --allow-unauthenticated
```

3. **Deploy Dashboard to Firebase**
```bash
cd dashboard
firebase init hosting
firebase deploy --only hosting
```

4. **Set up BigQuery**
```sql
CREATE TABLE phishshield_threats.scan_logs (
  id STRING, timestamp TIMESTAMP, scan_type STRING,
  target STRING, risk_score FLOAT64, risk_level STRING,
  is_phishing BOOL, reasons ARRAY<STRING>
) PARTITION BY DATE(timestamp)
```

5. **Deploy ML Models to Vertex AI**
```bash
gcloud ai models upload --display-name=phishshield-nlp \
  --artifact-uri=gs://bucket/models/nlp/ --region=us-central1
```

6. **Load Chrome Extension**
- Open chrome://extensions
- Enable Developer Mode
- Click "Load Unpacked"
- Select the /extension directory

---

## 10. Future Enhancements

### Short-term (Next Sprint)
- [ ] Multi-language phishing detection (Spanish, Chinese, Arabic)
- [ ] Threat intelligence feed integration (VirusTotal, AbuseIPDB)
- [ ] A/B testing framework for model improvements
- [ ] User feedback loop for model retraining

### Medium-term (1-3 months)
- [ ] Browser fingerprinting analysis
- [ ] Social media phishing detection (Facebook, Twitter DMs)
- [ ] Mobile app (React Native)
- [ ] Automated phishing takedown requests
- [ ] Organization-wide deployment (Admin console)

### Long-term (3-6 months)
- [ ] Federated learning for privacy-preserving training
- [ ] Active learning with human-in-the-loop
- [ ] Voice phishing (vishing) detection
- [ ] QR code phishing detection
- [ ] Supply chain attack detection
- [ ] Integration with SIEM/SOAR platforms
