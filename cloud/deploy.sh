#!/bin/bash
# PhishShield - Google Cloud Platform Deployment Script
# Deploys all components to GCP

set -e

PROJECT_ID="${GCP_PROJECT_ID:-phishshield-prod}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="phishshield-api"

echo "🛡️ PhishShield GCP Deployment"
echo "================================"
echo "Project: $PROJECT_ID"
echo "Region:  $REGION"
echo ""

# Step 1: Enable required APIs
echo "📡 Step 1: Enabling GCP APIs..."
gcloud services enable \
  cloudfunctions.googleapis.com \
  run.googleapis.com \
  aiplatform.googleapis.com \
  bigquery.googleapis.com \
  firebase.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  --project=$PROJECT_ID

# Step 2: Create BigQuery dataset for threat logging
echo "📊 Step 2: Setting up BigQuery..."
bq --project_id=$PROJECT_ID mk --dataset phishshield_threats 2>/dev/null || true
bq --project_id=$PROJECT_ID query --use_legacy_sql=false "
CREATE TABLE IF NOT EXISTS phishshield_threats.scan_logs (
  id STRING,
  timestamp TIMESTAMP,
  scan_type STRING,
  target STRING,
  risk_score FLOAT64,
  risk_level STRING,
  is_phishing BOOL,
  engines ARRAY<STRUCT<name STRING, score FLOAT64>>,
  reasons ARRAY<STRING>,
  user_agent STRING,
  source_ip STRING
)
PARTITION BY DATE(timestamp)
"

# Step 3: Deploy Cloud Function for URL scanning
echo "☁️ Step 3: Deploying Cloud Functions..."
cd ../backend
gcloud functions deploy scan-url \
  --runtime python311 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point scan_url \
  --source . \
  --region $REGION \
  --memory 512MB \
  --timeout 30s \
  --project $PROJECT_ID

gcloud functions deploy scan-email \
  --runtime python311 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point scan_email \
  --source . \
  --region $REGION \
  --memory 512MB \
  --timeout 60s \
  --project $PROJECT_ID

gcloud functions deploy scan-sms \
  --runtime python311 \
  --trigger-http \
  --allow-unauthenticated \
  --entry-point scan_sms \
  --source . \
  --region $REGION \
  --memory 512MB \
  --timeout 30s \
  --project $PROJECT_ID

# Step 4: Deploy to Cloud Run (containerized API)
echo "🐳 Step 4: Building and deploying to Cloud Run..."
cd ../backend
gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME .
gcloud run deploy $SERVICE_NAME \
  --image gcr.io/$PROJECT_ID/$SERVICE_NAME \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 2 \
  --max-instances 10 \
  --concurrency 80 \
  --port 5000 \
  --project $PROJECT_ID

# Step 5: Deploy Dashboard to Firebase Hosting
echo "🌐 Step 5: Deploying dashboard to Firebase..."
cd ../dashboard
firebase deploy --only hosting --project $PROJECT_ID

# Step 6: Set up Vertex AI model endpoints
echo "🧠 Step 6: Setting up Vertex AI..."
gcloud ai endpoints create \
  --display-name="phishshield-nlp" \
  --region=$REGION \
  --project=$PROJECT_ID

gcloud ai endpoints create \
  --display-name="phishshield-url" \
  --region=$REGION \
  --project=$PROJECT_ID

echo ""
echo "✅ Deployment complete!"
echo "================================"
echo "Dashboard: https://$PROJECT_ID.web.app"
echo "API:       $(gcloud run services describe $SERVICE_NAME --region=$REGION --format='value(status.url)' --project=$PROJECT_ID)"
echo ""
echo "Next steps:"
echo "  1. Upload trained models to Vertex AI"
echo "  2. Configure Firebase real-time alerts"
echo "  3. Update Chrome extension API URL"
echo "  4. Set up monitoring and alerting"
