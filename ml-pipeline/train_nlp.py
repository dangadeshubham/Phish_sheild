"""
PhishShield ML Pipeline - NLP Model Training
Fine-tunes BERT for phishing email/SMS classification.
Designed for Vertex AI training or local execution.
"""

import os
import json
import numpy as np  # type: ignore[import-not-found]
import pandas as pd  # type: ignore[import-not-found]
from sklearn.model_selection import train_test_split  # type: ignore[import-not-found]
from sklearn.metrics import classification_report, confusion_matrix  # type: ignore[import-not-found]

# ============================================================
# Configuration
# ============================================================
CONFIG = {
    "model_name": "bert-base-uncased",
    "max_length": 256,
    "batch_size": 32,
    "epochs": 5,
    "learning_rate": 2e-5,
    "train_split": 0.8,
    "val_split": 0.1,
    "test_split": 0.1,
    "output_dir": "./models/nlp_phishing",
    "num_labels": 2,  # phishing vs legitimate
}


# ============================================================
# Dataset Sources & Preparation
# ============================================================
DATASET_SOURCES = """
📊 DATASET SOURCES FOR PHISHING NLP MODELS:

1. Nazario Phishing Corpus
   - URL: https://monkey.org/~jose/phishing/
   - Contains real phishing emails
   - ~4,000+ phishing samples

2. APWG eCrime Research Dataset
   - URL: https://apwg.org/ecrime-research/
   - Academic access to phishing data
   - Includes timestamps and categories

3. SpamAssassin Public Corpus
   - URL: https://spamassassin.apache.org/old/publiccorpus/
   - Mix of spam and ham emails
   - Good for negative samples

4. Enron Email Dataset (legitimate baseline)
   - URL: https://www.cs.cmu.edu/~enron/
   - ~500,000 legitimate emails
   - Good for training "not phishing" class

5. SMS Spam Collection (UCI)
   - URL: https://archive.ics.uci.edu/ml/datasets/SMS+Spam+Collection
   - 5,574 SMS messages
   - Labeled as spam/ham

6. PhishTank (for URL-associated text)
   - URL: https://phishtank.org/
   - Community-verified phishing URLs
   - API available for real-time data

GENERATED SYNTHETIC DATA:
For hackathon, we generate synthetic training samples below.
"""


def generate_synthetic_dataset(n_samples=1000):
    """
    Generate synthetic phishing and legitimate email/SMS samples
    for training when real datasets aren't available.
    """
    phishing_templates = [
        "URGENT: Your {brand} account has been suspended. Verify immediately at {url}",
        "Dear valued customer, unusual activity detected on your account. Click {url} to verify",
        "Your {brand} password will expire in {hours} hours. Reset now: {url}",
        "ALERT: Unauthorized login attempt detected. Secure your account: {url}",
        "Congratulations! You've won a ${amount} gift card! Claim now: {url}",
        "NOTICE: Your account has been restricted due to suspicious activity. Verify: {url}",
        "Security Alert: Someone tried to sign in to your {brand} account. Review: {url}",
        "Your {brand} subscription payment failed. Update billing info: {url}",
        "FINAL WARNING: Account termination in {hours} hours unless verified. {url}",
        "Important: Tax refund of ${amount} pending. Confirm identity: {url}",
    ]

    legitimate_templates = [
        "Thank you for your purchase of {item}. Your order #{order} has shipped.",
        "Monthly newsletter: Check out our latest blog posts and updates.",
        "Your meeting with {name} is scheduled for tomorrow at {time}.",
        "Reminder: Your subscription will renew on {date}. Manage preferences in settings.",
        "Here's your weekly summary report for {project}.",
        "Thanks for signing up! Welcome to {brand}. Get started with our guide.",
        "Your recent support ticket #{ticket} has been resolved.",
        "Invitation: {name} shared a document with you in {brand}.",
        "Your {brand} statement for {month} is now available in your account.",
        "Team update: We've released version {version} with new features.",
    ]

    brands = ['Apple', 'Google', 'Microsoft', 'PayPal', 'Amazon', 'Netflix', 'Chase', 'Wells Fargo']
    urls = ['https://verify-secure.tk/login', 'https://account-update.ml/auth', 'https://secure-check.xyz/verify']
    
    data = []
    for _ in range(n_samples // 2):
        template = np.random.choice(phishing_templates)
        text = template.format(
            brand=np.random.choice(brands),
            url=np.random.choice(urls),
            hours=np.random.randint(1, 48),
            amount=np.random.randint(100, 10000)
        )
        data.append({"text": text, "label": 1})

    names = ['John', 'Sarah', 'Team', 'Alex']
    items = ['laptop', 'headphones', 'book', 'subscription']
    
    for _ in range(n_samples // 2):
        template = np.random.choice(legitimate_templates)
        text = template.format(
            brand=np.random.choice(brands),
            item=np.random.choice(items),
            name=np.random.choice(names),
            order=np.random.randint(10000, 99999),
            time='3:00 PM',
            date='January 15',
            project='PhishShield',
            ticket=np.random.randint(1000, 9999),
            month='December',
            version='2.0'
        )
        data.append({"text": text, "label": 0})

    np.random.shuffle(data)
    return pd.DataFrame(data)


# ============================================================
# Feature Engineering
# ============================================================
def extract_text_features(text):
    """Extract handcrafted features for ensemble models."""
    import re
    from collections import Counter
    
    features = {}
    
    # Basic statistics
    features['char_count'] = len(text)
    words = text.split()
    features['word_count'] = len(words)
    features['avg_word_len'] = np.mean([len(w) for w in words]) if words else 0
    features['sentence_count'] = len(re.split(r'[.!?]+', text))
    
    # Punctuation features
    features['exclamation_count'] = text.count('!')
    features['question_count'] = text.count('?')
    features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)  # type: ignore[assignment]
    
    # URL and entity features
    features['url_count'] = len(re.findall(r'https?://\S+', text))
    features['email_count'] = len(re.findall(r'\S+@\S+', text))
    features['phone_count'] = len(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', text))
    features['money_count'] = len(re.findall(r'\$[\d,]+', text))
    
    # Keyword features
    urgency_words = ['urgent', 'immediately', 'asap', 'hurry', 'expire', 'suspend', 'deadline', 'act now']
    features['urgency_count'] = sum(1 for w in urgency_words if w in text.lower())
    
    action_words = ['click', 'verify', 'confirm', 'update', 'login', 'sign in', 'reset', 'validate']
    features['action_count'] = sum(1 for w in action_words if w in text.lower())
    
    # Entropy
    freq = Counter(text.lower())
    total = len(text)
    _entropy = -sum(
        (c / total) * np.log2(c / total) for c in freq.values() if c > 0
    )
    features['text_entropy'] = _entropy  # type: ignore
    
    return features


# ============================================================
# BERT Training Pipeline
# ============================================================
def train_bert_model():
    """
    Fine-tune BERT for phishing text classification.
    Requires: pip install transformers torch
    """
    print("=" * 60)
    print("🧠 PhishShield NLP Training Pipeline")
    print("=" * 60)
    
    # Step 1: Prepare dataset
    print("\n📊 Step 1: Preparing dataset...")
    df = generate_synthetic_dataset(2000)
    print(f"   Generated {len(df)} samples")
    print(f"   Phishing: {(df['label'] == 1).sum()}")  # type: ignore[union-attr]
    print(f"   Legitimate: {(df['label'] == 0).sum()}")  # type: ignore[union-attr]
    
    # Split dataset
    train_df, temp_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label'])
    val_df, test_df = train_test_split(temp_df, test_size=0.5, random_state=42, stratify=temp_df['label'])
    print(f"   Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")

    try:
        from transformers import BertTokenizer, BertForSequenceClassification  # type: ignore[import-not-found]
        from transformers import TrainingArguments, Trainer  # type: ignore[import-not-found]
        import torch  # type: ignore[import-not-found]
        from torch.utils.data import Dataset  # type: ignore[import-not-found]
        
        class PhishingDataset(Dataset):
            def __init__(self, texts, labels, tokenizer, max_length):
                self.encodings = tokenizer(
                    texts.tolist(), truncation=True, padding=True, 
                    max_length=max_length, return_tensors='pt'
                )
                self.labels = torch.tensor(labels.tolist())

            def __getitem__(self, idx):
                item = {key: val[idx] for key, val in self.encodings.items()}
                item['labels'] = self.labels[idx]
                return item

            def __len__(self):
                return len(self.labels)
        
        # Step 2: Load tokenizer and model
        print(f"\n🤖 Step 2: Loading {CONFIG['model_name']}...")
        tokenizer = BertTokenizer.from_pretrained(CONFIG['model_name'])
        model = BertForSequenceClassification.from_pretrained(
            CONFIG['model_name'], num_labels=CONFIG['num_labels']
        )
        
        # Step 3: Create datasets
        print("\n📦 Step 3: Tokenizing datasets...")
        train_dataset = PhishingDataset(train_df['text'], train_df['label'], tokenizer, CONFIG['max_length'])  # type: ignore[index]
        val_dataset = PhishingDataset(val_df['text'], val_df['label'], tokenizer, CONFIG['max_length'])  # type: ignore[index]
        test_dataset = PhishingDataset(test_df['text'], test_df['label'], tokenizer, CONFIG['max_length'])  # type: ignore[index]
        
        # Step 4: Training
        print("\n🏋️ Step 4: Training model...")
        training_args = TrainingArguments(
            output_dir=CONFIG['output_dir'],
            num_train_epochs=CONFIG['epochs'],
            per_device_train_batch_size=CONFIG['batch_size'],
            per_device_eval_batch_size=CONFIG['batch_size'],
            learning_rate=CONFIG['learning_rate'],
            weight_decay=0.01,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            logging_steps=50,
        )
        
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
        )
        
        trainer.train()
        
        # Step 5: Evaluation
        print("\n📈 Step 5: Evaluating model...")
        predictions = trainer.predict(test_dataset)
        preds = np.argmax(predictions.predictions, axis=-1)
        print(classification_report(
            test_df['label'].values, preds,  # type: ignore[index]
            target_names=['Legitimate', 'Phishing']
        ))
        
        # Step 6: Save model
        print(f"\n💾 Step 6: Saving model to {CONFIG['output_dir']}")
        model.save_pretrained(CONFIG['output_dir'])
        tokenizer.save_pretrained(CONFIG['output_dir'])
        print("✅ Training complete!")
        
    except ImportError:
        print("\n⚠️  PyTorch/Transformers not installed.")
        print("   Install with: pip install torch transformers")
        print("\n📊 Running feature-based classification instead...")
        
        # Fallback: Feature-based classification with sklearn
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier  # type: ignore[import-not-found]
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-not-found]
        from sklearn.pipeline import Pipeline  # type: ignore[import-not-found]
        
        # TF-IDF + Random Forest pipeline
        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ('clf', GradientBoostingClassifier(n_estimators=200, max_depth=5, random_state=42))
        ])
        
        pipeline.fit(train_df['text'], train_df['label'])  # type: ignore[index]
        
        # Evaluate
        preds = pipeline.predict(test_df['text'])  # type: ignore[index]
        print("\n📊 Classification Report:")
        print(classification_report(
            test_df['label'].values, preds,  # type: ignore[index]
            target_names=['Legitimate', 'Phishing']
        ))
        
        # Save model
        import joblib  # type: ignore[import-not-found]
        os.makedirs(str(CONFIG['output_dir']), exist_ok=True)
        joblib.dump(pipeline, os.path.join(str(CONFIG['output_dir']), 'tfidf_model.pkl'))
        print(f"\n✅ Model saved to {CONFIG['output_dir']}/tfidf_model.pkl")
    
    print("\n" + "=" * 60)
    print("🎉 Training pipeline complete!")
    print("=" * 60)


if __name__ == '__main__':
    print(DATASET_SOURCES)
    train_bert_model()
