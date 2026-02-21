"""
PhishShield ML Pipeline - URL Classification Model Training
Trains an ensemble model (Random Forest + Neural Net) for phishing URL detection.
"""

import os
import numpy as np  # type: ignore[import-not-found]
import pandas as pd  # type: ignore[import-not-found]
from sklearn.model_selection import train_test_split  # type: ignore[import-not-found]
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier  # type: ignore[import-not-found]
from sklearn.metrics import classification_report, accuracy_score  # type: ignore[import-not-found]
from sklearn.preprocessing import StandardScaler  # type: ignore[import-not-found]
import joblib  # type: ignore[import-not-found]
import math
import re
from collections import Counter
from urllib.parse import urlparse

CONFIG = {
    "output_dir": "./models/url_classifier",
    "n_estimators": 300,
    "max_depth": 12,
    "random_state": 42,
}

DATASET_SOURCES = """
📊 URL DATASET SOURCES:
1. PhishTank      - https://phishtank.org/developer_info.php
2. OpenPhish      - https://openphish.com/
3. Alexa Top 1M   - https://s3.amazonaws.com/alexa-static/top-1m.csv.zip
4. URLHaus        - https://urlhaus.abuse.ch/
5. Kaggle Phishing URLs - https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
"""


def entropy(text):
    if not text:
        return 0
    freq = Counter(text)
    length = len(str(text))
    return -sum((c/length) * math.log2(c/length) for c in freq.values())


def extract_url_features(url):
    """Extract 20+ features from a URL."""
    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
    except:
        parsed = urlparse(f'http://{url}')

    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path
    f = {}

    f['url_length'] = len(url)
    f['domain_length'] = len(domain)
    f['path_length'] = len(path)
    f['dot_count'] = url.count('.')
    f['hyphen_count'] = url.count('-')
    f['underscore_count'] = url.count('_')
    f['slash_count'] = url.count('/')
    f['at_sign'] = 1 if '@' in url else 0
    f['double_slash'] = 1 if '//' in url[8:] else 0
    f['digit_count'] = sum(c.isdigit() for c in url)
    _digit_ratio = f['digit_count'] / max(len(url), 1)
    f['digit_ratio'] = _digit_ratio  # type: ignore
    _letter_ratio = sum(c.isalpha() for c in url) / max(len(url), 1)
    f['letter_ratio'] = _letter_ratio  # type: ignore
    f['has_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain) else 0
    f['subdomain_count'] = max(domain.count('.') - 1, 0)
    f['uses_https'] = 1 if parsed.scheme == 'https' else 0
    _url_ent = int(entropy(url) * 10000) / 10000.0
    f['url_entropy'] = _url_ent  # type: ignore
    _dom_ent = int(entropy(domain) * 10000) / 10000.0
    f['domain_entropy'] = _dom_ent  # type: ignore
    f['path_depth'] = path.count('/') - 1 if path else 0
    f['query_length'] = len(parsed.query)
    f['has_port'] = 1 if ':' in domain.split('.')[-1] else 0
    f['special_chars'] = sum(c in '!@#$%^&*()+=[]{}|;:,<>?' for c in url)

    sus_tlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.club','.online','.site']
    f['suspicious_tld'] = 1 if any(domain.endswith(t) for t in sus_tlds) else 0

    tokens = ['login','verify','secure','account','update','banking','password','confirm','signin']
    f['suspicious_tokens'] = sum(1 for t in tokens if t in url.lower())

    return f


def generate_synthetic_urls(n=2000):
    """Generate synthetic phishing and legitimate URL samples."""
    phishing_patterns = [
        'http://{rand}.{tld}/{brand}-login/verify?id={id}',
        'https://{brand}-secure.{tld}/account/update?ref={id}',
        'http://{ip}/~{brand}/login.php',
        'https://{brand}.security-verify.{tld}/auth?token={id}',
        'http://{rand}.{rand2}.{tld}/{brand}/signin',
        'https://secure-{brand}-login.{tld}/verify/{id}',
        'http://{brand}.{rand}.{tld}/password/reset?u={id}',
        'https://{brand}-account.{tld}/confirm-identity',
    ]
    legit_patterns = [
        'https://www.{brand}.com/{path}',
        'https://{brand}.com/products/{item}',
        'https://docs.{brand}.com/en/guide',
        'https://support.{brand}.com/help/{path}',
        'https://www.{brand}.com/about',
        'https://blog.{brand}.com/{path}',
        'https://api.{brand}.com/v2/{path}',
        'https://www.{brand}.com/contact',
    ]

    brands = ['google','apple','microsoft','paypal','amazon','netflix','chase','facebook','instagram','twitter']
    sus_tlds = ['tk','ml','ga','cf','gq','xyz','top','club','online','site']
    paths = ['home','products','about','contact','news','blog','docs','help','settings']
    items = ['laptop','phone','tablet','camera','headset','monitor','keyboard']

    import random
    data = []

    for _ in range(n // 2):
        tpl = random.choice(phishing_patterns)
        url = tpl.format(
            rand=''.join(random.choices('abcdefghijklmnop', k=random.randint(5,12))),
            rand2=''.join(random.choices('abcdefghijklmnop', k=random.randint(4,8))),
            tld=random.choice(sus_tlds),
            brand=random.choice(brands),
            ip=f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            id=''.join(random.choices('abcdef0123456789', k=16)),
            path=random.choice(paths),
            item=random.choice(items),
        )
        data.append({'url': url, 'label': 1})

    for _ in range(n // 2):
        tpl = random.choice(legit_patterns)
        url = tpl.format(
            brand=random.choice(brands),
            path=random.choice(paths),
            item=random.choice(items),
        )
        data.append({'url': url, 'label': 0})

    random.shuffle(data)
    return pd.DataFrame(data)


def train_url_model():
    print("=" * 60)
    print("🔗 PhishShield URL Classifier Training")
    print("=" * 60)

    # Generate dataset
    print("\n📊 Generating synthetic dataset...")
    df = generate_synthetic_urls(4000)
    print(f"   Samples: {len(df)} (Phishing: {(df['label']==1).sum()}, Legit: {(df['label']==0).sum()})")  # type: ignore[union-attr]

    # Extract features
    print("\n🔬 Extracting URL features...")
    features_list = [extract_url_features(url) for url in df['url']]
    features_df = pd.DataFrame(features_list)
    print(f"   Features extracted: {len(features_df.columns)}")
    print(f"   Features: {list(features_df.columns)}")

    # Split
    X = features_df.values
    y = df['label'].values
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest
    print("\n🌲 Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=CONFIG['n_estimators'],
        max_depth=CONFIG['max_depth'],
        random_state=CONFIG['random_state'],
        n_jobs=-1
    )
    rf.fit(X_train_scaled, y_train)
    rf_preds = rf.predict(X_test_scaled)
    rf_acc = accuracy_score(y_test, rf_preds)
    print(f"   Random Forest Accuracy: {rf_acc:.4f}")

    # Train Gradient Boosting
    print("\n🚀 Training Gradient Boosting...")
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        random_state=CONFIG['random_state']
    )
    gb.fit(X_train_scaled, y_train)
    gb_preds = gb.predict(X_test_scaled)
    gb_acc = accuracy_score(y_test, gb_preds)
    print(f"   Gradient Boosting Accuracy: {gb_acc:.4f}")

    # Ensemble (average probabilities)
    print("\n🎯 Creating Ensemble...")
    rf_probs = rf.predict_proba(X_test_scaled)[:, 1]
    gb_probs = gb.predict_proba(X_test_scaled)[:, 1]
    ensemble_probs = (rf_probs + gb_probs) / 2
    ensemble_preds = (ensemble_probs > 0.5).astype(int)
    ensemble_acc = accuracy_score(y_test, ensemble_preds)
    print(f"   Ensemble Accuracy: {ensemble_acc:.4f}")

    print("\n📊 Classification Report (Ensemble):")
    print(classification_report(y_test, ensemble_preds, target_names=['Legitimate', 'Phishing']))

    # Feature importance
    print("\n📈 Top Feature Importances (Random Forest):")
    importance = zip(features_df.columns, rf.feature_importances_)
    for name, imp in list(sorted(importance, key=lambda x: x[1], reverse=True))[0:10]:  # type: ignore[index]
        print(f"   {name:25s} {imp:.4f}")

    # Save models
    _out_dir = str(CONFIG['output_dir'])
    os.makedirs(_out_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(_out_dir, 'random_forest.pkl'))
    joblib.dump(gb, os.path.join(_out_dir, 'gradient_boosting.pkl'))
    joblib.dump(scaler, os.path.join(_out_dir, 'scaler.pkl'))
    print(f"\n✅ Models saved to {CONFIG['output_dir']}")

    print("\n" + "=" * 60)
    print("🎉 URL classifier training complete!")
    print("=" * 60)


if __name__ == '__main__':
    print(DATASET_SOURCES)
    train_url_model()
