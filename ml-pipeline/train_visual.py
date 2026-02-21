"""
PhishShield ML Pipeline - Visual Model Training
Trains a CNN (ResNet50 transfer learning) for phishing website screenshot classification.
Designed for Vertex AI or local training.
"""

import os
import numpy as np  # type: ignore[import-not-found]
from PIL import Image  # type: ignore[import-not-found]

CONFIG = {
    "model_name": "ResNet50",
    "image_size": (224, 224),
    "batch_size": 32,
    "epochs": 10,
    "learning_rate": 1e-4,
    "train_split": 0.8,
    "output_dir": "./models/visual_classifier",
    "num_classes": 2,
}

DATASET_SOURCES = """
📊 VISUAL DATASET SOURCES:

1. Custom Screenshot Collection
   - Capture screenshots of login pages
   - Use Selenium/Playwright to automate bulk collection
   - Recommended: 5000+ screenshots per class

2. PhishIntention Dataset
   - URL: https://github.com/lindsey98/PhishIntention
   - Screenshot-based phishing detection dataset
   - Includes brand logos and layout analysis

3. Phishing Website Dataset (Mendeley)
   - URL: https://data.mendeley.com/datasets/
   - Pre-collected phishing website screenshots

GENERATION APPROACH:
For hackathon, we create synthetic image data to demonstrate the pipeline.
"""


def generate_synthetic_images(n_per_class=100, image_size=(224, 224)):
    """Generate synthetic screenshots for demonstration."""
    _out = str(CONFIG['output_dir'])
    os.makedirs(os.path.join(_out, 'data', 'phishing'), exist_ok=True)
    os.makedirs(os.path.join(_out, 'data', 'legitimate'), exist_ok=True)

    print(f"   Generating {n_per_class} phishing samples...")
    for i in range(n_per_class):
        # Phishing: typically simple, centered login form, minimal design
        img = np.ones((*image_size, 3), dtype=np.uint8) * 240  # light bg
        # Add a colored rectangle (simulating a login box)
        cx, cy = image_size[0] // 2, image_size[1] // 2
        box_h, box_w = 80, 120
        color = np.random.randint(200, 256, 3)
        img[cx-box_h:cx+box_h, cy-box_w:cy+box_w] = color
        # Add some "input fields" (dark rectangles)
        for j in range(2):
            y = cx - 30 + j * 40
            img[y:y+20, cy-90:cy+90] = [200, 200, 200]
        # Save
        Image.fromarray(img).save(
            os.path.join(_out, 'data', 'phishing', 'phish_' + str(i).zfill(4) + '.png')
        )

    print(f"   Generating {n_per_class} legitimate samples...")
    for i in range(n_per_class):
        # Legitimate: more complex layout, nav bars, footers, etc.
        img = np.ones((*image_size, 3), dtype=np.uint8) * 250
        # Nav bar
        img[0:30, :] = np.random.randint(30, 80, 3)
        # Content blocks
        for j in range(3):
            y = 50 + j * 55
            x = 20 + j * 10
            color = np.random.randint(100, 200, 3)
            img[y:y+40, x:x+180] = color
        # Footer
        img[-25:, :] = np.random.randint(30, 80, 3)
        Image.fromarray(img).save(
            os.path.join(_out, 'data', 'legitimate', 'legit_' + str(i).zfill(4) + '.png')
        )


def train_visual_model():
    print("=" * 60)
    print("👁️ PhishShield Visual Classifier Training")
    print("=" * 60)

    print("\n🎨 Generating synthetic training data...")
    generate_synthetic_images(200)

    try:
        import tensorflow as tf  # type: ignore[import-not-found]
        from tensorflow.keras.applications import ResNet50  # type: ignore[import-not-found]
        from tensorflow.keras.layers import Dense, GlobalAveragePooling2D, Dropout  # type: ignore[import-not-found]
        from tensorflow.keras.models import Model  # type: ignore[import-not-found]
        from tensorflow.keras.preprocessing.image import ImageDataGenerator  # type: ignore[import-not-found]
        from tensorflow.keras.optimizers import Adam  # type: ignore[import-not-found]

        print(f"\n🤖 Loading {CONFIG['model_name']}...")
        _img_size = (int(CONFIG['image_size'][0]), int(CONFIG['image_size'][1]))  # type: ignore[index]
        base_model = ResNet50(weights='imagenet', include_top=False, input_shape=(_img_size[0], _img_size[1], 3))
        base_model.trainable = False  # Freeze base layers

        # Add classification head
        x = base_model.output
        x = GlobalAveragePooling2D()(x)
        x = Dense(256, activation='relu')(x)
        x = Dropout(0.5)(x)
        predictions = Dense(CONFIG['num_classes'], activation='softmax')(x)
        model = Model(inputs=base_model.input, outputs=predictions)

        model.compile(
            optimizer=Adam(learning_rate=CONFIG['learning_rate']),
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )

        print(f"   Model parameters: {model.count_params():,}")

        # Data generators
        datagen = ImageDataGenerator(
            rescale=1./255,
            rotation_range=10,
            width_shift_range=0.1,
            height_shift_range=0.1,
            validation_split=0.2
        )

        data_dir = os.path.join(str(CONFIG['output_dir']), 'data')
        train_gen = datagen.flow_from_directory(
            data_dir, target_size=CONFIG['image_size'],
            batch_size=CONFIG['batch_size'], class_mode='categorical', subset='training'
        )
        val_gen = datagen.flow_from_directory(
            data_dir, target_size=CONFIG['image_size'],
            batch_size=CONFIG['batch_size'], class_mode='categorical', subset='validation'
        )

        print("\n🏋️ Training model...")
        history = model.fit(
            train_gen, validation_data=val_gen,
            epochs=CONFIG['epochs'], verbose=1
        )

        # Save
        model.save(os.path.join(str(CONFIG['output_dir']), 'resnet50_phishing.h5'))
        print(f"\n✅ Model saved to {CONFIG['output_dir']}/resnet50_phishing.h5")

        # Results
        val_acc = max(history.history.get('val_accuracy', [0]))
        print(f"   Best validation accuracy: {val_acc:.4f}")

    except ImportError:
        print("\n⚠️  TensorFlow not installed.")
        print("   Install with: pip install tensorflow")
        print("\n📊 Demonstrating feature extraction pipeline instead...")

        from sklearn.ensemble import RandomForestClassifier  # type: ignore[import-not-found]
        from sklearn.metrics import classification_report  # type: ignore[import-not-found]
        import joblib  # type: ignore[import-not-found]

        # Extract simple image features
        data_dir = os.path.join(str(CONFIG['output_dir']), 'data')
        features, labels = [], []

        for label, class_name in enumerate(['legitimate', 'phishing']):
            class_dir = os.path.join(data_dir, class_name)
            for fname in list(os.listdir(class_dir))[0:100]:  # type: ignore[index]
                img = np.array(Image.open(os.path.join(class_dir, fname)).resize((64, 64)))
                feat = [
                    img.mean(), img.std(),
                    img[:30].mean(),  # top region (nav bar indicator)
                    img[-30:].mean(),  # bottom region (footer indicator)
                    img[80:140, 40:180].mean(),  # center region
                    img[80:140, 40:180].std(),
                    (img < 50).sum() / img.size,  # dark pixel ratio
                    (img > 200).sum() / img.size,  # light pixel ratio
                    np.unique(img.reshape(-1, 3), axis=0).shape[0],  # color diversity
                ]
                features.append(feat)
                labels.append(label)

        X = np.array(features)
        y = np.array(labels)

        from sklearn.model_selection import train_test_split  # type: ignore[import-not-found]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        print(classification_report(y_test, preds, target_names=['Legitimate', 'Phishing']))

        joblib.dump(clf, os.path.join(str(CONFIG['output_dir']), 'visual_rf.pkl'))
        print(f"✅ Feature-based model saved")

    print("\n" + "=" * 60)
    print("🎉 Visual classifier training complete!")
    print("=" * 60)


if __name__ == '__main__':
    print(DATASET_SOURCES)
    train_visual_model()
