"""
train.py — Main ML training pipeline
════════════════════════════════════════════════════════════════════════════════
Architecture: 42 → Dense(64, relu) → Dropout(0.3)
                 → Dense(32, relu) → Dropout(0.2)
                 → Dense(16, relu)
                 → Dense(1, sigmoid)

Matches model.js in the extension (same layer sizes, same activations).

Usage:
  python train.py                      # train on data/combined.csv
  python train.py --epochs 50          # custom epochs
  python train.py --download-data      # download data then train
  python train.py --export-only        # skip training, just export existing model
════════════════════════════════════════════════════════════════════════════════
"""

import os
import json
import argparse
import random
import warnings
import numpy as np
from pathlib import Path

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

from features import extract_features, FEATURE_NAMES, NUM_FEATURES

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).parent
DATA_DIR   = ROOT / 'data'
MODELS_DIR = ROOT / 'models'
EXPORT_DIR = ROOT / 'export'           # → copy to extension/ml/ after training

COMBINED_CSV   = DATA_DIR    / 'combined.csv'
KERAS_MODEL    = MODELS_DIR  / 'phishing_model.keras'
TFJS_MODEL_DIR = EXPORT_DIR  / 'tfjs_model'


# ════════════════════════════════════════════════════════════════════════════════
# DATA LOADING
# ════════════════════════════════════════════════════════════════════════════════

def load_csv_dataset(csv_path: Path):
    """Load url,label pairs from combined CSV."""
    import csv
    urls, labels = [], []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get('url', '').strip()
            lbl = int(row.get('label', 0))
            if url:
                urls.append(url)
                labels.append(lbl)
    return urls, labels


def build_feature_matrix(urls, labels, verbose=True):
    """Extract 42 features from all URLs into a numpy matrix."""
    try:
        from tqdm import tqdm
        it = tqdm(urls, desc='Extracting features', unit='url') if verbose else urls
    except ImportError:
        it = urls

    X = np.array([extract_features(u) for u in it], dtype=np.float32)
    y = np.array(labels, dtype=np.float32)
    return X, y


# ════════════════════════════════════════════════════════════════════════════════
# MODEL DEFINITION
# ════════════════════════════════════════════════════════════════════════════════

def build_model(input_dim: int = NUM_FEATURES, learning_rate: float = 0.001):
    """
    Build the Keras model.
    Architecture mirrors model.js: 42→64→32→16→1
    """
    import tensorflow as tf
    from tensorflow import keras

    inputs = keras.Input(shape=(input_dim,), name='url_features')

    x = keras.layers.Dense(64, activation='relu', name='dense_1',
        kernel_regularizer=keras.regularizers.l2(1e-4))(inputs)
    x = keras.layers.BatchNormalization(name='bn_1')(x)
    x = keras.layers.Dropout(0.3, name='dropout_1')(x)

    x = keras.layers.Dense(32, activation='relu', name='dense_2',
        kernel_regularizer=keras.regularizers.l2(1e-4))(x)
    x = keras.layers.BatchNormalization(name='bn_2')(x)
    x = keras.layers.Dropout(0.2, name='dropout_2')(x)

    x = keras.layers.Dense(16, activation='relu', name='dense_3')(x)

    outputs = keras.layers.Dense(1, activation='sigmoid', name='output')(x)

    model = keras.Model(inputs, outputs, name='PhishingDetector')

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss='binary_crossentropy',
        metrics=[
            'accuracy',
            keras.metrics.Precision(name='precision'),
            keras.metrics.Recall(name='recall'),
            keras.metrics.AUC(name='auc'),
        ],
    )

    return model


# ════════════════════════════════════════════════════════════════════════════════
# TRAINING
# ════════════════════════════════════════════════════════════════════════════════

def train(
    X_train, y_train,
    X_val,   y_val,
    epochs:        int   = 40,
    batch_size:    int   = 256,
    learning_rate: float = 0.001,
    class_weight:  bool  = True,
):
    import tensorflow as tf
    from tensorflow import keras

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model = build_model(learning_rate=learning_rate)
    model.summary()

    # Callbacks
    callbacks = [
        keras.callbacks.EarlyStopping(
            monitor='val_auc', patience=8, restore_best_weights=True,
            mode='max', verbose=1
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor='val_loss', factor=0.5, patience=4, min_lr=1e-6, verbose=1
        ),
        keras.callbacks.ModelCheckpoint(
            str(KERAS_MODEL), monitor='val_auc', save_best_only=True,
            mode='max', verbose=1
        ),
        keras.callbacks.CSVLogger(str(MODELS_DIR / 'training_log.csv')),
        keras.callbacks.TensorBoard(log_dir=str(MODELS_DIR / 'logs'), histogram_freq=0),
    ]

    # Class weights to handle imbalance
    cw = None
    if class_weight:
        n_total = len(y_train)
        n_pos   = y_train.sum()
        n_neg   = n_total - n_pos
        cw = {0: n_total / (2 * n_neg), 1: n_total / (2 * n_pos)}
        print(f'  Class weights: {cw}')

    print(f'\nTraining on {len(X_train):,} samples, validating on {len(X_val):,}…\n')

    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=cw,
        callbacks=callbacks,
        verbose=1,
    )

    return model, history


# ════════════════════════════════════════════════════════════════════════════════
# EXPORT TO TF.JS
# ════════════════════════════════════════════════════════════════════════════════

def export_tfjs(model, output_dir: Path = TFJS_MODEL_DIR):
    """Export Keras model to TensorFlow.js format."""
    try:
        import tensorflowjs as tfjs
    except ImportError:
        print('  ✗ tensorflowjs not installed. Run: pip install tensorflowjs')
        print('  Saving Keras model only…')
        model.save(str(KERAS_MODEL))
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f'\n  Exporting to TF.js: {output_dir}')
    tfjs.converters.save_keras_model(model, str(output_dir))

    # Also save a weights-only JSON for the extension's fallback weighted model
    weights_out = output_dir / 'feature_weights.json'
    export_feature_weights(model, weights_out)

    print(f'\n  ✓ TF.js model saved to: {output_dir}')
    print(f'  Copy contents of {output_dir} to extension/ml/ to update the extension.\n')


def export_feature_weights(model, output_path: Path):
    """
    Extract learned weights from the first Dense layer to build a
    lightweight linear fallback (used by model.js weightedLinearScore).
    """
    import tensorflow as tf

    # Get the first dense layer weights: shape (42, 64)
    dense1_weights = None
    for layer in model.layers:
        if layer.name == 'dense_1':
            dense1_weights = layer.get_weights()[0]  # (42, 64)
            break

    if dense1_weights is None:
        print('  ⚠ Could not find dense_1 layer for weight export')
        return

    # Reduce to per-feature importance: mean(|weight|) across output neurons
    importance = np.abs(dense1_weights).mean(axis=1)  # shape (42,)
    importance = importance / importance.max()          # normalize to [0,1]

    weights_dict = {
        FEATURE_NAMES[i]: float(importance[i])
        for i in range(NUM_FEATURES)
    }

    with open(output_path, 'w') as f:
        json.dump(weights_dict, f, indent=2)

    print(f'  ✓ Feature importance weights saved: {output_path}')

    # Print top 10 most important features
    sorted_feats = sorted(weights_dict.items(), key=lambda x: x[1], reverse=True)
    print('\n  Top 10 most important features:')
    for name, w in sorted_feats[:10]:
        bar = '█' * int(w * 20)
        print(f'    {name:<30} {bar} {w:.3f}')


# ════════════════════════════════════════════════════════════════════════════════
# EVALUATION
# ════════════════════════════════════════════════════════════════════════════════

def evaluate(model, X_test, y_test):
    """Compute and print evaluation metrics."""
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, average_precision_score,
    )

    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob >= 0.5).astype(int)

    print('\n' + '═'*60)
    print('  EVALUATION RESULTS')
    print('═'*60)

    # Keras metrics
    results = model.evaluate(X_test, y_test, verbose=0)
    metric_names = model.metrics_names
    for name, val in zip(metric_names, results):
        print(f'  {name:<20} {val:.4f}')

    # Sklearn metrics
    roc_auc = roc_auc_score(y_test, y_prob)
    avg_prec = average_precision_score(y_test, y_prob)
    print(f'  {"roc_auc":<20} {roc_auc:.4f}')
    print(f'  {"avg_precision":<20} {avg_prec:.4f}')

    print('\n  Classification Report:')
    print(classification_report(y_test, y_pred, target_names=['Legit', 'Phishing']))

    print('  Confusion Matrix:')
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f'    TN={tn:,}  FP={fp:,}  FN={fn:,}  TP={tp:,}')
    print(f'    False Positive Rate: {fp/(fp+tn):.3%}')
    print(f'    False Negative Rate: {fn/(fn+tp):.3%}')
    print('═'*60 + '\n')

    return {
        'roc_auc': roc_auc, 'avg_precision': avg_prec,
        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn),
    }


# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='Train AI Phishing Shield ML model')
    parser.add_argument('--data',          type=str,   default=str(COMBINED_CSV), help='CSV dataset path')
    parser.add_argument('--epochs',        type=int,   default=40,   help='Training epochs (default: 40)')
    parser.add_argument('--batch-size',    type=int,   default=256,  help='Batch size (default: 256)')
    parser.add_argument('--lr',            type=float, default=0.001,help='Learning rate (default: 0.001)')
    parser.add_argument('--val-split',     type=float, default=0.15, help='Validation split (default: 0.15)')
    parser.add_argument('--test-split',    type=float, default=0.10, help='Test split (default: 0.10)')
    parser.add_argument('--seed',          type=int,   default=42,   help='Random seed')
    parser.add_argument('--download-data', action='store_true',      help='Download dataset first')
    parser.add_argument('--export-only',   action='store_true',      help='Skip training, export existing model')
    parser.add_argument('--no-export',     action='store_true',      help='Skip TF.js export')
    parser.add_argument('--samples',       type=int,   default=10000,help='Max samples per class when downloading')
    args = parser.parse_args()

    # Seed
    random.seed(args.seed)
    np.random.seed(args.seed)

    import tensorflow as tf
    tf.random.set_seed(args.seed)

    print('\n' + '═'*60)
    print('  AI PHISHING SHIELD — ML TRAINING PIPELINE')
    print('═'*60)
    print(f'  TensorFlow version: {tf.__version__}')
    print(f'  Features:           {NUM_FEATURES}')
    print(f'  Architecture:       42→64→32→16→1')
    print('═'*60 + '\n')

    # ── Download data if requested ───────────────────────────────────────────
    if args.download_data:
        print('[STEP 1] Downloading datasets…')
        from data_loader import load_phishtank, load_tranco, build_combined_dataset
        phishing = load_phishtank(args.samples)
        legit    = load_tranco(args.samples)
        build_combined_dataset(phishing, legit, balance=True, output_path=Path(args.data))
        print()

    # ── Export-only mode ─────────────────────────────────────────────────────
    if args.export_only:
        print('[EXPORT] Loading saved Keras model…')
        from tensorflow import keras
        model = keras.models.load_model(str(KERAS_MODEL))
        export_tfjs(model)
        return

    # ── Load dataset ─────────────────────────────────────────────────────────
    data_path = Path(args.data)
    if not data_path.exists():
        print(f'  ✗ Dataset not found: {data_path}')
        print('  Run with --download-data to fetch datasets first.\n')
        print('  Generating a small synthetic demo dataset…')

        from data_loader import load_phishtank_fallback, load_tranco, build_combined_dataset
        phishing = load_phishtank_fallback(2000)
        legit    = [f'https://www.example{i}.com/page' for i in range(2000)]
        build_combined_dataset(phishing, legit, balance=True, output_path=data_path)

    print('[STEP 2] Loading dataset…')
    urls, labels = load_csv_dataset(data_path)
    print(f'  Loaded {len(urls):,} samples  ({sum(labels):,} phishing, {len(labels)-sum(labels):,} legit)\n')

    # ── Extract features ─────────────────────────────────────────────────────
    print('[STEP 3] Extracting features…')
    X, y = build_feature_matrix(urls, labels)
    print(f'  Feature matrix shape: {X.shape}\n')

    # ── Train/val/test split ─────────────────────────────────────────────────
    from sklearn.model_selection import train_test_split

    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=args.test_split, random_state=args.seed, stratify=y
    )
    val_ratio_adjusted = args.val_split / (1 - args.test_split)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_ratio_adjusted, random_state=args.seed, stratify=y_temp
    )

    print(f'[STEP 4] Dataset splits:')
    print(f'  Train: {len(X_train):,}  Val: {len(X_val):,}  Test: {len(X_test):,}\n')

    # ── Train ────────────────────────────────────────────────────────────────
    print('[STEP 5] Training model…\n')
    model, history = train(
        X_train, y_train, X_val, y_val,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
    )

    # ── Evaluate ─────────────────────────────────────────────────────────────
    print('[STEP 6] Evaluating on test set…')
    metrics = evaluate(model, X_test, y_test)

    # Save metrics
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    import json
    with open(MODELS_DIR / 'metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    # ── Export ───────────────────────────────────────────────────────────────
    if not args.no_export:
        print('[STEP 7] Exporting model to TF.js…')
        export_tfjs(model)

    print('\n✓ Training complete!\n')
    print('Next steps:')
    print('  1. Copy ml/export/tfjs_model/ contents to extension/ml/')
    print('  2. Reload the extension in chrome://extensions/')
    print('  3. Run evaluate.py for detailed plots and analysis\n')


if __name__ == '__main__':
    main()
