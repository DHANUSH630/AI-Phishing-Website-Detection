"""
evaluate.py — Model evaluation and visualization
════════════════════════════════════════════════════════════════════════════════
Generates:
  • ROC curve
  • Precision-Recall curve
  • Confusion matrix heatmap
  • Feature importance bar chart
  • Score distribution histogram
  • Training history plots

Usage:
  python evaluate.py                         # evaluate saved model
  python evaluate.py --url "http://suspicious-paypal.xyz/login"
════════════════════════════════════════════════════════════════════════════════
"""

import os
import json
import argparse
import warnings
import numpy as np
from pathlib import Path

warnings.filterwarnings('ignore')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

ROOT       = Path(__file__).parent
MODELS_DIR = ROOT / 'models'
PLOTS_DIR  = ROOT / 'plots'
KERAS_MODEL = MODELS_DIR / 'phishing_model.keras'


# ════════════════════════════════════════════════════════════════════════════════
# SINGLE URL PREDICTION
# ════════════════════════════════════════════════════════════════════════════════

def predict_url(url: str, model=None, threshold: float = 0.5):
    """Predict phishing probability for a single URL."""
    from features import extract_features, FEATURE_NAMES
    from tensorflow import keras

    if model is None:
        print(f'  Loading model from {KERAS_MODEL}…')
        model = keras.models.load_model(str(KERAS_MODEL))

    features = extract_features(url)
    X = np.array([features], dtype=np.float32)
    prob = float(model.predict(X, verbose=0)[0][0])
    score = int(round(prob * 100))

    print(f'\n{"═"*55}')
    print(f'  URL ANALYSIS: {url[:50]}{"…" if len(url)>50 else ""}')
    print(f'{"═"*55}')
    print(f'  Phishing Probability: {prob:.4f} ({score}/100)')
    print(f'  Verdict:              {"🚨 PHISHING" if prob >= threshold else "✅ LEGIT"}')
    print(f'{"─"*55}')

    # Show top contributing features
    weights_path = ROOT / 'export' / 'tfjs_model' / 'feature_weights.json'
    if weights_path.exists():
        with open(weights_path) as f:
            weights = json.load(f)

        contributions = [
            (name, val * weights.get(name, 0))
            for name, val in zip(FEATURE_NAMES, features)
        ]
        contributions.sort(key=lambda x: x[1], reverse=True)

        print('  Top contributing features:')
        for name, contrib in contributions[:8]:
            if contrib > 0.01:
                bar = '█' * int(contrib * 30)
                print(f'    {name:<30} {bar} {contrib:.3f}')

    print(f'{"═"*55}\n')
    return prob, score


# ════════════════════════════════════════════════════════════════════════════════
# EVALUATION PLOTS
# ════════════════════════════════════════════════════════════════════════════════

def plot_roc_curve(y_true, y_prob, output_dir: Path):
    """Plot ROC curve and save."""
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc

    fpr, tpr, _ = roc_curve(y_true, y_prob)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(7, 6), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    ax.plot(fpr, tpr, color='#3b82f6', lw=2.5, label=f'ROC AUC = {roc_auc:.4f}')
    ax.plot([0,1],[0,1], color='#484f58', lw=1, linestyle='--', label='Random')
    ax.fill_between(fpr, tpr, alpha=0.1, color='#3b82f6')

    ax.set_xlabel('False Positive Rate', color='#8b949e')
    ax.set_ylabel('True Positive Rate',  color='#8b949e')
    ax.set_title(f'ROC Curve — AUC: {roc_auc:.4f}', color='#e6edf3', fontsize=13, fontweight='bold')
    ax.legend(facecolor='#161b22', edgecolor='#21262d', labelcolor='#e6edf3')
    ax.tick_params(colors='#8b949e')
    ax.spines[:].set_color('#21262d')

    plt.tight_layout()
    out = output_dir / 'roc_curve.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ ROC curve saved: {out}')
    return roc_auc


def plot_precision_recall(y_true, y_prob, output_dir: Path):
    """Plot Precision-Recall curve."""
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve, average_precision_score

    precision, recall, _ = precision_recall_curve(y_true, y_prob)
    avg_prec = average_precision_score(y_true, y_prob)

    fig, ax = plt.subplots(figsize=(7, 6), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    ax.plot(recall, precision, color='#22c55e', lw=2.5, label=f'AP = {avg_prec:.4f}')
    ax.fill_between(recall, precision, alpha=0.1, color='#22c55e')

    ax.set_xlabel('Recall',    color='#8b949e')
    ax.set_ylabel('Precision', color='#8b949e')
    ax.set_title(f'Precision-Recall — AP: {avg_prec:.4f}', color='#e6edf3', fontsize=13, fontweight='bold')
    ax.legend(facecolor='#161b22', edgecolor='#21262d', labelcolor='#e6edf3')
    ax.tick_params(colors='#8b949e')
    ax.spines[:].set_color('#21262d')

    plt.tight_layout()
    out = output_dir / 'pr_curve.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ PR curve saved: {out}')


def plot_confusion_matrix(y_true, y_pred, output_dir: Path):
    """Plot confusion matrix heatmap."""
    import matplotlib.pyplot as plt
    import matplotlib.colors as mcolors
    from sklearn.metrics import confusion_matrix

    cm  = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    cmap = mcolors.LinearSegmentedColormap.from_list('dark_blue', ['#0d1117', '#3b82f6'])
    im   = ax.imshow(cm, cmap=cmap, aspect='auto')

    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(['Predicted Legit', 'Predicted Phishing'], color='#8b949e')
    ax.set_yticklabels(['Actual Legit', 'Actual Phishing'],      color='#8b949e')
    ax.set_title('Confusion Matrix', color='#e6edf3', fontsize=13, fontweight='bold', pad=14)
    ax.tick_params(colors='#8b949e')
    ax.spines[:].set_color('#21262d')

    labels = [['TN', 'FP'], ['FN', 'TP']]
    colors_map = [['#22c55e', '#ef4444'], ['#f59e0b', '#22c55e']]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f'{labels[i][j]}\n{cm[i][j]:,}',
                    ha='center', va='center',
                    fontsize=14, fontweight='bold',
                    color=colors_map[i][j])

    plt.tight_layout()
    out = output_dir / 'confusion_matrix.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ Confusion matrix saved: {out}')


def plot_feature_importance(output_dir: Path):
    """Bar chart of feature importances from learned weights."""
    import matplotlib.pyplot as plt

    weights_path = ROOT / 'export' / 'tfjs_model' / 'feature_weights.json'
    if not weights_path.exists():
        print('  ⚠ feature_weights.json not found. Run train.py first.')
        return

    with open(weights_path) as f:
        weights = json.load(f)

    names  = list(weights.keys())
    values = list(weights.values())

    sorted_pairs = sorted(zip(values, names), reverse=True)[:20]
    vals, nms = zip(*sorted_pairs)

    fig, ax = plt.subplots(figsize=(9, 7), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    colors = ['#ef4444' if v > 0.7 else '#f59e0b' if v > 0.4 else '#3b82f6' for v in vals]
    bars = ax.barh(range(len(nms)), vals, color=colors, alpha=0.85, edgecolor='none')

    ax.set_yticks(range(len(nms)))
    ax.set_yticklabels(nms, color='#8b949e', fontsize=10)
    ax.set_xlabel('Feature Importance (normalized)', color='#8b949e')
    ax.set_title('Top 20 Most Important Features', color='#e6edf3', fontsize=13, fontweight='bold')
    ax.tick_params(colors='#8b949e')
    ax.spines[:].set_color('#21262d')
    ax.invert_yaxis()

    for bar, val in zip(bars, vals):
        ax.text(val + 0.01, bar.get_y() + bar.get_height()/2,
                f'{val:.3f}', va='center', ha='left', color='#8b949e', fontsize=9)

    plt.tight_layout()
    out = output_dir / 'feature_importance.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ Feature importance saved: {out}')


def plot_score_distribution(y_true, y_prob, output_dir: Path):
    """Histogram of predicted probabilities split by class."""
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8, 5), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    legit_probs   = y_prob[y_true == 0]
    phish_probs   = y_prob[y_true == 1]

    ax.hist(legit_probs,  bins=50, alpha=0.7, color='#22c55e', label='Legit',    edgecolor='none')
    ax.hist(phish_probs,  bins=50, alpha=0.7, color='#ef4444', label='Phishing', edgecolor='none')
    ax.axvline(0.5, color='#f59e0b', lw=2, linestyle='--', label='Threshold 0.5')

    ax.set_xlabel('Predicted Probability', color='#8b949e')
    ax.set_ylabel('Count',                 color='#8b949e')
    ax.set_title('Score Distribution by Class', color='#e6edf3', fontsize=13, fontweight='bold')
    ax.legend(facecolor='#161b22', edgecolor='#21262d', labelcolor='#e6edf3')
    ax.tick_params(colors='#8b949e')
    ax.spines[:].set_color('#21262d')

    plt.tight_layout()
    out = output_dir / 'score_distribution.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ Score distribution saved: {out}')


def plot_training_history(history_csv: Path, output_dir: Path):
    """Plot training vs validation loss and accuracy over epochs."""
    import csv
    import matplotlib.pyplot as plt

    if not history_csv.exists():
        print(f'  ⚠ Training log not found: {history_csv}')
        return

    with open(history_csv) as f:
        rows = list(csv.DictReader(f))

    epochs = [int(r['epoch']) + 1 for r in rows]
    tr_loss = [float(r['loss'])     for r in rows]
    vl_loss = [float(r['val_loss']) for r in rows]
    tr_acc  = [float(r['accuracy'])     for r in rows]
    vl_acc  = [float(r['val_accuracy']) for r in rows]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5), facecolor='#0d1117')
    for ax in (ax1, ax2):
        ax.set_facecolor('#0d1117')
        ax.tick_params(colors='#8b949e')
        ax.spines[:].set_color('#21262d')

    ax1.plot(epochs, tr_loss, color='#3b82f6', lw=2, label='Train Loss')
    ax1.plot(epochs, vl_loss, color='#ef4444', lw=2, label='Val Loss')
    ax1.set_title('Loss', color='#e6edf3', fontsize=12, fontweight='bold')
    ax1.set_xlabel('Epoch', color='#8b949e')
    ax1.legend(facecolor='#161b22', edgecolor='#21262d', labelcolor='#e6edf3')

    ax2.plot(epochs, tr_acc, color='#22c55e', lw=2, label='Train Acc')
    ax2.plot(epochs, vl_acc, color='#f59e0b', lw=2, label='Val Acc')
    ax2.set_title('Accuracy', color='#e6edf3', fontsize=12, fontweight='bold')
    ax2.set_xlabel('Epoch', color='#8b949e')
    ax2.legend(facecolor='#161b22', edgecolor='#21262d', labelcolor='#e6edf3')

    plt.suptitle('Training History', color='#e6edf3', fontsize=14, fontweight='bold', y=1.01)
    plt.tight_layout()
    out = output_dir / 'training_history.png'
    plt.savefig(out, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'  ✓ Training history saved: {out}')


# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='Evaluate AI Phishing Shield model')
    parser.add_argument('--url',      type=str,   help='Predict a single URL')
    parser.add_argument('--data',     type=str,   default=str(ROOT/'data'/'combined.csv'), help='Test dataset')
    parser.add_argument('--model',    type=str,   default=str(KERAS_MODEL), help='Model path')
    parser.add_argument('--plots',    action='store_true', help='Generate evaluation plots')
    parser.add_argument('--threshold',type=float, default=0.5, help='Classification threshold')
    args = parser.parse_args()

    from tensorflow import keras

    # ── Single URL mode ──────────────────────────────────────────────────────
    if args.url:
        model = keras.models.load_model(args.model)
        predict_url(args.url, model, args.threshold)
        return

    # ── Full evaluation ──────────────────────────────────────────────────────
    print('\n  Loading model…')
    model = keras.models.load_model(args.model)

    from train import load_csv_dataset, build_feature_matrix
    from sklearn.model_selection import train_test_split

    print('  Loading dataset…')
    urls, labels = load_csv_dataset(Path(args.data))
    X, y = build_feature_matrix(urls, labels)

    _, X_test, _, y_test = train_test_split(X, y, test_size=0.1, random_state=42, stratify=y)
    y_prob = model.predict(X_test, verbose=0).flatten()
    y_pred = (y_prob >= args.threshold).astype(int)

    from sklearn.metrics import roc_auc_score, classification_report
    print(f'\n  ROC-AUC: {roc_auc_score(y_test, y_prob):.4f}')
    print(classification_report(y_test, y_pred, target_names=['Legit','Phishing']))

    if args.plots:
        PLOTS_DIR.mkdir(parents=True, exist_ok=True)
        print('\n  Generating plots…')
        plot_roc_curve(y_test, y_prob, PLOTS_DIR)
        plot_precision_recall(y_test, y_prob, PLOTS_DIR)
        plot_confusion_matrix(y_test, y_pred, PLOTS_DIR)
        plot_feature_importance(PLOTS_DIR)
        plot_score_distribution(y_test, y_prob, PLOTS_DIR)
        plot_training_history(MODELS_DIR / 'training_log.csv', PLOTS_DIR)
        print(f'\n  ✓ All plots saved to: {PLOTS_DIR}')


if __name__ == '__main__':
    main()
