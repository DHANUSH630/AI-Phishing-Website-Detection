# AI Phishing Shield — ML Training Guide

> Train the neural network that powers real-time phishing detection inside the browser extension.

---

## Architecture

```
Input (42 features)
       │
  Dense(64, relu) + BatchNorm + Dropout(0.3)
       │
  Dense(32, relu) + BatchNorm + Dropout(0.2)
       │
  Dense(16, relu)
       │
  Dense(1, sigmoid)  →  Phishing Probability [0–1]
```

Matches `model.js` layer-for-layer so trained weights transfer directly.

---

## Quick Start

### 1. Install dependencies

```bash
cd "d:\STUFF\AI Phishing Detection\ml"
pip install -r requirements.txt
```

### 2. Download datasets + train (one command)

```bash
python train.py --download-data --epochs 40
```

### 3. Train on existing data

```bash
python train.py --epochs 40 --batch-size 256
```

### 4. Evaluate a single URL

```bash
python evaluate.py --url "http://paypa1-secure.xyz/login"
```

### 5. Generate evaluation plots

```bash
python evaluate.py --plots
```

---

## Scripts

| File | Purpose |
|------|---------|
| `features.py` | 42-feature extractor (mirrors `features.js` exactly) |
| `data_loader.py` | Downloads PhishTank + Tranco datasets |
| `train.py` | Full training pipeline with TF.js export |
| `evaluate.py` | Metrics, plots, single-URL prediction |

---

## Dataset Sources

| Dataset | Type | Size | Access |
|---------|------|------|--------|
| [PhishTank](https://www.phishtank.com/developer_info.php) | Phishing URLs | ~80K verified | Free (API key optional) |
| [Tranco Top-1M](https://tranco-list.eu/) | Legit domains | 1,000,000 | Free download |
| [ISCX-URL-2016](https://www.kaggle.com/sid321axn/malicious-urls-dataset) | Both | 651K | Kaggle account |

---

## Features (42 total)

| # | Feature | Description |
|---|---------|-------------|
| 0 | `urlLength` | Total URL character count / 200 |
| 1 | `domainLength` | Hostname length / 50 |
| 2 | `subdomainDepth` | Number of subdomain levels / 5 |
| 3 | `hasHttps` | Uses HTTPS (1=yes) |
| 4 | `hasIpAddress` | Domain is an IP address |
| 5 | `hasPortInUrl` | Non-standard port present |
| 6 | `numDots` | Count of `.` chars / 10 |
| 7 | `numHyphens` | Count of `-` chars / 5 |
| 8 | `numUnderscores` | Count of `_` chars / 5 |
| 9 | `numSlashes` | Count of `/` chars / 10 |
| 10 | `numAtSymbols` | `@` in URL |
| 11 | `numQuestionMarks` | Count of `?` / 3 |
| 12 | `numEquals` | Count of `=` / 5 |
| 13 | `numAmpersands` | Count of `&` / 5 |
| 14 | `numPercents` | Count of `%` / 5 |
| 15 | `numDigitsInDomain` | Digit count in hostname / 10 |
| 16 | `pathLength` | URL path length / 100 |
| 17 | `queryLength` | Query string length / 100 |
| 18 | `hasDoubleSlash` | `//` in path |
| 19 | `hasDashInDomain` | Hyphen in hostname |
| 20 | `domainEntropy` | Shannon entropy of hostname / 4 |
| 21 | `pathEntropy` | Shannon entropy of path / 4 |
| 22 | `tldSuspicious` | TLD is in suspicious list (xyz, tk, ml…) |
| 23 | `domainAge` | Domain registration age (0.5=unknown) |
| 24 | `hasSuspiciousKeyword` | "secure", "verify", "banking"… |
| 25 | `hasLoginKeyword` | "login", "signin", "auth"… |
| 26 | `hasBrandKeyword` | Brand name in URL but not in domain |
| 27 | `hasSecureKeyword` | "ssl", "protected", "encrypted"… |
| 28 | `urlEntropyTotal` | Shannon entropy of full URL / 5 |
| 29 | `consonantRatio` | Consonant-to-letter ratio |
| 30 | `digitRatio` | Digit-to-character ratio |
| 31 | `specialCharRatio` | Special character ratio |
| 32 | `longestWordLength` | Longest token in URL / 30 |
| 33 | `avgWordLength` | Average token length / 15 |
| 34 | `numSubdomains` | Subdomain count / 5 |
| 35 | `freeHosting` | Domain uses free hosting service |
| 36 | `urlShortenService` | Domain is a URL shortener |
| 37 | `hexEncoding` | URL contains `%XX` hex encoding |
| 38 | `dataUriScheme` | URL starts with `data:` |
| 39 | `levenshteinMin` | Min edit distance to known brand domains / 20 |
| 40 | `domainRepeatedChars` | 3+ consecutive repeated chars in domain |
| 41 | `pathDepth` | Number of path segments / 8 |

---

## Training Output

After training, files are saved to:

```
ml/
├── models/
│   ├── phishing_model.keras     # Best Keras checkpoint
│   ├── training_log.csv         # Per-epoch metrics
│   ├── metrics.json             # Final test metrics
│   └── logs/                    # TensorBoard logs
├── export/
│   └── tfjs_model/
│       ├── model.json           # TF.js model topology
│       ├── group1-shard1of1.bin # Weights
│       └── feature_weights.json # Linear fallback weights
└── plots/
    ├── roc_curve.png
    ├── pr_curve.png
    ├── confusion_matrix.png
    ├── feature_importance.png
    ├── score_distribution.png
    └── training_history.png
```

### Deploying to the extension

```bash
# Copy TF.js model to extension
cp ml/export/tfjs_model/model.json extension/ml/
cp ml/export/tfjs_model/*.bin       extension/ml/

# Then reload extension at chrome://extensions/
```

---

## Expected Performance

With 10K balanced samples (PhishTank + Tranco):

| Metric | Expected |
|--------|----------|
| ROC-AUC | 0.97–0.99 |
| Accuracy | 96–98% |
| Precision | 95–97% |
| Recall | 96–98% |
| False Positive Rate | 2–4% |
| False Negative Rate | 1–3% |

> **Note**: The extension uses a blended score (neural network + rule-based + DOM analysis) so the real-world accuracy is higher than the URL-only model figures above.
