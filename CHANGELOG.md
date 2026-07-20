# Changelog

All notable changes to the **AI Phishing Shield** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-07-20
### Added
* **Unit Testing Suite**: Created `test/run-tests.mjs` checking URL parsing, feature vectors, whitelists, and model scoring thresholds.
* **Privacy Compliance**: Added `privacy.html` detailing zero-server data processing and local-only sandbox storage for Chrome Web Store compliance.
* **Trusted Whitelists**: Integrated academic (`.edu`, `.ac.in`), government (`.gov`), and major trusted base domains (like `google.com`, `overleaf.com`) to bypass scanning and cap scores at 10 (Safe).
* **Assets & Visuals**: Generated mockups for the popup UI, standalone dashboard, and warning overlays, added to `assets/` and linked in `README.md`.

### Changed
* **Scorer Recalibration**: Shuffled feature weights to reduce false positive alerts on safe pages. Shifted weighted linear model bias from `-3.2` to `-6.5` to lower benign site scores.
* **Minimal Permission Footprint**: Removed heavy permissions (`tabs`, `activeTab`, `webNavigation`, `scripting`, `alarms`) from `manifest.json`.
* **Standard Tabs Integration**: Replaced the `webNavigation` API with standard `chrome.tabs.onUpdated` events for scanning triggers, reducing CWS security review scrutiny.

### Fixed
* **Infinite Scans Loop**: Patched `content.js` to prevent infinite messaging scans that caused browser freeze and blank pages on DOM-triggered actions.
* **File URL Crashes**: Suppressed errors on `file://` URL logs by wrapping `chrome.tabs.get` in try-catch and creating crash-safe hostname defaults.

---

## [1.0.0] - 2026-07-19
### Added
* **MV3 Extension Core**: Standard manifest V3 service worker activation and popup layout.
* **Local ML Inference**: Integrated TensorFlow.js layers model running locally inside the browser service worker.
* **15-check DOM Scanner**: Active content scripts verifying cross-origin actions, honeypots, iframe overlays, copy blockers, and script obfuscation.
* **Explainable AI UI**: A 4-tab popup design displaying risk scores, XAI feature lists, allow/block toggles, and settings controls.
* **Warning Overlay**: Full-screen blocking UI featuring a 5-second proceed lock and a 15-second return-to-safety countdown for critical threats.
* **Web Dashboard**: Interactive admin panel showing scan trends, Chart.js doughnut metrics, threats heatmaps, allow/block lists management, and paginated logs.
* **Python ML Pipeline**: Python scripts (`train.py`, `data_loader.py`, `evaluate.py`) for balanced data compiling, model training, evaluation plots, and TF.js model exports.

---

## [2.0.0] - Future Roadmap
### Planned
* **Cloud Allowlist Sync**: Sync trusted domains across user instances using `chrome.storage.sync`.
* **NLP Domain Parsing**: Add transformer-based sub-domain parsing to detect sophisticated typosquatting patterns.
* **Right-Click Context Scanner**: Scan any highlighted link before clicking using context menus.

---

## 🏷️ How to Publish Releases on GitHub

To publish these versions on your GitHub repository as formal releases:

### 1. Tag the Commit Locally
```bash
# Tag the current commit with the version
git tag -a v1.1.0 -m "Release v1.1.0 — Calibrated AI & Minimal MV3 Permissions"

# Push the tag to GitHub
git push origin v1.1.0
```

### 2. Create the GitHub Release
1. Navigate to your repository at [GitHub - DHANUSH630/AI-Phishing-Website-Detection](https://github.com/DHANUSH630/AI-Phishing-Website-Detection).
2. On the right side of the page, click on **Releases** $\rightarrow$ **Draft a new release**.
3. Choose the tag **`v1.1.0`** you just pushed.
4. Set the Release Title to `AI Phishing Shield v1.1.0`.
5. Copy the Changelog section for `[1.1.0]` into the description box.
6. Click **Publish Release**!
