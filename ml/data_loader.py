"""
data_loader.py — Dataset downloader and preprocessor
════════════════════════════════════════════════════════════════════════════════
Downloads:
  • PhishTank verified phishing URLs (public JSON feed)
  • ISCX URL 2016 dataset (Kaggle — requires manual download)
  • Alexa/Tranco top-1M list (legit URLs)

Generates: data/phishing.csv  (url, label=1)
           data/legit.csv     (url, label=0)
           data/combined.csv  (shuffled, balanced)
"""

import os
import csv
import gzip
import json
import random
import argparse
import requests
from pathlib import Path
from typing import List, Tuple

DATA_DIR = Path(__file__).parent / 'data'

# ─── Download helpers ─────────────────────────────────────────────────────────

def download_file(url: str, dest: Path, desc: str = '') -> bool:
    """Download a file with progress indicator."""
    try:
        print(f'  Downloading {desc or url}…')
        resp = requests.get(url, timeout=30, stream=True)
        resp.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f'  ✓ Saved to {dest}')
        return True
    except Exception as e:
        print(f'  ✗ Failed: {e}')
        return False


# ─── PhishTank ────────────────────────────────────────────────────────────────

PHISHTANK_URL = 'https://data.phishtank.com/data/online-valid.json.gz'

def load_phishtank(max_samples: int = 20000) -> List[str]:
    """Load phishing URLs from PhishTank JSON feed."""
    dest_gz  = DATA_DIR / 'phishtank.json.gz'
    dest_csv = DATA_DIR / 'phishing.csv'

    if dest_csv.exists():
        print('  PhishTank CSV already exists, loading from cache…')
        with open(dest_csv) as f:
            reader = csv.reader(f)
            return [row[0] for row in reader if row][:max_samples]

    ok = download_file(PHISHTANK_URL, dest_gz, 'PhishTank phishing URLs')
    if not ok:
        print('  ⚠ PhishTank download failed. Trying fallback sources…')
        return load_phishtank_fallback(max_samples)

    urls = []
    with gzip.open(dest_gz, 'rt', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
        for entry in data:
            url = entry.get('url', '')
            if url and entry.get('verified') == 'yes':
                urls.append(url.strip())

    random.shuffle(urls)
    urls = urls[:max_samples]

    with open(dest_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        for url in urls:
            writer.writerow([url])

    print(f'  ✓ Loaded {len(urls):,} phishing URLs from PhishTank')
    return urls


def load_phishtank_fallback(max_samples: int) -> List[str]:
    """Fallback: use a small built-in synthetic set for demonstration."""
    print('  Using synthetic phishing URL set for demonstration…')
    synthetic = [
        'http://paypa1-secure-login.xyz/account/verify',
        'http://192.168.1.1/banking/login.php',
        'http://apple-id-verify.com/signin?user=victim',
        'http://secure-bankofamerica-update.tk/auth',
        'http://login-facebook-support.ml/help/recover',
        'http://microsoft-account-alert.gq/verify',
        'http://amazon-security-notice.cf/account-suspended',
        'http://paypal.com.account-verify.xyz/secure',
        'http://netflixx-billing-update.top/payment',
        'http://chase-bank-login-secure.tk/auth/verify',
    ] * (max_samples // 10)
    return synthetic[:max_samples]


# ─── Tranco Top 1M (Legit) ───────────────────────────────────────────────────

TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'

def load_tranco(max_samples: int = 20000) -> List[str]:
    """Load legitimate URLs from Tranco top-1M list."""
    dest_csv = DATA_DIR / 'legit.csv'

    if dest_csv.exists():
        print('  Tranco CSV already exists, loading from cache…')
        with open(dest_csv) as f:
            reader = csv.reader(f)
            return ['https://' + row[1] for row in reader if len(row) >= 2][:max_samples]

    # Try downloading Tranco
    dest_zip = DATA_DIR / 'tranco.zip'
    ok = download_file(TRANCO_URL, dest_zip, 'Tranco top-1M legit domains')

    urls = []
    if ok:
        import zipfile
        with zipfile.ZipFile(dest_zip) as z:
            with z.open(z.namelist()[0]) as f:
                reader = csv.reader(line.decode() for line in f)
                for i, row in enumerate(reader):
                    if i >= max_samples: break
                    if len(row) >= 2:
                        urls.append('https://' + row[1].strip())

    if not urls:
        print('  Using fallback legit domain list…')
        legit_domains = [
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'github.com', 'reddit.com',
            'wikipedia.org', 'yahoo.com', 'bing.com', 'stackoverflow.com',
            'medium.com', 'nytimes.com', 'bbc.com', 'cnn.com',
        ]
        for i in range(max_samples):
            domain = legit_domains[i % len(legit_domains)]
            urls.append(f'https://www.{domain}/page/{i}')

    random.shuffle(urls)
    urls = urls[:max_samples]

    with open(dest_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        for url in urls:
            writer.writerow([url])

    print(f'  ✓ Loaded {len(urls):,} legit URLs from Tranco')
    return urls


# ─── Combined dataset ─────────────────────────────────────────────────────────

def build_combined_dataset(
    phishing_urls: List[str],
    legit_urls: List[str],
    balance: bool = True,
    output_path: Path = None,
) -> Tuple[List[str], List[int]]:
    """
    Combine phishing + legit URLs into a balanced dataset.
    Returns (urls, labels) where label=1 means phishing.
    """
    if balance:
        n = min(len(phishing_urls), len(legit_urls))
        phishing_urls = random.sample(phishing_urls, n)
        legit_urls    = random.sample(legit_urls,    n)
        print(f'  Balanced dataset: {n:,} phishing + {n:,} legit = {2*n:,} total')

    urls   = phishing_urls + legit_urls
    labels = [1] * len(phishing_urls) + [0] * len(legit_urls)

    # Shuffle together
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['url', 'label'])
            for u, l in zip(urls, labels):
                writer.writerow([u, l])
        print(f'  ✓ Combined dataset saved: {output_path}')

    return list(urls), list(labels)


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download and prepare phishing detection datasets')
    parser.add_argument('--samples', type=int, default=10000, help='Max samples per class (default: 10000)')
    parser.add_argument('--output', type=str, default='data/combined.csv', help='Output CSV path')
    args = parser.parse_args()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    print('\n═══ AI Phishing Shield — Data Loader ═══\n')

    print('[1/3] Loading phishing URLs…')
    phishing = load_phishtank(args.samples)

    print('[2/3] Loading legit URLs…')
    legit = load_tranco(args.samples)

    print('[3/3] Building combined dataset…')
    output = Path(args.output)
    build_combined_dataset(phishing, legit, balance=True, output_path=output)

    print('\n✓ Dataset ready. Run python train.py to begin training.\n')
