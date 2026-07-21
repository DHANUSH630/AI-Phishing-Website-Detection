import os
import zipfile

source_dir = r"d:\STUFF\AI Phishing Detection\extension"
output_zip = r"d:\STUFF\AI Phishing Detection\extension-dist.zip"

if os.path.exists(output_zip):
    os.remove(output_zip)

with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(source_dir):
        for file in files:
            # Full local file path
            file_path = os.path.join(root, file)
            # Relative path inside the ZIP (so manifest.json is at the root)
            rel_path = os.path.relpath(file_path, source_dir)
            # Replace backslashes with forward slashes for cross-platform compliance
            zip_rel_path = rel_path.replace(os.sep, '/')
            zipf.write(file_path, zip_rel_path)

print("SUCCESS: extension-dist.zip created with forward slashes!")
