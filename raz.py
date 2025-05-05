#!/usr/bin/env python3
# detect_encryption.py

"""
Ransomware Detection Tool
Detect whether file change is suspicious (potential encryption)

Enhanced to detect:
- Base64 encoding (via structure and decoded entropy)
- High content mutation ratio
- Low Index of Coincidence (IC)

Efficiency:
- Memory: O(n) (hashes, stats)
- Runtime: O(n) for .txt files
- I/O: Medium
"""

import os
import hashlib
import math
import string
import base64
from collections import Counter

# === Utility Functions ===

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def calculate_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counter.values())

def is_ascii_printable(text):
    return all(c in string.printable for c in text)

def index_of_coincidence(data):
    if not data:
        return 0
    freqs = Counter(data)
    N = len(data)
    return sum(f * (f - 1) for f in freqs.values()) / (N * (N - 1)) if N > 1 else 0

def get_change_ratio(before, after):
    min_len = min(len(before), len(after))
    diffs = sum(1 for i in range(min_len) if before[i] != after[i])
    diffs += abs(len(before) - len(after))
    return diffs / max(len(before), 1)


def looks_like_base64_encoded(data, min_ratio=0.95):
    base64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r"
    b64_bytes = sum(byte in base64_chars for byte in data)
    ratio = b64_bytes / len(data) if data else 0
    if ratio < min_ratio:
        return False

    try:
        # Try to decode it
        clean_data = b"".join(data.split())
        decoded = base64.b64decode(clean_data, validate=True)

        # Check if the length of decoded data is within reasonable bounds
        if len(decoded) * 1.3 <= len(data) <= len(decoded) * 1.5:
            entropy_decoded = calculate_entropy(decoded)
            # Ensure that entropy after decoding is high
            if entropy_decoded > 7.5:
                print(f"[BASE64] Decoded data with high entropy: {entropy_decoded:.2f}")
                return True
    except Exception:
        return False

    return False

# === Detection Logic ===

def is_suspicious(file_path, old_data=None):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        entropy = calculate_entropy(data)
        ioc = index_of_coincidence(data)
        base64_check = looks_like_base64_encoded(data)

        try:
            text = data.decode("ascii")
            ascii_check = is_ascii_printable(text)
        except UnicodeDecodeError:
            ascii_check = False

        print(f"[ANALYSIS] {file_path} → Entropy: {entropy:.2f}, IC: {ioc:.3f}, ASCII: {ascii_check}, Base64-like: {base64_check}")

        if base64_check or entropy > 7.5 or not ascii_check or ioc < 0.04:
            if old_data:
                delta = get_change_ratio(old_data, data)
                print(f"[DELTA] Change ratio: {delta:.2%}")
                if delta > 0.6:
                    return True
            else:
                return True

    except Exception as e:
        print(f"[ERROR] Failed to analyze {file_path}: {e}")
        return False

    return False

# === Main Script ===

if __name__ == "__main__":
    folder_path = "example"
    baseline_file = "baseline.csv"
    data_snapshots = {}

    if not os.path.exists(baseline_file):
        with open(baseline_file, "w") as bf:
            bf.write("FilePath,Hash\n")
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if file.lower().endswith(".txt"):
                        full_path = os.path.join(root, file)
                        f_hash = calculate_file_hash(full_path)
                        bf.write(f"{full_path},{f_hash}\n")
        print("[INFO] Baseline file created successfully!")

    old_hash_dict = {}
    with open(baseline_file, "r") as bf:
        for line_index, line in enumerate(bf):
            if line_index == 0:
                continue
            parts = line.strip().split(",")
            if len(parts) == 2:
                filepath, filehash = parts
                old_hash_dict[filepath] = filehash
                try:
                    with open(filepath, "rb") as f:
                        data_snapshots[filepath] = f.read()
                except:
                    pass

    new_hash_dict = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".txt"):
                full_path = os.path.join(root, file)
                current_hash = calculate_file_hash(full_path)
                new_hash_dict[full_path] = current_hash

                old_hash = old_hash_dict.get(full_path)
                old_data = data_snapshots.get(full_path)

                if old_hash is None:
                    print(f"[NEW] New file detected: {full_path}")

                elif current_hash != old_hash:
                    print(f"[!] File changed: {full_path}")
                    if is_suspicious(full_path, old_data):
                        print(f"[ALERT] Suspicious (possible encryption): {full_path}")
                    else:
                        print(f"[OK] Change seems legitimate: {full_path}")

                else:
                    print(f"[-] File {full_path} was not changed (same hash).")

    with open(baseline_file, "w") as bf:
        bf.write("FilePath,Hash\n")
        for path, fhash in new_hash_dict.items():
            bf.write(f"{path},{fhash}\n")

    print("[DONE] Process completed.")