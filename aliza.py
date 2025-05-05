#!/usr/bin/env python3
# detect_encryption.py

"""
Ransomware Detection Tool
Part 2: Detect whether file change is suspicious (potential encryption or timing)

Features:
- SHA-256 hash-based comparison
- Entropy + ASCII + base64-like pattern analysis
- Detection of fast file changes (< 5s)
- Detection of mass changes (3+ files in short time)
- Detection of deleted/renamed files
"""

import os
import hashlib
import math
import string
import time
import re
from collections import Counter

def calculate_file_hash(file_path):
    print(f"[DEBUG] Calculating hash for: {file_path}")
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

def is_suspicious(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        entropy = calculate_entropy(data)
        try:
            text = data.decode("ascii")
            ascii_check = is_ascii_printable(text)
        except UnicodeDecodeError:
            ascii_check = False

        print(f"[ANALYSIS] Entropy: {entropy:.2f}, ASCII: {ascii_check}")

        if not ascii_check or entropy > 7.5:
            return True

        # Detect base64-like encoding patterns
        if ascii_check and len(text) > 100:
            if re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", text):
                print("[WARN] Base64-encoded content detected — suspicious pattern")
                return True

    except Exception as e:
        print(f"[ERROR] Failed to analyze {file_path}: {e}")
        return False

    return False

if __name__ == "__main__":
    folder_path = "example"
    baseline_file = "baseline.csv"

    print("[INFO] Starting ransomware detection...")
    print(f"[INFO] Folder path: {folder_path}")
    print(f"[INFO] Baseline file: {baseline_file}")

    if not os.path.exists(baseline_file):
        print("[DEBUG] Baseline file not found, creating it now...")
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

    new_hash_dict = {}
    change_times = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".txt"):
                full_path = os.path.join(root, file)
                current_hash = calculate_file_hash(full_path)
                new_hash_dict[full_path] = current_hash

                old_hash = old_hash_dict.get(full_path)
                if old_hash is None:
                    print(f"[NEW] New file detected: {full_path}")
                elif current_hash != old_hash:
                    print(f"[!] File changed: {full_path}")

                    # Check if file changed very recently (< 5s ago)
                    mod_time = os.path.getmtime(full_path)
                    time_since_change = time.time() - mod_time
                    if time_since_change < 5:
                        print(f"[ALERT] File changed VERY recently ({time_since_change:.2f}s ago): {full_path}")

                    change_times.append(mod_time)

                    if is_suspicious(full_path):
                        print(f"[ALERT] Suspicious (possible encryption): {full_path}")
                    else:
                        print(f"[OK] Change seems normal: {full_path}")
                else:
                    print(f"[-] File {full_path} was not changed (same hash).")

    # Detect deleted or renamed files
    missing_files = set(old_hash_dict.keys()) - set(new_hash_dict.keys())
    for missing in missing_files:
        print(f"[ALERT] File missing (deleted or renamed): {missing}")

    # Detect 3+ changes in under 5 seconds (mass-change behavior)
    if len(change_times) >= 3:
        change_times.sort()
        for i in range(len(change_times) - 2):
            if change_times[i+2] - change_times[i] < 5:
                print("[ALERT] Multiple file changes detected in under 5 seconds — possible ransomware behavior!")
                break

    # Save updated baseline
    print("[INFO] Updating baseline file with current hashes...")
    with open(baseline_file, "w") as bf:
        bf.write("FilePath,Hash\n")
        for path, fhash in new_hash_dict.items():
            bf.write(f"{path},{fhash}\n")

    print("[DONE] Process completed. Check debug messages above for details.")
