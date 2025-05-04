#!/usr/bin/env python3
# detect_encryption.py

"""
Ransomware Detection Tool
Part 2: Detect whether file change is suspicious (potential encryption)

Analysis:
- Memory: O(n), hashes only
- Runtime: O(n), all .txt files
- I/O: Medium (read only changed files)

Inspired by standard detection heuristics (entropy, ascii check)
"""

import os
import hashlib
import math
import string

from collections import Counter


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

    except Exception as e:
        print(f"[ERROR] Failed to analyze {file_path}: {e}")
        return False

    return False


if __name__ == "__main__":
    folder_path = "example"
    baseline_file = "baseline.csv"

    print("[INFO] Checking for encrypted/suspicious file changes...")

    old_hash_dict = {}
    with open(baseline_file, "r") as bf:
        for line_index, line in enumerate(bf):
            if line_index == 0:
                continue
            parts = line.strip().split(",")
            if len(parts) == 2:
                filepath, filehash = parts
                old_hash_dict[filepath] = filehash

    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".txt"):
                full_path = os.path.join(root, file)
                current_hash = calculate_file_hash(full_path)
                old_hash = old_hash_dict.get(full_path)

                if old_hash and current_hash != old_hash:
                    print(f"[!] File changed: {full_path}")
                    if is_suspicious(full_path):
                        print(f"[ALERT] Suspicious (possible encryption): {full_path}")
                    else:
                        print(f"[OK] Change seems normal: {full_path}")