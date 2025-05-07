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

import os # for file operations
import hashlib # for hashing
import math # for entropy calculation
import string # for ascii check
import re # for regex matching
from collections import Counter # for counting characters

# Function to calculate the SHA-256 hash of a file
def calculate_file_hash(file_path):
    sha256 = hashlib.sha256() # create a new sha256 hash object
    with open(file_path, "rb") as f: # open the file in binary mode
        for chunk in iter(lambda: f.read(4096), b""): # read the file in chunks
            sha256.update(chunk) # update the hash with the chunk
    return sha256.hexdigest() # return the hex digest of the hash

# Function to calculate the entropy of a byte array (Entropy is a measure of randomness)
def calculate_entropy(data):
    if not data: # if the data is empty
        return 0 # return 0 entropy
    counter = Counter(data) # count the occurrences of each byte
    total = len(data) # total number of bytes
    return -sum((count / total) * math.log2(count / total) for count in counter.values()) # calculate entropy

# Function to check if a string is ASCII printable
def is_ascii_printable(text):
    return all(c in string.printable for c in text) # check if all characters are printable

# Detect common encoding patterns
def is_encoded(text):
    # Encoding patterns
    base64_pattern = r"^[A-Za-z0-9+/=\r\n]+$"
    hex_pattern = r"^[0-9A-Fa-f\r\n]+$"
    base32_pattern = r"^[A-Z2-7=\r\n]+$"
    url_pattern = r"^%[0-9A-Fa-f]{2}$"
    uuencode_pattern = r"^begin [0-7]{3} .+\n[ -`]+end$"
    quoted_printable_pattern = r"^[A-Za-z0-9=]+$"
    base85_pattern = r"^[!-u]+$"
    rot13_pattern = r"^[A-Za-z\r\n]+$"

    # Match against known encoding patterns
    if re.fullmatch(base64_pattern, text):
        return "Base64"
    elif re.fullmatch(hex_pattern, text):
        return "Hex"
    elif re.fullmatch(base32_pattern, text):
        return "Base32"
    elif re.fullmatch(url_pattern, text):
        return "URL Encoding"
    elif re.fullmatch(uuencode_pattern, text):
        return "UUencode"
    elif re.fullmatch(quoted_printable_pattern, text):
        return "Quoted-Printable"
    elif re.fullmatch(base85_pattern, text):
        return "Base85"
    elif re.fullmatch(rot13_pattern, text):
        return "Rot13"
    return None

def is_suspicious(file_path):
    try:
        with open(file_path, "rb") as f: # open the file in binary mode
            data = f.read() # read the entire file

        entropy = calculate_entropy(data) # calculate the entropy
        try:
            text = data.decode("ascii") # try to decode the data as ASCII
            ascii_check = is_ascii_printable(text) # check if the text is ASCII printable
        except UnicodeDecodeError: # if decoding fails
            ascii_check = False

        print(f"[ANALYSIS] Entropy: {entropy:.2f}, ASCII: {ascii_check}")

        # Improved Base64 detection
        if ascii_check:
            encoding_type = is_encoded(text)
            if encoding_type:
                print(f"[ALERT] {encoding_type}-like content detected: {file_path}")
                return True

            # # Check for Base64 pattern and characteristics
            # base64_pattern = r"^[A-Za-z0-9+/=\r\n]+$"
            # if re.fullmatch(base64_pattern, text):
            #     # Additional Base64 characteristics:
            #     is_multiple_of_4 = len(text.strip()) % 4 == 0
            #     ends_with_equals = text.strip().endswith("=")
            #     alpha_num_ratio = sum(c.isalnum() for c in text) / len(text)
            #
            #     # Conditions to flag as Base64:
            #     if is_multiple_of_4 and ends_with_equals and alpha_num_ratio > 0.7:
            #         print(f"[ALERT] Base64-like content detected: {file_path}")
            #         return True

        # Check if the file is suspicious based on entropy and ASCII check
        if not ascii_check or entropy > 7.5:
            return True

        # Additional detection for partially encrypted files (heuristic)
        if 4.5 < entropy < 7.5 and not ascii_check:
            print(f"[ALERT] Mixed content detected (possible partial encryption): {file_path}")
            return True

    # Handle any exceptions that occur during file reading or analysis
    except Exception as e:
        print(f"[ERROR] Failed to analyze {file_path}: {e}")
        return False

    return False # if the file is not suspicious

# Detect rapid changes within a short period
def detect_mass_changes(change_times):
    if len(change_times) >= 3:
        change_times.sort()
        for i in range(len(change_times) - 2):
            if change_times[i+2] - change_times[i] < 5:
                print("[ALERT] Multiple file changes detected within 5 seconds!")
                return True
    return False

if __name__ == "__main__":
    folder_path = "example" # directory to scan for .txt files
    baseline_file = "baseline.csv" # baseline file to store hashes

    # Create baseline if not exists
    if not os.path.exists(baseline_file):
        with open(baseline_file, "w") as bf: # open the baseline file in write mode
            bf.write("FilePath,Hash\n") # write header
            for root, dirs, files in os.walk(folder_path): # walk through the directory
                for file in files: # for each file
                    if file.lower().endswith(".txt"): # if the file is a .txt file
                        full_path = os.path.join(root, file) # get a full path
                        f_hash = calculate_file_hash(full_path) # calculate hash
                        bf.write(f"{full_path},{f_hash}\n") # write to baseline
        print("[INFO] Baseline file created successfully!") # success message

    # Load baseline
    old_hash_dict = {} # dictionary to store old hashes
    with open(baseline_file, "r") as bf: # open the baseline file in read mode
        for line_index, line in enumerate(bf): # read each line
            # Skip header line
            if line_index == 0:
                continue

            # Split line into filepath and hash
            parts = line.strip().split(",") # split by comma
            if len(parts) == 2: # if there are two parts
                filepath, filehash = parts # get filepath and hash
                old_hash_dict[filepath] = filehash # store in dictionary

    # Detect suspicious file changes
    new_hash_dict = {} # dictionary to store new hashes
    change_times = [] # list to store change times
    for root, dirs, files in os.walk(folder_path): # walk through the directory
        for file in files: # for each file
            if file.lower().endswith(".txt"): # if the file is a .txt file
                full_path = os.path.join(root, file) # get a full path
                current_hash = calculate_file_hash(full_path) # calculate hash
                new_hash_dict[full_path] = current_hash # store in new hash dictionary
                current_modified = os.path.getmtime(full_path) # get the last modified time

                old_hash = old_hash_dict.get(full_path) # get old hash from dictionary

                # If the file is not in the old hash dictionary, it is new
                if old_hash is None:
                    print(f"[NEW] New file detected: {full_path}")

                # If the file is in the old hash dictionary, check for changes
                elif current_hash != old_hash: # if the hashes are different
                    print(f"[!] File changed: {full_path}") # file changed message
                    change_times.append(current_modified)

                    if is_suspicious(full_path): # check if the file is suspicious
                        print(f"[ALERT] Suspicious (possible encryption): {full_path}")

                    else: # if the file is not suspicious
                        print(f"[OK] Change seems legitimate: {full_path}")

                # If the file hash is the same, it has not changed
                else:
                    print(f"[-] File {full_path} was not changed (same hash).")

    # Update baseline
    with open(baseline_file, "w") as bf: # open the baseline file in write mode
        bf.write("FilePath,Hash\n") # write header
        for path, fhash in new_hash_dict.items(): # for each file in new hash dictionary
            bf.write(f"{path},{fhash}\n") # write to baseline

    # Detect rapid mass changes
    detect_mass_changes(change_times)
    print("[DONE] Process completed.")