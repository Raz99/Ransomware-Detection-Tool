import os
import hashlib


def calculate_file_hash(file_path):
    print(f"[DEBUG] Calculating hash for: {file_path}")
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


if __name__ == "__main__":
    folder_path = "example"  # or "/home/user/folder" on Linux
    baseline_file = "baseline.csv"

    print("[INFO] Starting file hash comparison process...")
    print(f"[INFO] Folder path: {folder_path}")
    print(f"[INFO] Baseline file: {baseline_file}")

    # If the baseline file doesn't exist, create it once
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

    # Read the existing baseline into a dictionary
    old_hash_dict = {}
    with open(baseline_file, "r") as bf:
        lines = bf.readlines()
        for line_index, line in enumerate(lines):
            if line_index == 0:  # Skip header
                continue
            parts = line.strip().split(",")
            if len(parts) == 2:
                filepath, filehash = parts
                old_hash_dict[filepath] = filehash

    print(f"[DEBUG] Number of entries in baseline: {len(old_hash_dict)}")

    # Compare the current hash to the stored baseline hash
    new_hash_dict = {}
    print("[INFO] Scanning directory...")
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(".txt"):
                full_path = os.path.join(root, file)
                print(f"[DEBUG] Checking: {full_path}")
                current_hash = calculate_file_hash(full_path)
                new_hash_dict[full_path] = current_hash

                old_hash = old_hash_dict.get(full_path)
                if old_hash is None:
                    print(f"[NEW] New file detected: {full_path}")
                else:
                    if old_hash == current_hash:
                        print(f"[-] File {full_path} was not changed (same hash).")
                    else:
                        print(f"[!] File {full_path} has changed! (Old: {old_hash}, New: {current_hash})")

    # Update the baseline file
    print("[INFO] Updating baseline file with current hashes...")
    with open(baseline_file, "w") as bf:
        bf.write("FilePath,Hash\n")
        for path, fhash in new_hash_dict.items():
            bf.write(f"{path},{fhash}\n")

    print("[DONE] Process completed. Check debug messages above for details.")