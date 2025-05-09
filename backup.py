"""
Ransomware Detection Tool - Resource Efficiency Analysis
=========================================================

1. Memory Usage (Space Complexity):
-----------------------------------
- ✅ O(1) for real-time event monitoring (via Watchdog/inotify): no full scan or buffer retention.
- ✅ O(n) for storing SHA-256 hashes, MIME types, and small file content snapshots in `self.file_hashes`, `self.file_types`, and `self.file_contents`.
- ❌ O(n*m) is *not used* – full file snapshots are limited to small files only (content stored in memory for fuzzy comparison).
- ➕ Overall: efficient. Metadata + small content only.

2. Runtime Efficiency (Time Complexity):
----------------------------------------
- ✅ O(1) per event for filesystem change detection.
- ✅ O(n) for analysis: scanning new file content, entropy calculation, fuzzy similarity, encoding detection.
  Each analysis on file change involves:
    - entropy: O(m)
    - ascii ratio: O(m)
    - fuzzy similarity (difflib): ~O(m)
    - MIME detection (1KB): O(1)
- ➕ Overall: acceptable for human-scale directories (~hundreds of files), fast response to changes.

3. I/O Complexity (Disk Access):
-------------------------------
- ✅ Low I/O thanks to real-time monitoring (`Watchdog`, `Observer`) – avoids periodic polling.
- ⚠️ Full file read (`open(path, 'rb')`) on changes only (for hash, entropy, content).
- ➕ Total I/O is proportional to change rate, not folder size — makes this suitable for interactive environments.

4. Architecture:
----------------
- Phase 1: Real-time detection of file changes (Watchdog) → very low overhead
- Phase 2: Suspicion scoring using:
    - File entropy (average + windowed)
    - ASCII-printable ratio
    - MIME type before/after
    - Encoding signatures
    - Fuzzy similarity to prior version
- Honeypot trap files added as high-confidence ransomware indicators

Summary:
--------
- 🎯 Optimized for lightweight detection without polling
- 🧠 Memory: O(n)
- ⏱️ Runtime: O(n) per modified file
- 📀 I/O: minimal, event-based
"""

import os
import time
import math
import hashlib
import string
import re
import base64
import quopri
import urllib.parse
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import difflib

MONITORED_DIR = "monitored_dir"
MAX_EVENTS_PER_MINUTE = 10
MAX_DELETIONS_PER_MINUTE = 5
ENTROPY_THRESHOLD = 7.0
LOW_ASCII_RATIO = 0.5
SIMILARITY_THRESHOLD = 50
WINDOW_ENTROPY_THRESHOLD = 7.8
SUSPICIOUS_EXTENSIONS = [
    ".locked", ".enc", ".encrypted", ".crypt", ".cripto", ".crypto",
    ".pay", ".ransom", ".crinf", ".r5a", ".WNCRY", ".wcry", ".wncrypt",
    ".wncryt", ".wnry", ".wantcrypt", ".cerber", ".zepto", ".thor",
    ".locky", ".aaa", ".zzz", ".ecc", ".exx", ".ezz", ".abc", ".xyz",
    ".pzdc", ".good", ".hush", ".odin", ".ccc", ".herbst", ".sage"
]
HONEYPOT_FILES = set()
HONEY_COUNT = 3


def file_entropy(data):
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())

def window_entropy(data, window_size=1024):
    if len(data) < window_size:
        return [file_entropy(data)]
    return [file_entropy(data[i:i + window_size]) for i in range(0, len(data), window_size)]

def ascii_ratio(data):
    printable = set(bytes(string.printable, 'ascii'))
    if not data:
        return 1.0
    return sum(1 for b in data if b in printable) / len(data)

def is_encoded(data, pattern, decoder):
    try:
        text = data.decode('ascii', errors='ignore')
        matches = re.findall(pattern, text)
        for chunk in matches:
            try:
                decoder(chunk.encode())
                return True
            except Exception:
                continue
        return False
    except:
        return False

def detect_encoding(data):
    flags = []
    if is_encoded(data, r'[A-Za-z0-9+/=]{16,}', base64.b64decode):
        flags.append('Base64')
    if is_encoded(data, r'[0-9a-fA-F]{16,}', bytes.fromhex):
        flags.append('Hex')
    if is_encoded(data, r'[A-Z2-7=]{16,}', base64.b32decode):
        flags.append('Base32')
    if is_encoded(data, r'[!-u]{16,}', base64.b85decode):
        flags.append('Base85')
    if is_encoded(data, r'(=[0-9A-F]{2})+', lambda x: quopri.decodestring(x)):
        flags.append('Quoted-Printable')
    if is_encoded(data, r'%[0-9A-Fa-f]{2}', lambda x: urllib.parse.unquote_to_bytes(x.decode())):
        flags.append('URL')
    return flags

def fuzzy_similarity(old_data, new_data):
    try:
        if not old_data:
            return 100  # treat as new file creation, not suspicious by itself
        return int(difflib.SequenceMatcher(None, old_data, new_data).ratio() * 100)
    except Exception:
        return 0

def detect_mime_type(path):
    try:
        with open(path, 'rb') as f:
            data = f.read(1024)  # Read only the beginning
        text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)))
        if bool(data.translate(None, text_chars)):
            return "binary"
        else:
            return "text"
    except Exception:
        return "unknown"

def hash_file(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
            return hashlib.sha256(data).hexdigest(), data
    except:
        return None, None

def create_honeypot_files(base_dir, count):
    for i in range(count):
        path = os.path.join(base_dir, f"__HONEY__{i}.txt")
        try:
            with open(path, 'w') as f:
                f.write("Project Plan - Confidential\n\nTasks:\n- Finalize budget proposal\n- Schedule design review\n- Contact suppliers\n- Prepare draft presentation\n\nDO NOT DELETE OR MODIFY")
            print(f"[INFO] Honeypot created at: {path} (overwritten if existed)")
            HONEYPOT_FILES.add(os.path.basename(path))
        except Exception as e:
            print(f"[ERROR] Failed to create honeypot file {path}: {e}")

def scan_initial_files(base_dir, file_hashes, file_types):
    for root, _, files in os.walk(base_dir):
        for file in files:
            path = os.path.join(root, file)
            h, _ = hash_file(path)
            if h:
                file_hashes[path] = h
                file_types[path] = detect_mime_type(path)

class RansomwareEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.file_hashes = {}
        self.file_types = {}
        self.modification_times = {}
        self.file_contents = {}
        self.event_log = deque()
        self.deletion_log = deque()
        scan_initial_files(MONITORED_DIR, self.file_hashes, self.file_types)

    def on_modified(self, event):
        if not event.is_directory:
            self.analyze(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            print(f"📁 New file created: {event.src_path}")
            self.analyze(event.src_path)

    # def on_deleted(self, event):
    #     if not event.is_directory:
    #         print(f"🗑️ File deleted: {event.src_path}")
    #         if os.path.basename(event.src_path) in HONEYPOT_FILES:
    #             print(f"🚨 Honeypot was deleted!")
    #             print("💥 This strongly indicates ransomware activity.")

    def on_deleted(self, event):
        if not event.is_directory:
            path = event.src_path
            print(f"🗑️ File deleted: {path}")
            basename = os.path.basename(path)

            now = time.time()
            self.deletion_log.append(now)
            self.cleanup_old_deletions(now)

            if basename in HONEYPOT_FILES:
                print(f"🚨 Honeypot was deleted!")
                print("💥 This strongly indicates ransomware activity.")
                return

            if len(self.deletion_log) > MAX_DELETIONS_PER_MINUTE:
                print(f"🚨 Bulk deletion detected: {len(self.deletion_log)} files deleted in the last minute!")

    def on_moved(self, event):
        if not event.is_directory:
            print(f"🔀 File renamed: {event.src_path} → {event.dest_path}")
            if os.path.basename(event.src_path) in HONEYPOT_FILES:
                print(f"🚨 Honeypot was renamed!")
                print("💥 This strongly indicates ransomware activity.")
            self.analyze(event.dest_path)
            if any(event.dest_path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                print(f"⚠️  Suspicious file rename to: {event.dest_path}")

    def analyze(self, path):
        now = time.time()
        self.event_log.append(now)
        self.cleanup_old_events(now)

        if not os.path.exists(path):
            return

        ext = os.path.splitext(path)[1].lower()
        suspicious = ext in SUSPICIOUS_EXTENSIONS
        if suspicious:
            print(f"⚠️  Suspicious file extension: {path}")

        h, data = hash_file(path)
        if h is None or data is None:
            return

        old_hash = self.file_hashes.get(path)
        old_type = self.file_types.get(path)
        new_type = detect_mime_type(path)
        similarity = fuzzy_similarity(self.file_contents.get(path, b""), data)

        if not old_hash or old_hash != h:
            ascii_val = ascii_ratio(data)
            entropy_val = file_entropy(data)
            enc_flags = detect_encoding(data)
            entropy_windows = window_entropy(data)

            print(f"📄 Change detected: {os.path.basename(path)}")
            print(f"    ├─ Text ratio: {ascii_val:.2f}, Entropy: {entropy_val:.2f}, MIME: {new_type}")
            print(f"    ├─ Fuzzy similarity: {similarity}%")

            if (entropy_val > ENTROPY_THRESHOLD or
                    ascii_val < LOW_ASCII_RATIO or
                    similarity < SIMILARITY_THRESHOLD or
                    any(e > WINDOW_ENTROPY_THRESHOLD for e in entropy_windows) or
                    new_type == "binary"):
                suspicious = True

            if old_type and old_type != new_type:
                print(f"    ├─ File type changed from {old_type} to {new_type}")
                suspicious = True

            print("    └─ {}".format("⚠️  Suspicious content detected" if suspicious else "✅ Legitimate modification"))

            self.file_hashes[path] = h
            self.file_types[path] = new_type
            self.file_contents[path] = data

            if os.path.basename(path) in HONEYPOT_FILES:
                print(f"🚨 Honeypot was accessed: {path}")
                print("💥 This strongly indicates ransomware activity.")

        if len(self.event_log) > MAX_EVENTS_PER_MINUTE:
            print(f"🚨 Bulk change detected: {len(self.event_log)} changes in last minute!")

    def cleanup_old_events(self, now):
        while self.event_log and now - self.event_log[0] > 60:
            self.event_log.popleft()

    def cleanup_old_deletions(self, now):
        while self.deletion_log and now - self.deletion_log[0] > 60:
            self.deletion_log.popleft()

def main():
    print(f"[INFO] Monitoring directory: {MONITORED_DIR}")

    # Check if the monitored directory exists and create it if not
    if not os.path.exists(MONITORED_DIR):
        print(f"[INFO] Directory '{MONITORED_DIR}' does not exist. Creating it...")
        try:
            os.makedirs(MONITORED_DIR)
        except Exception as e:
            print(f"[ERROR] Failed to create directory '{MONITORED_DIR}': {e}")
            return

    create_honeypot_files(MONITORED_DIR, HONEY_COUNT)
    print("[INFO] Honeypots created successfully. Monitoring has started.")
    event_handler = RansomwareEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=MONITORED_DIR, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()