
# Ransomware Detection Tool

## Overview
This Python-based tool is designed to detect ransomware activity on text files (`.txt`) in a monitored directory, using a combination of real-time file monitoring, statistical content analysis, fuzzy hashing, and behavioral pattern detection. It aims to identify suspicious modifications such as encryption or mass file changes while minimizing false positives in normal user environments.

## Features
- Real-time monitoring using `Watchdog` (inotify/FileSystemWatcher) for low-latency detection.
- Entropy and ASCII ratio analysis to detect statistical anomalies in file content.
- Fuzzy similarity comparison between old and new versions to detect non-legitimate changes.
- MIME type detection to identify format changes from text to binary.
- Behavioral heuristics for bulk modification/deletion events.
- Honeypot files to catch ransomware early with minimal overhead.

## Detection Methods

The tool uses a multi-layered detection approach that includes:

- **Real-Time File Monitoring**  
  Monitors filesystem events (creation, modification, deletion, rename) using Watchdog for immediate response without constant polling.

- **File Type & Entropy Check**  
  Identifies anomalies by measuring entropy (randomness) in file content and checking for MIME type changes that indicate encryption.

- **Fuzzy Similarity Analysis**  
  Compares modified files to their previous versions to detect significant content changes. Low similarity may indicate encryption.

- **Bulk Modification Tracking**  
  Detects abnormal activity patterns by tracking multiple file changes or deletions in short time windows, which may signal a ransomware outbreak.

- **Honeypot File Detection**  
  Deploys hidden decoy files that, if accessed or altered, trigger an immediate alert—useful for early-stage ransomware detection.

## Sources
We combined methods from a few research articles listed below:

- **Watchdog**  
  https://medium.com/h7w/how-to-detect-malware-on-a-windows-system-using-python-a-step-by-step-guide-for-beginners-ebe98c7aa967

- **Fuzzy similarity**  
  https://pure.port.ac.uk/ws/portalfiles/portal/20272871/1570559640.pdf  
  https://www.cise.ufl.edu/~traynor/papers/scaife-icdcs16.pdf

- **Honeypot**  
  https://www.researchgate.net/publication/309323786_Detecting_Ransomware_with_Honeypot_Techniques

- **Entropy, ASCII ratio, encoding detection**  
  https://www.mdpi.com/1424-8220/24/5/1446

- **High-frequency file modifications (extended to deletions)**  
  https://www.techrxiv.org/doi/full/10.36227/techrxiv.173047864.44215173

## Installation
```bash
pip install watchdog sortedcontainers
```

## Usage
```bash
python ransomware_detector.py
```

You can edit the `MONITORED_DIR` variable in the script to set the desired path.

## Authors
- Raz Cohen
- Aliza Lazar

## Notes
- Designed for `.txt` files with ASCII content.
- Partial file analysis (~4KB) ensures low I/O and memory overhead.
- Best used on folders containing non-binary textual workspaces.