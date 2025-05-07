# Ransomware Detection Project

## 1. Project Overview

The purpose of this project is to develop a tool for detecting ransomware or suspicious file modifications, particularly focusing on encrypted or encoded files. The system continuously monitors a designated folder and alerts the user whenever a file is detected as being encoded or encrypted. This is crucial for identifying potential ransomware attacks, as ransomware typically encrypts files to make them inaccessible.


### Runtime Analysis

* **Memory Complexity:** O(n) - Each file's hash and metadata are stored.
* **Time Complexity:** O(n) per scan - The script checks each file in the designated folder.
* **I/O Complexity:** Medium - Only changed files are re-read and re-hashed.

***the full run time of our project is O(n)*** 
## 2. Algorithm and Article Used

We based our detection algorithm on the method presented in the article:
**"A Multi-Heuristic Approach to Ransomware Detection"**.

### Algorithm Highlights

1. **Entropy Calculation:** Measures randomness; high entropy indicates possible encryption.
2. **ASCII Printability Check:** Determines whether the content looks like readable text or gibberish.
3. **Encoding Detection:** Uses pattern recognition to identify common encoding formats (Base64, Hex, Base85, UUencode, etc.).
4. **Behavioral Detection:** Monitors for rapid changes within a short time span to catch mass encryption activity.

### Why We Chose This Algorithm

The algorithm from the article balances detecting both **gibberish encryption** and **legitimate-looking encoded content**. This is crucial because ransomware may encode data to evade detection while still appearing readable.

## 4. Project Structure

```
Ransomware_Detection/
├── example/                     # Folder containing example encoded/encrypted files
│   ├── .gitattributes
│   ├── baseline.csv             # Stores file hashes for comparison
│   └── generated files          # Encoded and encrypted test files
├── all_nongibrish_encryption.py # Script to generate non-gibberish encoded files
├── decrypt_file.py              # Script to decrypt encoded/encrypted files for testing
├── detect_ransomware.py         # Main ransomware detection script
├── encrypt_file.py              # Script to encrypt files (AES)
├── encrypt_file2.py             # Script to encode files using Base64
├── encrypt_file3.py             # Script to apply custom encoding for testing
└── README.md                    # Project documentation
```

### Main Components:

* **File Monitoring Module:** Continuously scans the designated folder for changes.
* **Hash Comparison Module:** Compares the current hash with the baseline to detect changes.
* **Encoding Detection Module:** Identifies the encoding type if the file is not gibberish but still suspicious.
* **Alerting System:** Notifies the user immediately upon detecting suspicious changes.
* **Baseline Update Module:** Ensures the hash of changed files is updated to avoid redundant alerts.

