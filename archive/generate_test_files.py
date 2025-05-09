import os
from pathlib import Path

TARGET_DIR = Path(__file__).parent / "monitored_dir"
TARGET_DIR.mkdir(parents=True, exist_ok=True)

FILES = {
    "plain.txt": "This is a normal text file with readable ASCII content.\n" * 5,
    "base64.txt": "Base64 encoding often masks binary content.\n" * 5,
    "hex.txt": "Hex encoded strings look legit but aren't readable text.\n" * 5,
    "partial.txt": "This file simulates partial encryption.\n" * 5,
    "xorbase64.txt": "Combined XOR and Base64 should still raise flags.\n" * 5,
    "random.txt": "This file will be overwritten with random bytes.\n" * 5,
}

def main():
    for filename, content in FILES.items():
        path = TARGET_DIR / filename
        with open(path, "w", encoding="ascii") as f:
            f.write(content)
        print(f"[+] Created: {filename}")

if __name__ == "__main__":
    main()