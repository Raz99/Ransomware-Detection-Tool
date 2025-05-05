# xor_encrypt.py
import os

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def xor_encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted = xor_encrypt(data, key)
    with open(file_path, 'wb') as f:
        f.write(encrypted)
    print(f"[XOR] Encrypted {file_path}")

if __name__ == "__main__":
    key = os.urandom(8)
    xor_encrypt_file("example/file2.txt", key)