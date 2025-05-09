#!/usr/bin/env python3
# generate_encoded_files.py

"""
Script to generate files encoded or encrypted using various methods:
1. Base64 Encoding
2. Hex Encoding
3. Base32 Encoding
4. URL Encoding
5. UUencode
6. Quoted-Printable Encoding
7. Base85 Encoding
8. Rot13 Encoding
"""

import base64
import quopri
import urllib.parse
import codecs



# Text to encode
text = "Hello there, this is a test for ransomware detection!"

# Save content to file
def save_to_file(filename, content, mode="wb"):
    with open(filename, mode) as f:
        f.write(content)
    print(f"[INFO] Created file: {filename}")

# 1. Base64 Encoding
def create_base64_file():
    encoded = base64.b64encode(text.encode())
    save_to_file("test_folder/base64_encoded.txt", encoded)

# 2. Hex Encoding
def create_hex_file():
    encoded = text.encode().hex().encode()
    save_to_file("test_folder/hex_encoded.txt", encoded)

# 3. Base32 Encoding
def create_base32_file():
    encoded = base64.b32encode(text.encode())
    save_to_file("test_folder/base32_encoded.txt", encoded)

# 4. URL Encoding
def create_url_encoded_file():
    encoded = urllib.parse.quote(text).encode()
    save_to_file("test_folder/url_encoded.txt", encoded)

# Custom UUencode function
def create_uuencode_file():
    encoded = base64.b64encode(text.encode())  # Simulating UUencode with Base64
    encoded = f"begin 644 file.txt\n{encoded.decode()}\nend".encode()
    save_to_file("test_folder/uu_encoded.txt", encoded)

# 6. Quoted-Printable Encoding
def create_quoted_printable_file():
    encoded = quopri.encodestring(text.encode())
    save_to_file("test_folder/quoted_printable.txt", encoded)

# 7. Base85 Encoding
def create_base85_file():
    encoded = base64.b85encode(text.encode())
    save_to_file("test_folder/base85_encoded.txt", encoded)

# 8. Rot13 Encoding
def create_rot13_file():
    encoded = codecs.encode(text, "rot_13")
    save_to_file("test_folder/rot13_encoded.txt", encoded.encode(), mode="wb")

# Create all encoded files
if __name__ == "__main__":
    print("[INFO] Generating encoded/encrypted test files...")
    create_base64_file()
    create_hex_file()
    create_base32_file()
    create_url_encoded_file()
    create_uuencode_file()
    create_quoted_printable_file()
    create_base85_file()
    create_rot13_file()
    print("[DONE] All encoded files generated in the 'example' folder.")
