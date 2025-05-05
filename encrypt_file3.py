# base64_encrypt.py
import base64

def base64_encode_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    encoded = base64.b64encode(data)
    with open(file_path, 'wb') as f:
        f.write(encoded)
    print(f"[BASE64] Encoded {file_path}")

if __name__ == "__main__":
    base64_encode_file("example/file3.txt")