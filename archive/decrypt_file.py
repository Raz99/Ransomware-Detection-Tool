from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def decrypt_content(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    # חילוץ IV (16 הבתים הראשונים) והנתונים המוצפנים
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]

    # יצירת אובייקט לפענוח
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # פענוח התוכן
    padded_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # הסרת Padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    content = unpadder.update(padded_content) + unpadder.finalize()

    return content.decode()

# דוגמה לשימוש
file_path = "example/file1.txt"  # שם הקובץ
encryption_key = b'\xe22\nu<1U\xf4\x84\xf3\x13\xe6x\xeco\xbcA\x1b\xf5\xd4\xed\xcar\xaeRz`/\xdah.\x0e'
decrypted_content = decrypt_content(file_path, encryption_key)
print("תוכן מפוענח:", decrypted_content)