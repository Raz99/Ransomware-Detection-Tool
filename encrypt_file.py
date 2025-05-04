from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

# פונקציה להצפנת תוכן
def encrypt_content(content, key):
    # יצירת וקטור אתחול (Initialization Vector)
    iv = os.urandom(16)  # 16 bytes for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # הוספת Padding לתוכן כדי להתאים לבלוקים של AES
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_content = padder.update(content.encode()) + padder.finalize()

    # הצפנת התוכן
    encrypted_content = encryptor.update(padded_content) + encryptor.finalize()

    return iv + encrypted_content  # שילוב של IV והנתונים המוצפנים

# פונקציה להוספת התוכן המוצפן לקובץ
def add_encrypted_content_to_file(file_path, content, key):
    encrypted_content = encrypt_content(content, key)
    with open(file_path, 'wb') as f:
        f.write(encrypted_content)
    print(f"תוכן מוצפן נוסף לקובץ: {file_path}")

def read_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        print(f"שגיאה: הקובץ '{file_path}' לא נמצא.")
        return None

# מפתח הצפנה (חייב להיות בגודל 16, 24, או 32 בתים עבור AES)
encryption_key = os.urandom(32)  # דוגמה ליצירת מפתח בגודל 256 ביט (32 בתים)

# דוגמה לשימוש
file_path = "example/file1.txt"  # שם הקובץ
content_to_encrypt = read_file(file_path)  # תוכן להצפנה
add_encrypted_content_to_file(file_path, content_to_encrypt, encryption_key)
print(f"encryption_key: {encryption_key}")