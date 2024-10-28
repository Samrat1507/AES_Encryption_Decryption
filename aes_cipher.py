from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# AES Encryption for Text
def encrypt_text(key, plaintext):
    cipher = AES.new(key, AES.MODE_CFB)
    iv = cipher.iv
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(iv + ciphertext).decode()

# AES Decryption for Text
def decrypt_text(key, encrypted_text):
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode()

# AES Encryption for Files
def encrypt_file(key, file_data):
    cipher = AES.new(key, AES.MODE_CFB)
    iv = cipher.iv
    ciphertext = cipher.encrypt(file_data)
    return iv + ciphertext

# AES Decryption for Files
def decrypt_file(key, encrypted_file_data):
    iv = encrypted_file_data[:16]
    ciphertext = encrypted_file_data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext)
