from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

# Generate AES key and IV
key = os.urandom(32)  # 256-bit key
iv = os.urandom(16)   # 128-bit IV

open("aes_key.bin", "wb").write(key)
open("aes_iv.bin", "wb").write(iv)

# Read message
message = open("message.txt", "rb").read()

# Pad message
padder = padding.PKCS7(128).padder()
padded_message = padder.update(message) + padder.finalize()

# Encrypt
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_message) + encryptor.finalize()
open("message_aes_encrypted.bin", "wb").write(ciphertext)

# Decrypt
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

# Unpad
unpadder = padding.PKCS7(128).unpadder()
decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
open("message_aes_decrypted.txt", "wb").write(decrypted)
