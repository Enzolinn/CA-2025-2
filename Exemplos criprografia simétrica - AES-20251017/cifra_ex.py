from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

#Geração de chaves de 32 bytes
key = os.urandom(32)
#Geração do vetor de inicialização de 16 bytes
iv  = os.urandom(16)

message = b'Aula de ciberseguranca aplicada'

padder = padding.PKCS7(128).padder()
padded_message = padder.update(message) + padder.finalize()

cipher = Cipher(algorithms.AES(key),modes.CBC(iv), backend=default_backend())

encryptor =  cipher.encryptor()

texto_cifrado = encryptor.update(padded_message) + encryptor.finalize()

print(texto_cifrado)

decryptor = cipher.decryptor()

decrypted_padded_message = decryptor.update(texto_cifrado) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()

texto_original = unpadder.update(decrypted_padded_message) + unpadder.finalize()

print(texto_original)