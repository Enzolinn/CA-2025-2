import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # nonce + ciphertext+tag

def aes_decrypt(aes_key: bytes, blob: bytes) -> bytes:
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ct, None)
