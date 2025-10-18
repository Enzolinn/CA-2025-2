import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

def generateAsaKeys(pasta, password: str | None = None) -> bytes:
    if password:
        salt = os.urandom(16)
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
        key = kdf.derive(password.encode())
        
    else:
        key = os.urandom(32)  # AES-256

    with open(f"{pasta}/asa-key.bin", "wb") as f:
        f.write(key)

    return key
