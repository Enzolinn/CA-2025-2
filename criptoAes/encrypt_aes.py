

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64, os, json

# === CONFIG ===
password = input("Defina uma senha compartilhada: ")
input_file = "mensagem.txt"
output_file = "mensagem.enc"
# ===============

# Deriva chave
salt = os.urandom(16)
kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
key = kdf.derive(password.encode())
print("a chave é: ",key)

# Criptografa
aesgcm = AESGCM(key)
nonce = os.urandom(12)

with open(input_file, "rb") as f:
    dados = f.read()

ciphertext = aesgcm.encrypt(nonce, dados, None)

# Salva em JSON
conteudo = {
    "salt": base64.b64encode(salt).decode(),
    "nonce": base64.b64encode(nonce).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode()
}

with open(output_file, "w") as f:
    json.dump(conteudo, f)

print(f"Arquivo '{input_file}' criptografado como '{output_file}'")
print("Compartilhe o arquivo e a senha com seu colega para descriptografar.")
