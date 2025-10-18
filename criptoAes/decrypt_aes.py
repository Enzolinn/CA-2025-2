

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64, json

# === CONFIG ===
password = input("Digite a senha compartilhada: ")
input_file = "mensagem.enc"
output_file = "mensagem_recuperada.txt"
# ===============

# Carrega JSON
with open(input_file, "r") as f:
    conteudo = json.load(f)

salt = base64.b64decode(conteudo["salt"])
nonce = base64.b64decode(conteudo["nonce"])
ciphertext = base64.b64decode(conteudo["ciphertext"])

# Deriva chave
kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
key = kdf.derive(password.encode())

# Decriptografa
aesgcm = AESGCM(key)
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    with open(output_file, "wb") as f:
        f.write(plaintext)
    print(f"Arquivo descriptografado com sucesso como '{output_file}'")
except Exception as e:
    print("Falha na descriptografia! Senha incorreta ou arquivo alterado.")
