from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

with open("documento.txt", "rb") as f:
    data = f.read()

# Criar assinatura digital (hash + RSA)
assinatura = private_key.sign(
    data,
    padding.PSS(                # PSS = padding seguro para assinatura
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Salvar assinatura em arquivo
with open("assinatura.bin", "wb") as f:
    f.write(assinatura)

print("Documento assinado com sucesso!")
