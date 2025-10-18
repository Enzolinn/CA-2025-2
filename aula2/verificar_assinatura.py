from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization


# Carregar chave pública
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Carregar documento e assinatura
with open("documento.txt", "rb") as f:
    data = f.read()

with open("assinatura.bin", "rb") as f:
    assinatura = f.read()

# Verificar assinatura
try:
    public_key.verify(
        assinatura,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Assinatura válida. Documento íntegro e autenticado.")
except Exception as e:
    print("Assinatura inválida ou documento alterado.")
