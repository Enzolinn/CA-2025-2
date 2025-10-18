from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Carregar chave pública
with open("public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

mensagem_str = "pazuzu el amumu"
mensagem = mensagem_str.encode('utf-8')
mensagem_cifrada = public_key.encrypt(
    mensagem,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)

with open("mensagem.bin", "wb") as f:
    f.write(mensagem_cifrada)
