from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

with open("chave_publica_professor.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("senha_criptografada.bin", "rb") as f:
    mensagem_cifrada = f.read()

mensagem_decifrada_bytes = private_key.decrypt(
    mensagem_cifrada,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

mensagem_final = mensagem_decifrada_bytes.decode('utf-8')

print(mensagem_final)