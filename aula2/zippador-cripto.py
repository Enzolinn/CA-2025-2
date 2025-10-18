import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# -----------------------------
# CONFIGURAÇÕES
# -----------------------------
arquivo_zip = 'atividade2.zip'  # zip que você criou manualmente
senha_zip = 'gremiomaiordosul'   # senha do zip
chave_publica_professor = 'chave_publica_professor.pem'  # PEM da chave pública

# -----------------------------
# GERAR HASH SHA-256 DO ZIP
# -----------------------------
hash_sha256 = hashlib.sha256()
with open(arquivo_zip, 'rb') as f:
    for bloco in iter(lambda: f.read(4096), b''):
        hash_sha256.update(bloco)

hash_final = hash_sha256.hexdigest()
print(f"[OK] Hash SHA-256 do zip: {hash_final}")

# Salvar hash em arquivo
with open('hash.txt', 'w') as f:
    f.write(hash_final)
print("[OK] Hash salvo em hash.txt")

# -----------------------------
# CRIPTOGRAFAR A SENHA COM A CHAVE PÚBLICA
# -----------------------------
with open(chave_publica_professor, 'rb') as key_file:
    chave_publica = serialization.load_pem_public_key(key_file.read())

senha_criptografada = chave_publica.encrypt(
    senha_zip.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Salvar senha criptografada
with open('senha_criptografada.bin', 'wb') as f:
    f.write(senha_criptografada)
print("[OK] Senha criptografada salva em senha_criptografada.bin")
