import hashlib

def calcular_hash_arquivo(caminho_arquivo):
    sha256 = hashlib.sha256() 
    with open(caminho_arquivo, "rb") as f:
        for bloco in iter(lambda: f.read(4096), b""):
            sha256.update(bloco)
    return sha256.hexdigest()

arquivo = 'plano.pdf'
try:
    hash_resultado = calcular_hash_arquivo(arquivo)
    print(f"\nHash SHA-256 do arquivo '{arquivo}':\n{hash_resultado}")
except FileNotFoundError:
    print("Arquivo não encontrado.")
