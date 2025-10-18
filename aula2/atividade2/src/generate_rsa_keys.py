from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def gerarASyncKeys(pasta):
  
    
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  public_key = private_key.public_key()
  
  # Salvar chaves
  with open(f"{pasta}/private.pem", "wb") as f:
      f.write(private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
      ))
  
  with open(f"{pasta}/public.pem", "wb") as f:
      f.write(public_key.public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
      ))
