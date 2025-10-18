from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def descriptografarWithMyPrvKey(enderecoChavePriv,msgcifrada):
    with open(enderecoChavePriv, "rb") as f:
      private_key = serialization.load_pem_private_key(
          f.read(),
          password=None
      )
        
    chaveAsaDecifradaBytes = private_key.decrypt( # type: ignore
      msgcifrada,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
    )
    
    return chaveAsaDecifradaBytes
