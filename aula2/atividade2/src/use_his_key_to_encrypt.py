from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def critografarComAChaveDele(chaveAsync, content):
  with open(chaveAsync, "rb") as f:
    serverKey = serialization.load_pem_public_key(f.read())
  
  pasta=chaveAsync.split("/")[0]
  
  chaveAsaCripto = serverKey.encrypt( # type: ignore
      content,
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
  )
#   print(mensagem_cifrada)

  with open(f"{pasta}/chaveAsa.bin", "wb") as f:
    f.write(chaveAsaCripto)
    
  return chaveAsaCripto