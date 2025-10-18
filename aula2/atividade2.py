import socket
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64, os, json

HOST = "172.30.128.115"  # IP do servidor (alterar para o IP real em rede)
PORT = 5000         # mesma porta do servidor

def gerarASyncKeys():
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  public_key = private_key.public_key()
  
  # Salvar chaves
  with open("private.pem", "wb") as f:
      f.write(private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
      ))
  
  with open("public.pem", "wb") as f:
      f.write(public_key.public_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PublicFormat.SubjectPublicKeyInfo
      ))

def gerarMsgCripto(msg):
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(msg.encode())
    return key
  
def critografarComAChaveDoServer(chavesync):
  with open("publicServer.pem", "rb") as f:
    serverKey = serialization.load_pem_public_key(f.read())

  mensagem = chavesync
  mensagem_cifrada = serverKey.encrypt(
      mensagem,
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
  )
  print(mensagem_cifrada)
  return mensagem_cifrada

def descriptografarWithMyPrvKey(msgcifrada):
    with open("private.pem", "rb") as f:
      private_key = serialization.load_pem_private_key(
          f.read(),
          password=None
      )
        
    mensagem_decifrada_bytes = private_key.decrypt(
      msgcifrada,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
    )
    mensagem_final = mensagem_decifrada_bytes.decode('utf-8')
    return mensagem_final

    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
    
    chavepub=''
    gerarASyncKeys()
    with open("public.pem", "r") as pk:
        chavepub=pk.read()
   
    # print(chavepub)
    cliente.connect((HOST, PORT))
    print(f"Conectado ao servidor {HOST}:{PORT}")
    
    cliente.sendall(chavepub.encode())
    
    chaveServer=cliente.recv(1024)
    with open("publicServer.pem", "wb") as f:
      f.write(chaveServer)
    
    chaveSync=gerarMsgCripto('mirasol')
    msgCriptografada =critografarComAChaveDoServer(chaveSync)
    
    cliente.sendall(msgCriptografada)
    
    
    # while True:
    #     mensagem = input("Você: ")
    #     cliente.sendall(mensagem.encode())

    #     if mensagem.lower() == "/sair":
    #         print("Encerrando chat...")
    #         break

    #     resposta = cliente.recv(1024)
    #     if not resposta:
    #         print("Servidor encerrou a conexão.")
    #         break

    #     print("Servidor:", resposta.decode())
