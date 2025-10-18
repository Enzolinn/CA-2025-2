# atividade2_client.py
import socket
import json
import base64
import time
from itertools import cycle

from src.generate_rsa_keys import gerarASyncKeys
from src.use_his_key_to_encrypt import critografarComAChaveDele
from src.use_my_key_to_decrypt import descriptografarWithMyPrvKey
from src.generate_asa_key import generateAsaKeys
from src.aes_encript__decrypt import aes_decrypt, aes_encrypt
HOST = "127.0.0.1"
PORT = 5000


def load_messages(path):
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln.strip() for ln in f.readlines() if ln.strip() != ""]
  
    return lines

def run_client():
    gerarASyncKeys("client-keys")
    msgs = load_messages("client-keys/mensagens.txt")
    msg_iter = cycle(msgs)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
        cliente.connect((HOST, PORT))
        rfile = cliente.makefile("rb")
        print("Conectado ao servidor", HOST, PORT)

        # enviar minha public key
        with open("client-keys/public.pem", "rb") as f:
            mypub = f.read()
        print("ENVIANDO CHAVE PUB DO CLEINTE-> ",mypub)
        content=(json.dumps({"type": "pubkey", "payload": base64.b64encode(mypub).decode()})+"\n").encode()
        cliente.sendall(content)
        print("chave publica enviada para o serv")
        
        
        # receber public key do servidor
        env =json.loads(rfile.readline())
       
    
        server_pub = base64.b64decode(env["payload"])
        with open("client-keys/publicServer.pem", "wb") as f:
            f.write(server_pub)
        print("CHAVE PUB DO server RECEBIDA-> ",server_pub)
        # gerar ASA (aleatória) e enviar cifrada com RSA do servidor
        aes_key = generateAsaKeys("client-keys", None)
        rsa_cipher = critografarComAChaveDele("client-keys/publicServer.pem", aes_key)
        contentAsa=(json.dumps({"type": "rsa_asa", "payload": base64.b64encode(rsa_cipher).decode()}) + "\n").encode()
        cliente.sendall(contentAsa)
        print("Chave AES enviada: ",aes_key)

        start_time = time.time()
        msg_count = 0
        total_sent = 0
        recv_counter = 0

        print("Iniciando envio de mensagens.")
     
        for message in msg_iter:
            # rekey quando atingir limites
            now = time.time()
            if msg_count >= 4 or (now - start_time) >= 20:
                print("Cliente iniciando rekey...")
                new_aes = generateAsaKeys("client-keys", None)
                rsa_cipher = critografarComAChaveDele("client-keys/publicServer.pem", new_aes)
                contentReKey=(json.dumps({"type": "rsa_asa", "payload": base64.b64encode(rsa_cipher).decode()})+"\n").encode()
                cliente.sendall(contentReKey)
                aes_key = new_aes
                start_time = time.time()
                msg_count = 0
                print(f"Cliente: nova chave enviada\n   chave nova->{new_aes}   chave nova cripto-> {rsa_cipher}")

            # enviar mensagem cifrada
            blob = aes_encrypt(aes_key, message.encode())
            contentMsg =(json.dumps({"type": "msg", "payload": base64.b64encode(blob).decode()})+"\n").encode()
            cliente.sendall(contentMsg)
            total_sent += 1
            msg_count += 1
            print(f"[enviado #{total_sent}]\n   mensagem original-> {message}\n   mensaem criptografada-> {blob}")

            # esperar resposta 
            env = json.loads(rfile.readline())
          
            if env.get("type") == "msg":
                blob = base64.b64decode(env["payload"])
                pt = aes_decrypt(aes_key, blob)
                recv_counter += 1
                print(f"[recebido #{recv_counter}] {pt.decode()}")
                
          

        cliente.close()

if __name__ == "__main__":
    run_client()
