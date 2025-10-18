# atividade2_server.py
import socket
import json
import base64
from time import sleep
from src.generate_rsa_keys import gerarASyncKeys
from src.use_my_key_to_decrypt import descriptografarWithMyPrvKey
from src.aes_encript__decrypt import aes_decrypt, aes_encrypt

HOST = "0.0.0.0"
PORT = 5000


def handle_chat(conn):
    
    rfile = conn.makefile("rb")
    # 1) receber public key do cliente

    env= json.loads(rfile.readline().decode())
    client_pub = base64.b64decode(env["payload"])
    print("CHAVE PUB DO CLIENTE RECEBIDA-> ",client_pub)
    with open("serv-keys/publicClient.pem", "wb") as f:
        f.write(client_pub)

    # 2) enviar minha public key
    
    with open("serv-keys/public.pem", "rb") as f:
        mypub = f.read()
    print("ENVIANDO CHAVE PUB DO SERVIDOR-> ",mypub)
    contentPubKey=(json.dumps({"type": "pubkey", "payload": base64.b64encode(mypub).decode()})+"\n").encode()
    conn.sendall(contentPubKey)
    
    # 3) receber rsa_asa inicial
    env = json.loads(rfile.readline().decode())
    rsa_asa = base64.b64decode(env["payload"])
    aes_key = descriptografarWithMyPrvKey("serv-keys/private.pem", rsa_asa)
    print("Chave aes recebida -> ",aes_key)
    print("Chave aes criptografada pela rsa -> ",rsa_asa)

    received_count = 0

    while True:
        env = json.loads(rfile.readline().decode())
        t = env.get("type")
        if t == "msg":
            blob = base64.b64decode(env["payload"])
            plaintext = aes_decrypt(aes_key, blob)
            received_count += 1
            texto = plaintext.decode()
            print(f"[recebido #{received_count}]\n  criptografada-> {blob}\n  descriptografada-> {texto}\n")
            resposta = f"sua mensagem numero: {received_count} foi recebida!"
            blob_resp = aes_encrypt(aes_key, resposta.encode())
            contentMsg = (json.dumps({"type": "msg", "payload": base64.b64encode(blob_resp).decode()})+"\n").encode()
            conn.sendall(contentMsg)
        elif t == "rsa_asa":
            # cliente enviou rekey: decifra e aceita nova AES
            rsa_asa = base64.b64decode(env["payload"])
            aes_key = descriptografarWithMyPrvKey("serv-keys/private.pem", rsa_asa)
            print("Servidor: nova chave AES recebida.")
            print("Chave aes recebida -> ",aes_key)
            print("Chave aes criptografada pela rsa -> ",rsa_asa)

        sleep(4)

if __name__ == "__main__":

    gerarASyncKeys("serv-keys")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
        servidor.bind((HOST, PORT))
        servidor.listen(1)
        print(f"Servidor escutando em {HOST}:{PORT}...")
        conn, addr = servidor.accept()
        print("Conectado por", addr)
        handle_chat(conn)
        print("Conexão encerrada.")
