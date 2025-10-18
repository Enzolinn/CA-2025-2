import socket

HOST = "172.30.128.115"  # IP do servidor (alterar para o IP real em rede)
PORT = 5000         # mesma porta do servidor

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
    cliente.connect((HOST, PORT))
    print(f"Conectado ao servidor {HOST}:{PORT}")

    while True:
        mensagem = input("Você: ")
        cliente.sendall(mensagem.encode())

        if mensagem.lower() == "/sair":
            print("Encerrando chat...")
            break

        resposta = cliente.recv(1024)
        if not resposta:
            print("Servidor encerrou a conexão.")
            break

        print("Servidor:", resposta.decode())
