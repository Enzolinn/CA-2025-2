import socket

HOST = "0.0.0.0"   # aceita conexões de qualquer IP local
PORT = 5000        # porta fixa

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as servidor:
    servidor.bind((HOST, PORT))
    servidor.listen(1)
    print(f"Servidor escutando em {HOST}:{PORT}...")

    conexao, endereco = servidor.accept()
    print(f"Conectado a {endereco}")

    while True:
        dados = conexao.recv(1024)
        if not dados:
            print("Cliente desconectado.")
            break

        mensagem = dados.decode()
        if mensagem.lower() == "/sair":
            print("Encerrando conexão...")
            break

        print("Cliente:", mensagem)
        resposta = input("Você: ")
        conexao.sendall(resposta.encode())

    conexao.close()
