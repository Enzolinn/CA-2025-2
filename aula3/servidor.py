import http.server 
import ssl

# Configura o servidor
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Configura o SSL (HTTPS)
# Aponta para os arquivos que ACABAMOS de criar
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               keyfile="private.key",  # Nossa chave privada
                               certfile="meu-servidor.crt", # Nosso certificado
                               ssl_version=ssl.PROTOCOL_TLS)

print("Servidor HTTPS rodando em https://localhost:4443 ...")
httpd.serve_forever()
