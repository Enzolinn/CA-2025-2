import http.server
import ssl

# Configura o servidor
server_address = ('localhost', 4443)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

# Cria o contexto SSL corretamente
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="ACRaiz.key")

# Envolve o socket com SSL
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

print("Servidor HTTPS rodando em https://localhost:4443")
httpd.serve_forever()
