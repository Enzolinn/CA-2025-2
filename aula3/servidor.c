#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Carrega certificado e chave privada
    if (SSL_CTX_use_certificate_file(ctx, "186665.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4443);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
    listen(sockfd, 1);

    printf("Servidor HTTPS rodando em https://localhost:4443 ...\n");

    while (1) {
        int client = accept(sockfd, NULL, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOlá, HTTPS!", 61);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
