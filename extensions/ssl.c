#include "st_ssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
    st_init();
    SSL_load_error_strings();
    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    int sock;
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        abort();
    }

    BIO *ssl_bio = BIO_new_ssl(ctx, 1);
    BIO *nfd_bio = BIO_new_netfd(sock, 1);
    BIO *bio = BIO_push(ssl_bio, nfd_bio);

    SSL *ssl = NULL;
    BIO_get_ssl(ssl_bio, &ssl);
    if (!ssl) {
        abort();
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    st_netfd_t nfd;
    BIO_get_fp(bio, &nfd);

#if 0
    struct sockaddr_in addr;
    // www.google.com
    inet_pton(AF_INET, "74.125.224.48", &addr.sin_addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);

    if (st_connect(nfd, (struct sockaddr *)&addr, sizeof(addr), ST_UTIME_NO_TIMEOUT) < 0) {
        abort();
    }
#else
    BIO_set_conn_hostname(nfd_bio, "www.google.com");
    BIO_set_conn_port(nfd_bio, "https");

    if (BIO_do_connect(nfd_bio) <= 0) {
        fprintf(stderr, "Error establishing connection\n");
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (BIO_do_handshake(ssl_bio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
#endif

    char tmpbuf[1024];
    BIO_puts(bio, "GET / HTTP/1.0\r\nHost: encrypted.google.com\r\n\r\n");
    int len;
    for(;;) {
        len = BIO_read(bio, tmpbuf, 1024);
        if(len <= 0) break;
        fwrite(tmpbuf, sizeof(char), len, stdout);
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}
