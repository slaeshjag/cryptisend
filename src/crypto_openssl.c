#include <stdlib.h>
#include "crypto_openssl.h"

/* Crypto_OpenSSL will *NOT* work with WinSuck, will probably use FailAPI stuff for that. */

int crypto_global_init() {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	return 0;
}


struct CTCDCryptoConn *crypto_connection_close(struct CTCDCryptoConn *conn) {
	if (!conn) return NULL;
	if (conn->ssl) SSL_free(conn->ssl);
	if (conn->bio) BIO_free_all(conn->bio);
	if (conn->ctx) SSL_CTX_free(conn->ctx);
	if (conn->sock >= 0) close(conn->sock);
	free(conn);
	return NULL;
}


static struct CTCDCryptoConn *crypto_socket_new(enum CTCDError *err, int server) {
	struct CTCDCryptoConn *conn;
	
	if (!(conn = calloc(sizeof(*conn), 1))) {
		*err = CTCD_ERR_MEMORY;
		return NULL;
	}

	conn->sock = -1;
	if (!(conn->ctx = SSL_CTX_new(server?SSLv3_server_method():SSLv3_client_method()))) {
		ERR_print_errors_fp(stderr);
	}

	if (server)
		SSL_CTX_set_cipher_list(conn->ctx, "ALL");
	else if (!(conn->bio = BIO_new_ssl_connect(conn->ctx))) {
		*err = CTCD_ERR_CONNECT;
		return crypto_connection_close(conn);
	}
	
	*err = CTCD_ERR_SUCCESS;
	return conn;
}


struct CTCDCryptoConn *crypto_connection_apply(enum CTCDError *err, int sock) {
	struct CTCDCryptoConn *conn;
	
	if (!err)
		return NULL;
	if (!(conn = crypto_socket_new(err, 1)))
		return NULL;

	conn->sock = sock;
	SSL_CTX_use_certificate_file(conn->ctx, "/tmp/server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(conn->ctx, "/tmp/server.key", SSL_FILETYPE_PEM);

	conn->ssl = SSL_new(conn->ctx);
	SSL_set_fd(conn->ssl, sock);
	if (SSL_accept(conn->ssl) < 1) {
		ERR_print_errors_fp(stderr);
		*err = CTCD_ERR_SSL_NEG_FAIL;
		return crypto_connection_close(conn);
	}

	*err = CTCD_ERR_SUCCESS;
	return conn;
}


/* TODO: Add fingerprint verification */
struct CTCDCryptoConn *crypto_connection_open(char *hostname, enum CTCDError *err) {
	struct CTCDCryptoConn *conn;
	if (!err)
		return NULL;
	if (!(conn = crypto_socket_new(err, 0))) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	BIO_set_conn_hostname(conn->bio, hostname);

	if (BIO_do_connect(conn->bio) <= 0) {
		ERR_print_errors_fp(stderr);
		*err = CTCD_ERR_CONNECT;
		goto connection_error;
	}

	*err = CTCD_ERR_SUCCESS;
	return conn;

	connection_error:
	return crypto_connection_close(conn);
}
