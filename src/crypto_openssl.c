#include <stdlib.h>
#include "crypto_openssl.h"

/* Crypto_OpenSSL will *NOT* work with WinSuck, will probably use FailAPI stuff for that. */

int crypto_global_init() {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	return 0;
}


struct CTCDCryptoConn *crypto_connection_close(CTCDCryptoConn *conn) {
	if (!conn) return NULL;
	if (conn->ssl) SSL_free(ssl);
	if (conn->bio) BIO_free_all(conn->bio);
	if (conn->ctx) SSL_CTX_free(conn->ctx);
	if (conn->sock < 0) close(conn->sock);
	free(conn);
	return NULL;
}


static struct CTCDCryptoConn *crypto_socket_new(enum CTCDError *err) {
	struct CTCDCryptoConn *conn;
	
	if (!(conn = calloc(sizeof(conn), 1))) {
		*err = CTCD_ERR_MEMORY;
		return NULL;
	}

	conn->sock = -1;
	conn->ctx = SSL_CTX_new(SSLv3_client_method());

	if (!(conn->bio = BIO_new_ssl_connect(conn->ctx))) {
		*err = CTCD_ERR_CONNECT;
		return crypto_connection_close(conn);
	}
	
	*err = STCD_ERR_SUCCESS;
	return conn;
}


struct CTCDCryptoConn *crypto_connection_apply(enum CTCDError *err, int sock) {
	struct CTCDCryptoConn *conn;
	
	if (!err)
		return NULL;
	if (!(conn = crypto_socket_new(err)))
		return NULL;

	conn->sock = sock;
	conn->ssl = SSL_new(conn->ctx);
	SSL_set_fd(conn->ssl, sock);
	if (SSL_accept(conn->ssl) < 0) {
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
	if (!(conn = crypto_socket_new(err)))
		return NULL;

	BIO_set_conn_hostname(conn->bio, hostname);

	if (BIO_do_connect(conn->bio) <= 0) {
		*err = CTCD_ERR_CONNECT;
		goto connection_error;
	}

	*err = CTCD_ERR_SUCCESS;
	return conn;

	connection_error:
	return crypto_connection_close(conn);
}
