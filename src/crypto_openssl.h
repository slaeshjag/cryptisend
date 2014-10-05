#ifndef __CRYPTO_H__
#define	__CRYPTO_H__

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cryptisend_error.h"


struct CTCDCryptoConn {
	SSL			*ssl;
	BIO			*bio;
	SSL_CTX			*ctx;
	int			sock;
};

int crypto_global_init();
struct CTCDCryptoConn *crypto_connection_close(struct CTCDCryptoConn *conn);
struct CTCDCryptoConn *crypto_connection_apply(enum CTCDError *err, int sock);
struct CTCDCryptoConn *crypto_connection_open(char *hostname, enum CTCDError *err);


#endif
