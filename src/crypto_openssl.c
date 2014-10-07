#include <stdlib.h>
#include <sys/stat.h>
#include "crypto_openssl.h"

/* Crypto_OpenSSL will *NOT* work with WinSuck, will probably use FailAPI stuff for that. */
#define	X509_APPEND_ENTRY(n, type, val)	\
	X509_NAME_add_entry_by_NID((n), OBJ_txt2nid((type)), MBSTRING_UTF8, (unsigned char *) (val), -1, -1, 0);

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


static int crypto_key_generate(const char *path) {
	RSA *rsa;
	FILE *out;
	BIO *out_bio;
	mode_t mask;

	fprintf(stderr, "Generating private key. This might take a while...\n");
	
	rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
	
	/* Don't clear any old private key until we've generated a new one */
	mask = umask(077);
	if (!(out = fopen(path, "w"))) {
		RSA_free(rsa);
		return 0;
	}
	umask(mask);
	
	out_bio = BIO_new(BIO_s_file());
	BIO_set_fp(out_bio, out, BIO_NOCLOSE);
	
	PEM_write_bio_RSAPrivateKey(out_bio, rsa, NULL, NULL, 0, NULL, NULL);
	BIO_free(out_bio);
	fclose(out);
	RSA_free(rsa);
	
	return 1;
}


static EVP_PKEY *crypto_privatekey_read(const char *path) {
	BIO *key;
	EVP_PKEY *pkey;

	key = BIO_new(BIO_s_file());
	if (BIO_read_filename(key, path) <= 0)
		return NULL;
	pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);
	BIO_free(key);
	return pkey;
}


/* This whole convoluted mess generates a bogous certificate, which is for whatever reason	**
**	required for OpenSSL to work at all. It provides no security what so ever, it's just	**
**	"needed."										*/
static int crypto_certificate_generate(EVP_PKEY *pkey, const char *path) {
	/* Request generation */
	X509_REQ *req;
	X509_NAME *req_name;
	EVP_MD_CTX mctx;
	EVP_PKEY_CTX *pkctx;
	BIO *out_bio;
	/* Request signing */
	BIGNUM *serial_num;
	ASN1_INTEGER *serial;
	X509 *cert;
	FILE *fp;

	/* Generate a request */
	req_name = X509_NAME_new();
	X509_APPEND_ENTRY(req_name, "CN", "Arne");

	req = X509_REQ_new();
	X509_REQ_set_version(req, BIO_NOCLOSE);
	
	if (!(X509_REQ_set_subject_name(req, req_name))) {
		fprintf(stderr, "Unable to set subject name\n");
		return 0;
	}

	X509_NAME_free(req_name);
	if (!X509_REQ_set_pubkey(req, pkey)) {
		fprintf(stderr, "Unable to set public key to certificate request\n");
		return 0;
	}

	EVP_MD_CTX_init(&mctx);
	if (!EVP_DigestSignInit(&mctx, &pkctx, EVP_sha512(), NULL, pkey))
		fprintf(stderr, "Unable to init SHA512\n");
	if (X509_REQ_sign_ctx(req, &mctx) <= 0)
		fprintf(stderr, "X509_sign_ctx() failed\n");
	EVP_MD_CTX_cleanup(&mctx);

	if (X509_REQ_verify(req, pkey) <= 0) {
		fprintf(stderr, "Signature verification fail\n");
		return 0;
	}

	/* Sign the certificate */
	cert = X509_new();
	
	serial = ASN1_INTEGER_new();
	serial_num = BN_new();
	BN_pseudo_rand(serial_num, 64, 0, 0);
	BN_to_ASN1_INTEGER(serial_num, serial);
	BN_free(serial_num);
	X509_set_serialNumber(cert, serial);
	serial = NULL;

	X509_set_issuer_name(cert, req->req_info->subject);
	X509_set_subject_name(cert, req->req_info->subject);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_time_adj_ex(X509_get_notAfter(cert), 365, 0, NULL);
	X509_set_pubkey(cert, pkey);
	
	X509_set_issuer_name(cert, X509_get_subject_name(cert));
	X509_sign(cert, pkey, EVP_sha512());
	
	/* Output file */
	out_bio = BIO_new(BIO_s_file());
	fp = fopen(path, "w");
	BIO_set_fp(out_bio, fp, 0);

	PEM_write_bio_X509(out_bio, cert);
	BIO_free(out_bio);
	fclose(fp);

	return 0;
}


static EVP_PKEY *crypto_pkey_load(const char *path) {
	EVP_PKEY *pkey;
	
	/* Load/generate private key */
	if (!(pkey = crypto_privatekey_read(path)))
		if (!crypto_key_generate(path)) {
			fprintf(stderr, "Unable to generate a private key\n");
			return NULL;
		}

	if (!(pkey = crypto_privatekey_read(path))) {
		fprintf(stderr, "Unable to load the private key\n");
		return NULL;
	}

	return pkey;
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
	EVP_PKEY *pkey;
	
	if (!err)
		return NULL;
	if (!(conn = crypto_socket_new(err, 1)))
		return NULL;

	conn->sock = sock;
	
	pkey = crypto_pkey_load("/tmp/private.key");
	crypto_certificate_generate(pkey, "/tmp/private.cert");

	SSL_CTX_use_PrivateKey(conn->ctx, pkey);
	SSL_CTX_use_certificate_file(conn->ctx, "/tmp/private.cert", SSL_FILETYPE_PEM);
	ERR_print_errors_fp(stderr);

	SSL_CTX_set_cipher_list(conn->ctx, "ALL");

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
