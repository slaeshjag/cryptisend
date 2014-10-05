#include <stdlib.h>
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


/* This whole convoluted mess generates a bogous certificate, which is for whatever reason	**
**	required for OpenSSL to work at all. It provides no security what so ever, it's just	**
**	"needed."										*/
static int crypto_certificate_generate() {
	/* Key generation */
	EVP_PKEY *pkey;
	RSA *rsa;
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


	/* Generate private key */
	pkey = EVP_PKEY_new();
	rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
	EVP_PKEY_set1_RSA(pkey, rsa);
	RSA_free(rsa), rsa = NULL;

	/* Generate a request */
	req_name = X509_NAME_new();
	X509_APPEND_ENTRY(req_name, "CN", "Arne");

	req = X509_REQ_new();
	X509_REQ_set_version(req, 0);
	
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
	out_bio = BIO_new(BIO_s_file());
	BIO_set_fp(out_bio, stdout, BIO_NOCLOSE);

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

	PEM_write_bio_X509(out_bio, cert);


	return 0;
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
	
	#if 0
	/* Generate DHparams */
	fprintf(stderr, "Generating DH params\n");
	DH *dh = DH_new();
	DH_generate_parameters_ex(dh, 205, 2, NULL);
	SSL_CTX_set_tmp_dh(conn->ctx, dh);

	/* Set RSA key */
	fprintf(stderr, "Generating RSA key\n");
	rsa = RSA_generate_key(4096, RSA_F4, NULL, NULL);
	SSL_CTX_set_tmp_rsa(conn->ctx, rsa);
	RSA_free(rsa);

	fprintf(stderr, "Keys generated\n");
	ERR_print_errors_fp(stderr);
	#endif

	crypto_certificate_generate();


	SSL_CTX_use_certificate_file(conn->ctx, "/tmp/server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(conn->ctx, "/tmp/server.key", SSL_FILETYPE_PEM);
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
