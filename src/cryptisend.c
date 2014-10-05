#include "cryptisend.h"
#include "crypto_openssl.h"
#include "socket_posix.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	SOCKET_TYPE s;
	struct CTCDCryptoConn *c;
	enum CTCDError err;

	crypto_global_init();
	if (argc > 1) {
		s = socket_listen(CRYPTISEND_PORT);
		SOCKET_TYPE a = socket_accept(s);

		if (SOCKET_IS_ERROR(a)) {
			fprintf(stderr, "Error accepting socket\n");
			return -1;
		}

		fprintf(stderr, "Attempting SSL\n");
		if (!(c = crypto_connection_apply(&err, a)))
			fprintf(stderr, "Error applying SSL\n");
		sleep(3);
	} else {
		if (!(c = crypto_connection_open("localhost:19421", &err)))
			fprintf(stderr, "Unable to connect using SSL\n");
	}


	return 0;
}
