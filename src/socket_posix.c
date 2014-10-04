#include "socket_posix.h"


int socket_accept(int socket) {
	struct sockaddr_in addr;
	int len = sizeof(addr);

	return accept(socket, (struct sockaddr *) &addr, &len);
}


int socket_listen(int port) {
	int sock;
	struct sockaddr_in addr;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	/* Listen on *ALL* the interfaces */
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
		close(sock);
		return -1;
	}

	if (listen(sock, 10)) {
		close(sock);
		return -1;
	}

	return sock;
}
