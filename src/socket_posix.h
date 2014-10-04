#ifndef __SOCKET_H__
#define	__SOCKET_H__


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>

#define	SOCKET_IS_ERROR(sock)		((sock) < 0)
#define	SOCKET_TYPE			int

int socket_listen(int port);
int socket_accept(int sock);

#endif
