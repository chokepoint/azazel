#define _GNU_SOURCE
#ifndef CRYPTHOOK_H
#define CRYPTHOOK_H

#define MAX_LEN 4125

extern ssize_t crypt_read(int sockfd, void *buf, size_t len) __attribute__((visibility("hidden")));
extern ssize_t crypt_write(int sockfd, const void *buf, size_t len) __attribute__((visibility("hidden")));

#endif
