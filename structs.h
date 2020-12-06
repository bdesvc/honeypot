#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <assert.h>

struct honeypot_t {
	int fd;
	int connected_at;
};

struct creds_t {
	char username[32];
	char password[32];
};