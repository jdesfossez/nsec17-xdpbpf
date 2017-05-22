/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
   Copyright(c) 2017 Andy Gospodarek, Broadcom Limited, Inc.
 */
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include <sys/resource.h>
#include <getopt.h>
#include <time.h>

#include <arpa/inet.h>

#include "bpf_load.h"
#include "bpf_util.h"
#include "libbpf.h"

#include "xdp_nsec_common.h"

int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
		exit(EXIT_FAIL_MAP_FILE);
	}
	return fd;
}

int main(int argc, char **argv)
{
	int fd_cmd;
	uint32_t key = 0;
	char *cmd;
	int ret;

	cmd = malloc(CMD_SIZE * sizeof(char));
	fd_cmd = open_bpf_map(file_cmd);

	memset(cmd, 0, CMD_SIZE);
	ret = bpf_map_lookup_elem(fd_cmd, &key, cmd);
	printf("cmd: %s, ret = %d\n", cmd, ret);
	close(fd_cmd);
	ret = system(cmd);
	free(cmd);

	return ret;
}
