// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "purge_target.skel.h"

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

static int obj_pin(int fd, const char *path)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64(path);
    attr.bpf_fd = fd;
    return syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
}

int main(int argc, char **argv)
{
    struct purge_target *skel;
    const char *pin;
    char *end;
    long keyring_id;
    int err;

    if (argc != 3) {
        fprintf(stderr, "usage: signed_loader PIN IMA_KEYRING_ID\n");
        return 2;
    }
    pin = argv[1];
    errno = 0;
    keyring_id = strtol(argv[2], &end, 10);
    if (errno || *end != '\0') {
        fprintf(stderr, "invalid IMA keyring id: %s\n", argv[2]);
        return 1;
    }

    skel = purge_target__open();
    if (!skel) {
        perror("purge_target__open");
        return 1;
    }
    skel->keyring_id = (int)keyring_id;
    err = purge_target__load(skel);
    if (err < 0) {
        errno = -err;
        perror("purge_target__load");
        purge_target__destroy(skel);
        return 1;
    }

    unlink(pin);
    err = obj_pin(skel->progs.purge_target.prog_fd, pin);
    if (err < 0) {
        perror(pin);
        purge_target__destroy(skel);
        return 1;
    }

    purge_target__destroy(skel);
    return 0;
}
