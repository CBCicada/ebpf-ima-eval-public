// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "cgroup_target.skel.h"

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int obj_get(const char *path)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64(path);
    return sys_bpf(BPF_OBJ_GET, &attr);
}

static int obj_pin(int fd, const char *path)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64(path);
    attr.bpf_fd = fd;
    return sys_bpf(BPF_OBJ_PIN, &attr);
}

static int cgroup_attach(int cgroup_fd, int prog_fd)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cgroup_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    return sys_bpf(BPF_PROG_ATTACH, &attr);
}

static int cgroup_detach(int cgroup_fd, int prog_fd)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.target_fd = cgroup_fd;
    attr.attach_bpf_fd = prog_fd;
    attr.attach_type = BPF_CGROUP_INET_SOCK_CREATE;
    return sys_bpf(BPF_PROG_DETACH, &attr);
}

static int attach_main(int argc, char **argv)
{
    struct cgroup_target *skel;
    const char *pin, *cgroup_path;
    char *end;
    long keyring_id;
    int cgroup_fd;
    int err;

    if (argc != 4) {
        fprintf(stderr, "usage: direct_cgroup_loader attach PIN CGROUP_PATH IMA_KEYRING_ID\n");
        return 2;
    }
    pin = argv[1];
    cgroup_path = argv[2];
    errno = 0;
    keyring_id = strtol(argv[3], &end, 10);
    if (errno || *end != '\0') {
        fprintf(stderr, "invalid IMA keyring id: %s\n", argv[3]);
        return 1;
    }

    cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        perror(cgroup_path);
        return 1;
    }

    skel = cgroup_target__open();
    if (!skel) {
        perror("cgroup_target__open");
        close(cgroup_fd);
        return 1;
    }
    skel->keyring_id = (int)keyring_id;
    err = cgroup_target__load(skel);
    if (err < 0) {
        errno = -err;
        perror("cgroup_target__load");
        cgroup_target__destroy(skel);
        close(cgroup_fd);
        return 1;
    }

    unlink(pin);
    err = obj_pin(skel->progs.cgroup_sock_create.prog_fd, pin);
    if (err < 0) {
        perror(pin);
        cgroup_target__destroy(skel);
        close(cgroup_fd);
        return 1;
    }

    err = cgroup_attach(cgroup_fd, skel->progs.cgroup_sock_create.prog_fd);
    if (err < 0) {
        perror("BPF_PROG_ATTACH");
        unlink(pin);
        cgroup_target__destroy(skel);
        close(cgroup_fd);
        return 1;
    }

    cgroup_target__destroy(skel);
    close(cgroup_fd);
    return 0;
}

static int detach_main(int argc, char **argv)
{
    const char *pin, *cgroup_path;
    int cgroup_fd, prog_fd;
    int err;

    if (argc != 3) {
        fprintf(stderr, "usage: direct_cgroup_loader detach PIN CGROUP_PATH\n");
        return 2;
    }
    pin = argv[1];
    cgroup_path = argv[2];
    cgroup_fd = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        perror(cgroup_path);
        return 1;
    }
    prog_fd = obj_get(pin);
    if (prog_fd < 0) {
        perror(pin);
        close(cgroup_fd);
        return 1;
    }
    err = cgroup_detach(cgroup_fd, prog_fd);
    if (err < 0)
        perror("BPF_PROG_DETACH");
    close(prog_fd);
    close(cgroup_fd);
    return err < 0 ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "attach"))
        return attach_main(argc - 1, argv + 1);
    if (!strcmp(argv[1], "detach"))
        return detach_main(argc - 1, argv + 1);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
