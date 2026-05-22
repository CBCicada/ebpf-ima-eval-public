// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef ITERS
#define ITERS 1000
#endif

#ifndef OBJ_PATH
#define OBJ_PATH "build/payload_88kb.bpf.o"
#endif

#ifndef PIN_PATH
#define PIN_PATH "/sys/fs/bpf/ima_exp_d_loadbench"
#endif

#ifndef SIGN_KEY
#define SIGN_KEY "keys/signing_key.pem"
#endif

#ifndef SIGN_CERT
#define SIGN_CERT "keys/signing_cert.pem"
#endif

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

int main(void)
{
    for (int i = 0; i < ITERS; i++) {
        char cmd[512];
        double start, end;
        int n, status, rc = -1;

        unlink(PIN_PATH);
        n = snprintf(cmd, sizeof(cmd),
                     "bpftool -L -S -k %s -i %s prog load %s %s type socket_filter >/dev/null",
                     SIGN_KEY, SIGN_CERT, OBJ_PATH, PIN_PATH);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            fprintf(stderr, "bpftool command too long\n");
            return 2;
        }

        start = now_ms();
        status = system(cmd);
        end = now_ms();
        unlink(PIN_PATH);

        if (WIFEXITED(status))
            rc = WEXITSTATUS(status);

        if (rc != 0) {
            fprintf(stderr, "bpftool load failed at iteration %d with rc=%d\n", i, rc);
            return rc;
        }

        printf("%d\t%.6f\t%d\n", i, end - start, rc);
    }

    return 0;
}
