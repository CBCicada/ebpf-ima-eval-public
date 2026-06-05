#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef offsetofend
#define offsetofend(TYPE, MEMBER) (offsetof(TYPE, MEMBER) + sizeof(((TYPE *)0)->MEMBER))
#endif

#define ptr_to_u64(ptr) ((__u64)(uintptr_t)(ptr))

static const char license[] = "GPL";

struct sample {
    struct bpf_insn insns[2];
    union bpf_attr attr;
    unsigned char *sig;
    size_t sig_len;
};

struct config {
    int iters;
    int signed_load;
    int unique;
    int keyring_id;
    const char *sign_key;
    const char *sign_cert;
};

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };

    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

static void init_prog(struct bpf_insn insns[2], int salt)
{
    memset(insns, 0, sizeof(struct bpf_insn) * 2);
    insns[0].code = BPF_ALU64 | BPF_MOV | BPF_K;
    insns[0].dst_reg = BPF_REG_0;
    insns[0].imm = salt;
    insns[1].code = BPF_JMP | BPF_EXIT;
}

static EVP_PKEY *read_private_key(const char *path)
{
    BIO *bio;
    EVP_PKEY *key;

    bio = BIO_new_file(path, "rb");
    if (!bio)
        return NULL;
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return key;
}

static X509 *read_x509(const char *path)
{
    unsigned char buf[2];
    BIO *bio;
    X509 *x509 = NULL;
    int n;

    bio = BIO_new_file(path, "rb");
    if (!bio)
        return NULL;

    n = BIO_read(bio, buf, sizeof(buf));
    if (n == (int)sizeof(buf) && BIO_reset(bio) == 0) {
        if (buf[0] == 0x30 && buf[1] >= 0x81 && buf[1] <= 0x84)
            x509 = d2i_X509_bio(bio, NULL);
        else
            x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return x509;
}

static int sign_prog(const void *data, size_t data_len, EVP_PKEY *key, X509 *x509,
                     unsigned char **sig, size_t *sig_len)
{
    BIO *in = NULL, *out = NULL;
    CMS_ContentInfo *cms = NULL;
    char *mem;
    long len;
    int ret = -1;

    in = BIO_new_mem_buf(data, (int)data_len);
    if (!in)
        goto out;

    cms = CMS_sign(NULL, NULL, NULL, NULL,
                   CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED | CMS_STREAM);
    if (!cms)
        goto out;

    if (!CMS_add1_signer(cms, x509, key, EVP_sha256(),
                         CMS_NOCERTS | CMS_BINARY | CMS_NOSMIMECAP |
                         CMS_USE_KEYID | CMS_NOATTR))
        goto out;

    if (CMS_final(cms, in, NULL, CMS_NOCERTS | CMS_BINARY) != 1)
        goto out;

    out = BIO_new(BIO_s_mem());
    if (!out)
        goto out;

    if (!i2d_CMS_bio_stream(out, cms, NULL, 0))
        goto out;

    len = BIO_get_mem_data(out, &mem);
    if (len <= 0)
        goto out;

    *sig = malloc((size_t)len);
    if (!*sig)
        goto out;
    memcpy(*sig, mem, (size_t)len);
    *sig_len = (size_t)len;
    ret = 0;

out:
    BIO_free(out);
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    return ret;
}

static void init_load_attr(struct sample *sample, const struct config *cfg)
{
    memset(&sample->attr, 0, sizeof(sample->attr));
    sample->attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    sample->attr.insns = ptr_to_u64(sample->insns);
    sample->attr.insn_cnt = ARRAY_SIZE(sample->insns);
    sample->attr.license = ptr_to_u64(license);
    memcpy(sample->attr.prog_name, "load_perf", sizeof("load_perf"));

    if (cfg->signed_load) {
        sample->attr.signature = ptr_to_u64(sample->sig);
        sample->attr.signature_size = sample->sig_len;
        sample->attr.keyring_id = cfg->keyring_id;
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s --iters N [--unique] [--signed --sign-key KEY --sign-cert CERT --keyring-id ID]\n",
            prog);
}

static int parse_int(const char *s, int *value)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || *end != '\0' || v < INT32_MIN || v > INT32_MAX)
        return -1;
    *value = (int)v;
    return 0;
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->iters = 1000;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            if (parse_int(argv[++i], &cfg->iters))
                return -1;
        } else if (!strcmp(argv[i], "--signed")) {
            cfg->signed_load = 1;
        } else if (!strcmp(argv[i], "--unique")) {
            cfg->unique = 1;
        } else if (!strcmp(argv[i], "--sign-key") && i + 1 < argc) {
            cfg->sign_key = argv[++i];
        } else if (!strcmp(argv[i], "--sign-cert") && i + 1 < argc) {
            cfg->sign_cert = argv[++i];
        } else if (!strcmp(argv[i], "--keyring-id") && i + 1 < argc) {
            if (parse_int(argv[++i], &cfg->keyring_id))
                return -1;
        } else {
            return -1;
        }
    }

    if (cfg->iters <= 0)
        return -1;
    if (cfg->signed_load && (!cfg->sign_key || !cfg->sign_cert || !cfg->keyring_id))
        return -1;
    return 0;
}

int main(int argc, char **argv)
{
    const size_t attr_sz = offsetofend(union bpf_attr, keyring_id);
    struct config cfg;
    struct sample *samples;
    EVP_PKEY *key = NULL;
    X509 *x509 = NULL;
    int ret = 0;

    if (parse_args(argc, argv, &cfg)) {
        usage(argv[0]);
        return 2;
    }

    bump_memlock_rlimit();

    samples = calloc((size_t)cfg.iters, sizeof(*samples));
    if (!samples) {
        perror("calloc");
        return 1;
    }

    for (int i = 0; i < cfg.iters; i++)
        init_prog(samples[i].insns, cfg.unique ? i + 1 : 1);

    if (cfg.signed_load) {
        key = read_private_key(cfg.sign_key);
        x509 = read_x509(cfg.sign_cert);
        if (!key || !x509) {
            fprintf(stderr, "failed to read signing key or cert\n");
            ERR_print_errors_fp(stderr);
            ret = 1;
            goto out;
        }

        for (int i = 0; i < cfg.iters; i++) {
            if (!cfg.unique && i > 0) {
                samples[i].sig = samples[0].sig;
                samples[i].sig_len = samples[0].sig_len;
                continue;
            }
            if (sign_prog(samples[i].insns, sizeof(samples[i].insns), key, x509,
                          &samples[i].sig, &samples[i].sig_len)) {
                fprintf(stderr, "failed to sign sample %d\n", i);
                ERR_print_errors_fp(stderr);
                ret = 1;
                goto out;
            }
        }
    }

    for (int i = 0; i < cfg.iters; i++)
        init_load_attr(&samples[i], &cfg);

    for (int i = 0; i < cfg.iters; i++) {
        double start, end;
        int fd, err = 0, rc = 0;

        errno = 0;
        start = now_ms();
        fd = syscall(__NR_bpf, BPF_PROG_LOAD, &samples[i].attr, attr_sz);
        end = now_ms();

        if (fd < 0) {
            rc = -1;
            err = errno;
        } else {
            close(fd);
        }

        printf("%d\t%.6f\t%d\t%d\n", i, end - start, rc, err);
        if (rc) {
            ret = 1;
            break;
        }
    }

out:
    if (samples) {
        for (int i = 0; i < cfg.iters; i++) {
            if (cfg.signed_load && (!cfg.unique && i > 0))
                continue;
            free(samples[i].sig);
        }
        free(samples);
    }
    X509_free(x509);
    EVP_PKEY_free(key);
    return ret;
}
