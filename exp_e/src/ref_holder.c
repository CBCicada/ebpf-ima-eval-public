// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define ptr_to_u64(ptr) ((__u64)(unsigned long)(ptr))

struct held_fd {
    int fd;
    const char *kind;
    const char *path;
    int slot;
    int reported_open;
    int reported_closed;
};

static volatile sig_atomic_t sigusr1_count;
static volatile sig_atomic_t sigusr2_count;

static const char *tracepoints[] = {
    "raw_syscalls/sys_enter",
    "raw_syscalls/sys_exit",
    "sched/sched_switch",
    "sched/sched_wakeup",
    "sched/sched_wakeup_new",
    "sched/sched_process_fork",
    "sched/sched_process_exit",
    "sched/sched_process_exec",
    "irq/softirq_entry",
    "irq/softirq_exit",
    "irq/irq_handler_entry",
    "irq/irq_handler_exit",
    "timer/timer_start",
    "timer/timer_cancel",
    "timer/hrtimer_start",
    "timer/hrtimer_cancel",
    "exceptions/page_fault_user",
    "exceptions/page_fault_kernel",
};

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
                           int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int read_tracepoint_id(int index)
{
    const char *roots[] = {
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    };
    char buf[64];
    char path[256];

    if (index < 0 || (size_t)index >= sizeof(tracepoints) / sizeof(tracepoints[0])) {
        errno = ERANGE;
        return -1;
    }

    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        FILE *f;

        snprintf(path, sizeof(path), "%s/%s/id", roots[i], tracepoints[index]);
        f = fopen(path, "r");
        if (!f)
            continue;
        if (fgets(buf, sizeof(buf), f)) {
            fclose(f);
            return atoi(buf);
        }
        fclose(f);
    }
    return -1;
}

static int open_tracepoint_perf_event(int index)
{
    struct perf_event_attr attr;
    int id = read_tracepoint_id(index);
    int fd;

    if (id < 0) {
        fprintf(stderr, "could not read tracepoint id for slot %d\n", index);
        return -1;
    }

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = (unsigned long long)id;
    attr.sample_period = 1;
    attr.wakeup_events = 1;

    fd = perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        return -1;
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

static int create_perf_link(int prog_fd, int index)
{
    union bpf_attr attr;
    int perf_fd = open_tracepoint_perf_event(index);
    int link_fd;

    if (perf_fd < 0)
        return -1;

    memset(&attr, 0, sizeof(attr));
    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = perf_fd;
    attr.link_create.attach_type = BPF_PERF_EVENT;

    link_fd = sys_bpf(BPF_LINK_CREATE, &attr);
    close(perf_fd);
    return link_fd;
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

static int prog_array_create(int entries)
{
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_PROG_ARRAY;
    attr.key_size = sizeof(__u32);
    attr.value_size = sizeof(__u32);
    attr.max_entries = entries;
    return sys_bpf(BPF_MAP_CREATE, &attr);
}

static int map_update_prog(int map_fd, __u32 key, int prog_fd)
{
    union bpf_attr attr;
    __u32 value = (__u32)prog_fd;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd;
    attr.key = ptr_to_u64(&key);
    attr.value = ptr_to_u64(&value);
    attr.flags = BPF_ANY;
    return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr);
}

static void note_signal(int signo)
{
    if (signo == SIGUSR1)
        sigusr1_count++;
    else if (signo == SIGUSR2)
        sigusr2_count++;
}

static void setup_signals(void)
{
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = note_signal;
    sigemptyset(&act.sa_mask);
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGUSR2, &act, NULL);
}

static void report_signals(void)
{
    static int reported_usr1;
    static int reported_usr2;

    if (reported_usr1 != sigusr1_count) {
        reported_usr1 = sigusr1_count;
        printf("signal signo=SIGUSR1 count=%d\n", reported_usr1);
        fflush(stdout);
    }
    if (reported_usr2 != sigusr2_count) {
        reported_usr2 = sigusr2_count;
        printf("signal signo=SIGUSR2 count=%d\n", reported_usr2);
        fflush(stdout);
    }
}

static void report_fd_states(struct held_fd *records, int count)
{
    for (int i = 0; i < count; i++) {
        int rc;

        errno = 0;
        rc = fcntl(records[i].fd, F_GETFD);
        if (rc < 0 && errno == EBADF) {
            if (!records[i].reported_closed) {
                records[i].reported_closed = 1;
                printf("fd_state kind=%s fd=%d path=%s slot=%d state=closed\n",
                       records[i].kind, records[i].fd, records[i].path, records[i].slot);
                fflush(stdout);
            }
        } else if (!records[i].reported_open) {
            records[i].reported_open = 1;
            printf("fd_state kind=%s fd=%d path=%s slot=%d state=open\n",
                   records[i].kind, records[i].fd, records[i].path, records[i].slot);
            fflush(stdout);
        }
    }
}

static void sleep_seconds(int seconds, struct held_fd *records, int record_count)
{
    struct timespec end, now;

    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_sec += seconds;
    for (;;) {
        struct timespec req = { .tv_sec = 1, .tv_nsec = 0 };

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > end.tv_sec || (now.tv_sec == end.tv_sec && now.tv_nsec >= end.tv_nsec))
            break;
        nanosleep(&req, NULL);
        report_signals();
        if (sigusr1_count || sigusr2_count)
            report_fd_states(records, record_count);
    }
}

static int hold_main(int argc, char **argv)
{
    int seconds, total = 0;
    struct held_fd *records;

    if (argc < 4 || ((argc - 2) % 2) != 0) {
        fprintf(stderr, "usage: ref_holder hold SECONDS PATH COPIES [PATH COPIES ...]\n");
        return 2;
    }

    seconds = atoi(argv[1]);
    for (int i = 3; i < argc; i += 2)
        total += atoi(argv[i]);

    records = calloc((size_t)total, sizeof(*records));
    if (!records) {
        perror("calloc");
        return 1;
    }

    setup_signals();

    int n = 0;
    for (int i = 2; i < argc; i += 2) {
        const char *path = argv[i];
        int copies = atoi(argv[i + 1]);

        for (int j = 0; j < copies; j++) {
            records[n].fd = obj_get(path);
            if (records[n].fd < 0) {
                perror(path);
                return 1;
            }
            records[n].kind = "obj";
            records[n].path = path;
            records[n].slot = -1;
            n++;
        }
    }

    for (int i = 0; i < total; i++)
        printf("held kind=%s fd=%d path=%s slot=%d\n",
               records[i].kind, records[i].fd, records[i].path, records[i].slot);
    printf("ready\n");
    fflush(stdout);
    sleep_seconds(seconds, records, total);
    return 0;
}

static int prog_array_main(int argc, char **argv)
{
    const char *pin;
    int entries, map_fd;

    if (argc < 4) {
        fprintf(stderr, "usage: ref_holder prog_array MAP_PIN ENTRIES PROG_PIN [PROG_PIN ...]\n");
        return 2;
    }

    pin = argv[1];
    entries = atoi(argv[2]);
    map_fd = prog_array_create(entries);
    if (map_fd < 0) {
        perror("BPF_MAP_CREATE prog_array");
        return 1;
    }

    for (int i = 0; i < entries; i++) {
        const char *prog_pin = argv[3 + (i % (argc - 3))];
        int prog_fd = obj_get(prog_pin);
        if (prog_fd < 0) {
            perror(prog_pin);
            return 1;
        }
        if (map_update_prog(map_fd, (__u32)i, prog_fd) < 0) {
            perror("BPF_MAP_UPDATE_ELEM");
            return 1;
        }
        close(prog_fd);
    }

    unlink(pin);
    if (obj_pin(map_fd, pin) < 0) {
        perror(pin);
        return 1;
    }
    return 0;
}

static int link_hold_main(int argc, char **argv)
{
    int seconds, count, start_index, total;
    struct held_fd *records;

    if (argc < 5) {
        fprintf(stderr, "usage: ref_holder link_hold SECONDS COUNT START_INDEX PROG_PIN [PROG_PIN ...]\n");
        return 2;
    }

    seconds = atoi(argv[1]);
    count = atoi(argv[2]);
    start_index = atoi(argv[3]);
    total = count * (argc - 4);
    records = calloc((size_t)total, sizeof(*records));
    if (!records) {
        perror("calloc");
        return 1;
    }

    setup_signals();

    int n = 0;
    for (int i = 4; i < argc; i++) {
        int prog_fd = obj_get(argv[i]);
        if (prog_fd < 0) {
            perror(argv[i]);
            return 1;
        }
        for (int j = 0; j < count; j++) {
            records[n].fd = create_perf_link(prog_fd, start_index + j);
            if (records[n].fd < 0) {
                perror("BPF_LINK_CREATE");
                return 1;
            }
            records[n].kind = "link";
            records[n].path = argv[i];
            records[n].slot = start_index + j;
            n++;
        }
        close(prog_fd);
    }

    for (int i = 0; i < total; i++)
        printf("held kind=%s fd=%d path=%s slot=%d tracepoint=%s\n",
               records[i].kind, records[i].fd, records[i].path, records[i].slot,
               tracepoints[records[i].slot]);
    printf("ready\n");
    fflush(stdout);
    sleep_seconds(seconds, records, total);
    return 0;
}

static int link_pin_main(int argc, char **argv)
{
    const char *dir;
    int count, start_index;

    if (argc < 5) {
        fprintf(stderr, "usage: ref_holder link_pin DIR COUNT START_INDEX PROG_PIN [PROG_PIN ...]\n");
        return 2;
    }

    dir = argv[1];
    count = atoi(argv[2]);
    start_index = atoi(argv[3]);
    for (int i = 4; i < argc; i++) {
        int prog_fd = obj_get(argv[i]);
        if (prog_fd < 0) {
            perror(argv[i]);
            return 1;
        }
        for (int j = 0; j < count; j++) {
            char pin[512];
            int link_fd = create_perf_link(prog_fd, start_index + j);
            if (link_fd < 0) {
                perror("BPF_LINK_CREATE");
                return 1;
            }
            snprintf(pin, sizeof(pin), "%s/link_%d_%d", dir, i - 4, j);
            unlink(pin);
            if (obj_pin(link_fd, pin) < 0) {
                perror(pin);
                return 1;
            }
            close(link_fd);
        }
        close(prog_fd);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "hold"))
        return hold_main(argc - 1, argv + 1);
    if (!strcmp(argv[1], "prog_array"))
        return prog_array_main(argc - 1, argv + 1);
    if (!strcmp(argv[1], "link_hold"))
        return link_hold_main(argc - 1, argv + 1);
    if (!strcmp(argv[1], "link_pin"))
        return link_pin_main(argc - 1, argv + 1);
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 2;
}
