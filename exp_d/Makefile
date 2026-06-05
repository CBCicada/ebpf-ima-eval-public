ROOT := ..
.DEFAULT_GOAL := run

ITERS ?= 1000
RUN_NAME ?= run
SIGNED ?= 0
UNIQUE ?= 0
SALT_BASE ?= $(shell n=$$(date +%s%N); printf '%d' $$((n % 1000000000)))
SIGNER_TAG ?= $(shell if uname -r | grep -q rc4; then printf 'linux_6_19_rc4'; elif uname -r | grep -q rc1; then printf 'ebpf_ima_linux'; else printf 'unknown'; fi)
SIGN_KEY ?= keys/signing_key.$(SIGNER_TAG).pem
SIGN_CERT ?= keys/signing_cert.$(SIGNER_TAG).pem
KEYRING_ID ?=

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
CFLAGS += -I$(ROOT)/ebpf-ima-linux/tools/include/uapi
LDLIBS += -lcrypto

.PHONY: all clean run

all: run

load_perf: src/load_perf.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

run: load_perf
	mkdir -p results
	set -e; \
	out="results/$$(date +%Y%m%d-%H%M%S)-$(RUN_NAME)"; \
	mkdir -p "$$out"; \
	args="--iters $(ITERS)"; \
	if [ "$(UNIQUE)" = "1" ]; then args="$$args --unique --salt-base $(SALT_BASE)"; fi; \
	if [ "$(SIGNED)" = "1" ]; then \
		test -f "$(SIGN_KEY)" || { printf 'missing SIGN_KEY=%s\n' "$(SIGN_KEY)" >&2; exit 2; }; \
		test -f "$(SIGN_CERT)" || { printf 'missing SIGN_CERT=%s\n' "$(SIGN_CERT)" >&2; exit 2; }; \
		keyring="$(KEYRING_ID)"; \
		if [ -z "$$keyring" ]; then keyring="$$(sudo keyctl describe %:.ima 2>/dev/null | cut -d: -f1)"; fi; \
		test -n "$$keyring" || { printf 'missing KEYRING_ID and cannot resolve %%:.ima\n' >&2; exit 2; }; \
		args="$$args --signed --sign-key $(SIGN_KEY) --sign-cert $(SIGN_CERT) --keyring-id $$keyring"; \
	fi; \
	{ \
		printf 'run_name\t%s\n' "$(RUN_NAME)"; \
		printf 'iters\t%s\n' "$(ITERS)"; \
		printf 'signed\t%s\n' "$(SIGNED)"; \
		printf 'unique\t%s\n' "$(UNIQUE)"; \
		printf 'salt_base\t%s\n' "$(SALT_BASE)"; \
	} > "$$out/meta.tsv"; \
	sudo ./load_perf $$args > "$$out/load.tsv"; \
	printf '%s\n' "$$out"

clean:
	rm -rf load_perf results
