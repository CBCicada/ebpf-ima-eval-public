ROOT := ..
BUILD := build
.DEFAULT_GOAL := run

ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(origin PAYLOAD_KB), undefined)
$(error PAYLOAD_KB is required, e.g. make PAYLOAD_KB=88 RUN_NAME=no_ima)
endif
endif

OBJ := build/payload_$(PAYLOAD_KB)kb.bpf.o
PIN_PATH ?= /sys/fs/bpf/ima_exp_d_loadbench
RUN_NAME ?= run
SIGN_KEY ?= keys/signing_key.pem
SIGN_CERT ?= keys/signing_cert.pem

CLANG ?= clang
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf
BPF_INCLUDES := -I$(ROOT)/ebpf-ima-linux/tools/lib -I$(ROOT)/ebpf-ima-linux/tools/include/uapi

.PHONY: all clean load_bench payload run

all: run

load_bench: src/load_bench.c
	$(CC) $(CFLAGS) \
		-DOBJ_PATH='"$(OBJ)"' \
		-DPIN_PATH='"$(PIN_PATH)"' \
		-DSIGN_KEY='"$(SIGN_KEY)"' \
		-DSIGN_CERT='"$(SIGN_CERT)"' \
		-o $@ $<

$(BUILD):
	mkdir -p $@

$(BUILD)/%.bpf.o: src/%.bpf.c | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

$(BUILD)/payload_$(PAYLOAD_KB)kb.bpf.c: src/payload.bpf.c.in | $(BUILD)
	sed -e 's/@PAYLOAD_KB@/$(PAYLOAD_KB)/g' -e 's/@PROG_NAME@/payload_$(PAYLOAD_KB)kb/g' $< > $@

$(BUILD)/payload_$(PAYLOAD_KB)kb.bpf.o: $(BUILD)/payload_$(PAYLOAD_KB)kb.bpf.c
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

payload: $(BUILD)/payload_$(PAYLOAD_KB)kb.bpf.o

run: payload load_bench
	@test -f "$(SIGN_KEY)" || { printf 'missing SIGN_KEY=%s\n' "$(SIGN_KEY)" >&2; exit 2; }
	@test -f "$(SIGN_CERT)" || { printf 'missing SIGN_CERT=%s\n' "$(SIGN_CERT)" >&2; exit 2; }
	mkdir -p results
	set -e; \
	out="results/$$(date +%Y%m%d-%H%M%S)-$(RUN_NAME)-$(PAYLOAD_KB)kb"; \
	mkdir -p "$$out"; \
	sudo ./load_bench > "$$out/load.tsv"; \
	printf '%s\n' "$$out"

clean:
	rm -rf $(BUILD) load_bench results
