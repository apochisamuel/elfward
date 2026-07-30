CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -O2 -std=c11 -Isrc
AR ?= ar

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)
LIB  := libelfward.a

FUZZ_DIR := fuzz
FUZZ_SRCS := $(wildcard $(FUZZ_DIR)/*_fuzzer.c)
FUZZ_BINS := $(FUZZ_SRCS:.c=)

TEST_SRCS := $(wildcard tests/*.c)
TEST_BINS := $(TEST_SRCS:.c=)

TOOL_SRCS := $(wildcard tools/*.c)
TOOL_BINS := $(TOOL_SRCS:.c=)

.PHONY: all clean test fuzz-build

all: $(LIB) tools

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Tools
tools: $(TOOL_BINS)

tools/%: tools/%.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lelfward

# Tests
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "=== $$t ==="; ./$$t || exit 1; done

tests/%: tests/%.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -L. -lelfward

# Fuzz targets (built via build.sh for ClusterFuzzLite)
fuzz-build: $(FUZZ_BINS)

$(FUZZ_DIR)/%_fuzzer: $(FUZZ_DIR)/%_fuzzer.c $(LIB)
	$(CC) $(CFLAGS) $(FUZZER_FLAGS) -o $@ $< -L. -lelfward

clean:
	rm -f $(OBJS) $(LIB) $(TEST_BINS) $(TOOL_BINS) $(FUZZ_BINS)
