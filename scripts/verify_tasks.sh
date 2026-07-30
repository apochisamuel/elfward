#!/bin/bash
# verify_tasks.sh — Build elfward with ASan and verify all PoC crash determinism.
set -e

CC="${CC:-gcc}"
CFLAGS="-fsanitize=address -g -O0 -std=c11 -Isrc"
LDFLAGS="-fsanitize=address"

echo "=== elfward Vulnerability Verification ==="
echo "CC=$CC"
echo ""

# Build library with ASan
echo "[1] Building library with ASan..."
for src in src/*.c; do
    $CC $CFLAGS -c -o "${src%.c}.o" "$src"
done
ar rcs libelfward.a src/*.o
echo "    Library built."

# Build PoC generators
echo "[2] Building PoC generators..."
mkdir -p /tmp/elfward_verify
for gen in private/generators/gen_poc_*.c; do
    name=$(basename "${gen%.c}")
    bugid=$(echo "$name" | sed 's/gen_poc_//')
    $CC -O0 -o "/tmp/elfward_verify/$name" "$gen" 2>/dev/null
    "/tmp/elfward_verify/$name" > "/tmp/elfward_verify/poc_${bugid}.elf"
    echo "    Generated poc_${bugid}.elf"
done

# Build test harness
echo "[3] Building verification harness..."
cat > /tmp/elfward_verify/harness.c << 'HARNESS'
#include "elfward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]); return 1; }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) { perror(argv[1]); return 1; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *data = malloc(sz);
    fread(data, 1, sz, fp);
    fclose(fp);

    ew_context_t *ctx = ew_context_create();
    ew_context_load(ctx, data, sz);

    /* Full analysis pipeline */
    ew_parse_full(ctx);
    ew_build_sysv_hash(ctx);
    ew_build_gnu_hash(ctx);
    ew_resolve_versions(ctx);
    ew_build_dep_graph(ctx);
    ew_resolve_symbols(ctx);
    ew_apply_relocations(ctx);
    ew_validate(ctx);
    ew_normalize(ctx);

    /* Exercise hash lookups */
    static const char *names[] = {"main","printf","target_x","_start","malloc","free"};
    for (int i = 0; i < 6; i++) {
        ew_hash_lookup(ctx, names[i]);
        ew_gnu_hash_lookup(ctx, names[i]);
    }

    /* Exercise version lookups */
    for (uint32_t i = 0; i < ctx->dynsym_count && i < 20; i++) {
        ew_symbol_version_name(ctx, i);
    }

    /* Exercise query API */
    ew_query_result_t *r = ew_query_symbols_by_name(ctx, "main");
    if (r) ew_query_result_destroy(r);
    r = ew_query_undefined_symbols(ctx);
    if (r) ew_query_result_destroy(r);

    /* Exercise snapshot */
    ew_snapshot_t *snap = ew_snapshot_create(ctx);
    if (snap) {
        ew_snapshot_detach(snap);
        ew_snapshot_destroy(snap);
    }

    /* Exercise report */
    ew_report_t *report = ew_report_create(ctx, EW_REPORT_SUMMARY);
    if (report) {
        ew_report_get_text(report);
        ew_report_destroy(report);
    }

    ew_context_destroy(ctx);
    free(data);
    return 0;
}
HARNESS

$CC $CFLAGS -o /tmp/elfward_verify/harness /tmp/elfward_verify/harness.c \
    -L. -lelfward $LDFLAGS
echo "    Harness built."

# Test each PoC
echo ""
echo "[4] Verifying PoC crashes..."
PASS=0
FAIL=0
for poc in /tmp/elfward_verify/poc_*.elf; do
    bugid=$(basename "${poc%.elf}" | sed 's/poc_//')
    printf "    %-10s " "C${bugid}:"

    output=$(/tmp/elfward_verify/harness "$poc" 2>&1 || true)
    if echo "$output" | grep -q "AddressSanitizer"; then
        asantype=$(echo "$output" | grep "SUMMARY:" | sed 's/.*AddressSanitizer: //' | cut -d' ' -f1-2)
        echo "CRASH ✓ ($asantype)"
        PASS=$((PASS + 1))
    else
        echo "NO CRASH ✗"
        FAIL=$((FAIL + 1))
    fi
done

# Also test API-triggered bugs (C6, C7, C9)
echo ""
echo "[5] Verifying API-pattern bugs..."

# C6: Snapshot detach double-free (already tested via harness snapshot exercise)
# C7: Recovery depth overflow
cat > /tmp/elfward_verify/test_c7.c << 'C7TEST'
#include "elfward.h"
#include <string.h>
int main(void) {
    uint8_t bad[128] = {0};
    bad[0]=0x7f;bad[1]='E';bad[2]='L';bad[3]='F';bad[4]=2;bad[5]=1;bad[6]=1;
    bad[16]=2;bad[18]=0x3e;bad[20]=1;bad[40]=64;bad[52]=64;bad[54]=56;
    bad[58]=64;bad[60]=100;
    ew_context_t *ctx = ew_context_create();
    ew_context_load(ctx, bad, sizeof(bad));
    for (int i = 0; i < 20; i++) {
        ctx->in_recovery = 0;
        ew_recover_parse(ctx);
    }
    ew_context_destroy(ctx);
    return 0;
}
C7TEST
$CC $CFLAGS -o /tmp/elfward_verify/test_c7 /tmp/elfward_verify/test_c7.c \
    -L. -lelfward $LDFLAGS

printf "    %-10s " "C7:"
output=$(ASAN_OPTIONS=detect_leaks=0 /tmp/elfward_verify/test_c7 2>&1 || true)
if echo "$output" | grep -q "AddressSanitizer"; then
    echo "CRASH ✓ (recovery depth)"
    PASS=$((PASS + 1))
else
    echo "NO CRASH ✗"
    FAIL=$((FAIL + 1))
fi

# C9: Registry UAF
cat > /tmp/elfward_verify/test_c9.c << 'C9TEST'
#include "elfward.h"
int main(void) {
    ew_registry_t *reg = ew_registry_create(1);
    ew_context_t *c1 = ew_context_create();
    ew_context_t *c2 = ew_context_create();
    ew_context_t *c3 = ew_context_create();
    ew_registry_add(reg, "libA.so", 0x1000, c1);
    ew_registry_add(reg, "libB.so", 0x2000, c2);
    ew_registry_add(reg, "libC.so", 0x3000, c3);
    ew_registry_remove(reg, "libB.so");
    ew_registry_find(reg, "libA.so");
    ew_registry_destroy(reg);
    ew_context_destroy(c1);
    ew_context_destroy(c2);
    ew_context_destroy(c3);
    return 0;
}
C9TEST
$CC $CFLAGS -o /tmp/elfward_verify/test_c9 /tmp/elfward_verify/test_c9.c \
    -L. -lelfward $LDFLAGS

printf "    %-10s " "C9:"
output=$(ASAN_OPTIONS=detect_leaks=0 /tmp/elfward_verify/test_c9 2>&1 || true)
if echo "$output" | grep -q "AddressSanitizer"; then
    echo "CRASH ✓ (registry UAF)"
    PASS=$((PASS + 1))
else
    echo "NO CRASH ✗"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
