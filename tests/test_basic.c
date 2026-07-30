/*
 * test_basic.c — Basic integration tests for elfward.
 *
 * Constructs minimal valid ELF32 and ELF64 binaries in memory
 * and verifies the library can parse them correctly.
 */

#include "elfward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    printf("  %-50s", name); \
    tests_run++; \
} while (0)

#define PASS() do { \
    printf("PASS\n"); \
    tests_passed++; \
} while (0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while (0)

/* ------------------------------------------------------------------ */
/* Build minimal ELF64 header in memory                                */
/* ------------------------------------------------------------------ */

static uint8_t *make_minimal_elf64(size_t *out_size)
{
    /* ELF64 header = 64 bytes, 1 section header = 64 bytes */
    size_t total = 64 + 64;
    uint8_t *buf = calloc(1, total);
    if (!buf) return NULL;

    /* ELF magic */
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    /* Class: ELF64 */
    buf[4] = 2;
    /* Data: little endian */
    buf[5] = 1;
    /* Version */
    buf[6] = 1;
    /* OS/ABI */
    buf[7] = 0;
    /* Type: ET_EXEC */
    buf[16] = 2; buf[17] = 0;
    /* Machine: EM_X86_64 */
    buf[18] = 0x3e; buf[19] = 0;
    /* Version */
    buf[20] = 1; buf[21] = 0; buf[22] = 0; buf[23] = 0;
    /* Entry point */
    buf[24] = 0; /* e_entry = 0 */
    /* Program header offset = 0 (none) */
    /* Section header offset = 64 */
    buf[40] = 64; /* e_shoff = 64 (little endian) */
    /* Flags */
    buf[48] = 0;
    /* ELF header size = 64 */
    buf[52] = 64; buf[53] = 0;
    /* Program header entry size */
    buf[54] = 56; buf[55] = 0;
    /* Number of program headers = 0 */
    buf[56] = 0;
    /* Section header entry size = 64 */
    buf[58] = 64; buf[59] = 0;
    /* Number of section headers = 1 */
    buf[60] = 1; buf[61] = 0;
    /* Section name string table index = 0 */
    buf[62] = 0;

    /* Section 0: SHT_NULL (all zeros, already zeroed by calloc) */

    *out_size = total;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Build minimal ELF32 header in memory                                */
/* ------------------------------------------------------------------ */

static uint8_t *make_minimal_elf32(size_t *out_size)
{
    /* ELF32 header = 52 bytes, 1 section header = 40 bytes */
    size_t total = 52 + 40;
    uint8_t *buf = calloc(1, total);
    if (!buf) return NULL;

    /* ELF magic */
    buf[0] = 0x7f; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    /* Class: ELF32 */
    buf[4] = 1;
    /* Data: little endian */
    buf[5] = 1;
    /* Version */
    buf[6] = 1;
    /* Type: ET_EXEC */
    buf[16] = 2; buf[17] = 0;
    /* Machine: EM_386 */
    buf[18] = 3; buf[19] = 0;
    /* Version */
    buf[20] = 1;
    /* Section header offset = 52 */
    buf[32] = 52;
    /* ELF header size = 52 */
    buf[40] = 52; buf[41] = 0;
    /* Program header entry size = 32 */
    buf[42] = 32;
    /* Number of program headers = 0 */
    buf[44] = 0;
    /* Section header entry size = 40 */
    buf[46] = 40; buf[47] = 0;
    /* Number of section headers = 1 */
    buf[48] = 1;
    /* shstrndx = 0 */
    buf[50] = 0;

    *out_size = total;
    return buf;
}

/* ------------------------------------------------------------------ */
/* Test: Context lifecycle                                             */
/* ------------------------------------------------------------------ */

static void test_context_lifecycle(void)
{
    TEST("context create/destroy");

    ew_context_t *ctx = ew_context_create();
    if (!ctx) { FAIL("create returned NULL"); return; }

    ew_context_destroy(ctx);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Parse minimal ELF64                                           */
/* ------------------------------------------------------------------ */

static void test_parse_elf64(void)
{
    TEST("parse minimal ELF64");

    size_t size;
    uint8_t *data = make_minimal_elf64(&size);
    if (!data) { FAIL("alloc"); return; }

    ew_context_t *ctx = ew_context_create();
    ew_error_t err = ew_context_load(ctx, data, size);
    if (err != EW_OK) { FAIL("load"); free(data); ew_context_destroy(ctx); return; }

    err = ew_parse_header(ctx);
    if (err != EW_OK) { FAIL("parse_header"); free(data); ew_context_destroy(ctx); return; }

    if (!ctx->is_64bit) { FAIL("not 64-bit"); free(data); ew_context_destroy(ctx); return; }
    if (ctx->is_big_endian) { FAIL("wrong endian"); free(data); ew_context_destroy(ctx); return; }
    if (ctx->header.e_type != EW_ET_EXEC) { FAIL("wrong type"); free(data); ew_context_destroy(ctx); return; }
    if (ctx->header.e_machine != EW_EM_X86_64) { FAIL("wrong machine"); free(data); ew_context_destroy(ctx); return; }

    err = ew_parse_sections(ctx);
    if (err != EW_OK) { FAIL("parse_sections"); free(data); ew_context_destroy(ctx); return; }

    if (ctx->section_count != 1) { FAIL("wrong section count"); free(data); ew_context_destroy(ctx); return; }

    ew_context_destroy(ctx);
    free(data);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Parse minimal ELF32                                           */
/* ------------------------------------------------------------------ */

static void test_parse_elf32(void)
{
    TEST("parse minimal ELF32");

    size_t size;
    uint8_t *data = make_minimal_elf32(&size);
    if (!data) { FAIL("alloc"); return; }

    ew_context_t *ctx = ew_context_create();
    ew_error_t err = ew_context_load(ctx, data, size);
    if (err != EW_OK) { FAIL("load"); free(data); ew_context_destroy(ctx); return; }

    err = ew_parse_header(ctx);
    if (err != EW_OK) { FAIL("parse_header"); free(data); ew_context_destroy(ctx); return; }

    if (ctx->is_64bit) { FAIL("should be 32-bit"); free(data); ew_context_destroy(ctx); return; }

    ew_context_destroy(ctx);
    free(data);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Invalid data                                                  */
/* ------------------------------------------------------------------ */

static void test_invalid_magic(void)
{
    TEST("reject invalid magic");

    uint8_t data[64] = {0};
    data[0] = 0x7f;
    data[1] = 'X';  /* wrong */

    ew_context_t *ctx = ew_context_create();
    ew_context_load(ctx, data, sizeof(data));

    ew_error_t err = ew_parse_header(ctx);
    if (err != EW_ERR_BAD_MAGIC) { FAIL("should fail with BAD_MAGIC"); ew_context_destroy(ctx); return; }

    ew_context_destroy(ctx);
    PASS();
}

static void test_too_small(void)
{
    TEST("reject too-small input");

    uint8_t data[4] = {0x7f, 'E', 'L', 'F'};

    ew_context_t *ctx = ew_context_create();
    ew_error_t err = ew_context_load(ctx, data, sizeof(data));
    /* Should fail because < 16 bytes */
    if (err == EW_OK) {
        err = ew_parse_header(ctx);
        if (err == EW_OK) { FAIL("should reject tiny input"); ew_context_destroy(ctx); return; }
    }

    ew_context_destroy(ctx);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Error strings                                                 */
/* ------------------------------------------------------------------ */

static void test_error_strings(void)
{
    TEST("error string lookup");

    const char *s = ew_error_string(EW_OK);
    if (!s || strlen(s) == 0) { FAIL("OK string empty"); return; }

    s = ew_error_string(EW_ERR_BAD_MAGIC);
    if (!s || strlen(s) == 0) { FAIL("BAD_MAGIC string empty"); return; }

    s = ew_error_string(EW_ERR_NOMEM);
    if (!s || strlen(s) == 0) { FAIL("NOMEM string empty"); return; }

    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Cache operations                                              */
/* ------------------------------------------------------------------ */

static void test_cache(void)
{
    TEST("cache put/get/invalidate");

    ew_cache_t *cache = ew_cache_create(32);
    if (!cache) { FAIL("create"); return; }

    int val1 = 42, val2 = 99;
    ew_cache_put(cache, 100, &val1);
    ew_cache_put(cache, 200, &val2);

    void *got = ew_cache_get(cache, 100);
    if (got != &val1) { FAIL("get 100"); ew_cache_destroy(cache); return; }

    got = ew_cache_get(cache, 200);
    if (got != &val2) { FAIL("get 200"); ew_cache_destroy(cache); return; }

    ew_cache_invalidate(cache, 100);
    got = ew_cache_get(cache, 100);
    if (got != NULL) { FAIL("should be invalidated"); ew_cache_destroy(cache); return; }

    ew_cache_freeze(cache);
    ew_error_t err = ew_cache_put(cache, 300, &val1);
    if (err != EW_ERR_READONLY) { FAIL("should be frozen"); ew_cache_destroy(cache); return; }

    ew_cache_destroy(cache);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Recoverability classification                                 */
/* ------------------------------------------------------------------ */

static void test_recoverability(void)
{
    TEST("error recoverability classification");

    if (!ew_is_recoverable(EW_OK)) { FAIL("OK should be recoverable"); return; }
    if (ew_is_recoverable(EW_ERR_NOMEM)) { FAIL("NOMEM should not be"); return; }
    if (!ew_is_recoverable(EW_ERR_BAD_SECTION)) { FAIL("BAD_SECTION should be"); return; }
    if (ew_is_recoverable(EW_ERR_BAD_MAGIC)) { FAIL("BAD_MAGIC should not be"); return; }

    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Report generation                                             */
/* ------------------------------------------------------------------ */

static void test_report_on_elf64(void)
{
    TEST("report generation on ELF64");

    size_t size;
    uint8_t *data = make_minimal_elf64(&size);
    if (!data) { FAIL("alloc"); return; }

    ew_context_t *ctx = ew_context_create();
    ew_context_load(ctx, data, size);
    ew_parse_header(ctx);
    ew_parse_sections(ctx);

    ew_report_t *report = ew_report_create(ctx, EW_REPORT_SUMMARY);
    if (!report) { FAIL("report create"); free(data); ew_context_destroy(ctx); return; }

    const char *text = ew_report_get_text(report);
    if (!text || strlen(text) == 0) { FAIL("empty report"); ew_report_destroy(report); free(data); ew_context_destroy(ctx); return; }

    ew_report_destroy(report);
    ew_context_destroy(ctx);
    free(data);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Test: Name lookup functions                                         */
/* ------------------------------------------------------------------ */

static void test_name_lookups(void)
{
    TEST("name lookup functions");

    const char *s;
    s = ew_machine_name(EW_EM_X86_64);
    if (!s || strlen(s) == 0) { FAIL("machine name"); return; }

    s = ew_type_name(EW_ET_EXEC);
    if (!s || strlen(s) == 0) { FAIL("type name"); return; }

    s = ew_section_type_name(EW_SHT_SYMTAB);
    if (!s || strlen(s) == 0) { FAIL("section type name"); return; }

    s = ew_segment_type_name(EW_PT_LOAD);
    if (!s || strlen(s) == 0) { FAIL("segment type name"); return; }

    PASS();
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("elfward basic tests\n");
    printf("===================\n");

    test_context_lifecycle();
    test_parse_elf64();
    test_parse_elf32();
    test_invalid_magic();
    test_too_small();
    test_error_strings();
    test_cache();
    test_recoverability();
    test_report_on_elf64();
    test_name_lookups();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
