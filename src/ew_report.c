/*
 * ew_report.c — Formatted text reporting of parsed ELF data.
 *
 * Generates human-readable reports of ELF structures, similar to
 * readelf output. Reports are accumulated in a dynamically-growing
 * buffer and can be retrieved or written to a file descriptor.
 */

#include "elfward.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Report buffer management                                            */
/* ------------------------------------------------------------------ */

static ew_error_t report_ensure(ew_report_t *report, size_t extra)
{
    size_t needed = report->length + extra + 1;
    if (needed <= report->capacity)
        return EW_OK;

    size_t new_cap = report->capacity == 0 ? 4096 : report->capacity;
    while (new_cap < needed)
        new_cap *= 2;

    char *tmp = realloc(report->buffer, new_cap);
    if (!tmp)
        return EW_ERR_NOMEM;

    report->buffer = tmp;
    report->capacity = new_cap;
    return EW_OK;
}

static ew_error_t report_append(ew_report_t *report, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);

    if (needed < 0)
        return EW_ERR_INTERNAL;

    ew_error_t err = report_ensure(report, (size_t)needed);
    if (err != EW_OK)
        return err;

    va_start(ap, fmt);
    vsnprintf(report->buffer + report->length, (size_t)needed + 1, fmt, ap);
    va_end(ap);

    report->length += (size_t)needed;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Summary report                                                      */
/* ------------------------------------------------------------------ */

static ew_error_t generate_summary(ew_report_t *report, ew_context_t *ctx)
{
    report_append(report, "ELF Analysis Summary\n");
    report_append(report, "====================\n\n");

    report_append(report, "Class:       %s\n",
                  ctx->is_64bit ? "ELF64" : "ELF32");
    report_append(report, "Encoding:    %s\n",
                  ctx->is_big_endian ? "Big Endian" : "Little Endian");
    report_append(report, "Type:        %s\n",
                  ew_type_name(ctx->header.e_type));
    report_append(report, "Machine:     %s\n",
                  ew_machine_name(ctx->header.e_machine));
    report_append(report, "Entry point: 0x%lx\n",
                  (unsigned long)ctx->header.e_entry);
    report_append(report, "Flags:       0x%x\n", ctx->header.e_flags);
    report_append(report, "\n");

    report_append(report, "Sections:    %u\n", ctx->section_count);
    report_append(report, "Segments:    %u\n", ctx->segment_count);
    report_append(report, "Symbols:     %u (static) + %u (dynamic)\n",
                  ctx->symtab_count, ctx->dynsym_count);
    report_append(report, "Relocations: %u\n", ctx->reloc_count);
    report_append(report, "Dynamic:     %u entries\n", ctx->dynamic_count);
    report_append(report, "Notes:       %u\n", ctx->note_count);
    report_append(report, "Version defs: %u\n", ctx->verdef_count);
    report_append(report, "Version needs: %u\n", ctx->verneed_count);
    report_append(report, "\n");

    report_append(report, "State: parsed=%d resolved=%d validated=%d "
                  "normalized=%d cached=%d registered=%d\n",
                  ctx->parsed, ctx->resolved, ctx->validated,
                  ctx->normalized, ctx->cached, ctx->registered);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Sections report                                                     */
/* ------------------------------------------------------------------ */

static ew_error_t generate_sections(ew_report_t *report, ew_context_t *ctx)
{
    report_append(report, "Section Headers:\n");
    report_append(report, "  [Nr] %-20s %-12s %16s %8s %8s %2s %3s\n",
                  "Name", "Type", "Address", "Offset", "Size", "Lk", "Inf");

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        report_append(report,
                      "  [%2u] %-20s %-12s %016lx %08lx %08lx %2u %3u\n",
                      i,
                      sec->name ? sec->name : "",
                      ew_section_type_name(sec->sh_type),
                      (unsigned long)sec->sh_addr,
                      (unsigned long)sec->sh_offset,
                      (unsigned long)sec->sh_size,
                      sec->sh_link,
                      sec->sh_info);
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Segments report                                                     */
/* ------------------------------------------------------------------ */

static ew_error_t generate_segments(ew_report_t *report, ew_context_t *ctx)
{
    report_append(report, "\nProgram Headers:\n");
    report_append(report, "  %-14s %8s %16s %16s %8s %8s %3s %s\n",
                  "Type", "Offset", "VirtAddr", "PhysAddr",
                  "FileSiz", "MemSiz", "Flg", "Align");

    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg = &ctx->segments[i];
        char flags[4] = "   ";
        if (seg->p_flags & EW_PF_R) flags[0] = 'R';
        if (seg->p_flags & EW_PF_W) flags[1] = 'W';
        if (seg->p_flags & EW_PF_X) flags[2] = 'E';

        report_append(report,
                      "  %-14s %08lx %016lx %016lx %08lx %08lx %s %lx\n",
                      ew_segment_type_name(seg->p_type),
                      (unsigned long)seg->p_offset,
                      (unsigned long)seg->p_vaddr,
                      (unsigned long)seg->p_paddr,
                      (unsigned long)seg->p_filesz,
                      (unsigned long)seg->p_memsz,
                      flags,
                      (unsigned long)seg->p_align);
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Symbols report                                                      */
/* ------------------------------------------------------------------ */

static ew_error_t generate_symbols_table(ew_report_t *report,
                                          ew_symbol_t *syms, uint32_t count,
                                          const char *table_name)
{
    report_append(report, "\n%s (%u entries):\n", table_name, count);
    report_append(report, "  Num:    Value          Size Type    Bind   "
                  "Vis      Ndx Name\n");

    for (uint32_t i = 0; i < count && i < 200; i++) {
        ew_symbol_t *sym = &syms[i];
        const char *ndx_str;
        char ndx_buf[16];

        switch (sym->st_shndx) {
        case EW_SHN_UNDEF: ndx_str = "UND"; break;
        case EW_SHN_ABS:   ndx_str = "ABS"; break;
        case EW_SHN_COMMON: ndx_str = "COM"; break;
        default:
            snprintf(ndx_buf, sizeof(ndx_buf), "%3u", sym->st_shndx);
            ndx_str = ndx_buf;
            break;
        }

        report_append(report,
                      "  %4u: %016lx %5lu %-7s %-6s %-8s %s %s\n",
                      i,
                      (unsigned long)sym->st_value,
                      (unsigned long)sym->st_size,
                      ew_symbol_type_name(EW_ELF_ST_TYPE(sym->st_info)),
                      ew_symbol_binding_name(EW_ELF_ST_BIND(sym->st_info)),
                      sym->st_other == 0 ? "DEFAULT" : "HIDDEN",
                      ndx_str,
                      sym->name ? sym->name : "");
    }

    if (count > 200)
        report_append(report, "  ... (%u more entries)\n", count - 200);

    return EW_OK;
}

static ew_error_t generate_symbols(ew_report_t *report, ew_context_t *ctx)
{
    if (ctx->symtab && ctx->symtab_count > 0) {
        generate_symbols_table(report, ctx->symtab, ctx->symtab_count,
                               "Symbol Table (.symtab)");
    }

    if (ctx->dynsym && ctx->dynsym_count > 0) {
        generate_symbols_table(report, ctx->dynsym, ctx->dynsym_count,
                               "Symbol Table (.dynsym)");
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Dynamic section report                                              */
/* ------------------------------------------------------------------ */

static ew_error_t generate_dynamic(ew_report_t *report, ew_context_t *ctx)
{
    if (!ctx->dynamics || ctx->dynamic_count == 0)
        return EW_OK;

    report_append(report, "\nDynamic Section (%u entries):\n",
                  ctx->dynamic_count);
    report_append(report, "  %-14s %-18s %s\n", "Tag", "Value", "Name/Info");

    for (uint32_t i = 0; i < ctx->dynamic_count; i++) {
        ew_dynamic_entry_t *dyn = &ctx->dynamics[i];
        if (dyn->d_tag == EW_DT_NULL) {
            report_append(report, "  %-14s 0x%016lx\n",
                          "NULL", (unsigned long)dyn->d_val);
            break;
        }

        const char *tag_name = ew_dynamic_tag_name(dyn->d_tag);
        if (dyn->string_val) {
            report_append(report, "  %-14s 0x%016lx %s\n",
                          tag_name, (unsigned long)dyn->d_val,
                          dyn->string_val);
        } else {
            report_append(report, "  %-14s 0x%016lx\n",
                          tag_name, (unsigned long)dyn->d_val);
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Report creation and output                                          */
/* ------------------------------------------------------------------ */

ew_report_t *ew_report_create(ew_context_t *ctx, ew_report_type_t type)
{
    if (!ctx)
        return NULL;

    ew_report_t *report = calloc(1, sizeof(ew_report_t));
    if (!report)
        return NULL;

    report->type = type;

    switch (type) {
    case EW_REPORT_SUMMARY:
        generate_summary(report, ctx);
        break;
    case EW_REPORT_SECTIONS:
        generate_sections(report, ctx);
        break;
    case EW_REPORT_SEGMENTS:
        generate_segments(report, ctx);
        break;
    case EW_REPORT_SYMBOLS:
        generate_symbols(report, ctx);
        break;
    case EW_REPORT_DYNAMIC:
        generate_dynamic(report, ctx);
        break;
    case EW_REPORT_FULL:
        generate_summary(report, ctx);
        generate_sections(report, ctx);
        generate_segments(report, ctx);
        generate_symbols(report, ctx);
        generate_dynamic(report, ctx);
        break;
    default:
        break;
    }

    return report;
}

ew_error_t ew_report_write(ew_report_t *report, int fd)
{
    if (!report || !report->buffer)
        return EW_ERR_INVALID;

    size_t written = 0;
    while (written < report->length) {
        ssize_t n = write(fd, report->buffer + written,
                          report->length - written);
        if (n < 0)
            return EW_ERR_INTERNAL;
        written += (size_t)n;
    }

    return EW_OK;
}

const char *ew_report_get_text(ew_report_t *report)
{
    if (!report)
        return NULL;
    return report->buffer;
}

void ew_report_destroy(ew_report_t *report)
{
    if (!report)
        return;
    free(report->buffer);
    free(report);
}
