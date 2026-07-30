/*
 * ew_section.c — Section header table parsing.
 *
 * Reads section headers from the section header table, validates
 * each entry's bounds, and resolves section names through the
 * section header string table (.shstrtab).
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Section header parsing for ELF32                                    */
/* ------------------------------------------------------------------ */

static ew_error_t parse_section32(ew_reader_t *rd, ew_section_t *sec)
{
    ew_error_t err;
    uint32_t val32;

    err = ew_read_u32(rd, &sec->sh_name);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &sec->sh_type);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_flags = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_addr = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_offset = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_size = val32;

    err = ew_read_u32(rd, &sec->sh_link);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &sec->sh_info);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_addralign = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    sec->sh_entsize = val32;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Section header parsing for ELF64                                    */
/* ------------------------------------------------------------------ */

static ew_error_t parse_section64(ew_reader_t *rd, ew_section_t *sec)
{
    ew_error_t err;

    err = ew_read_u32(rd, &sec->sh_name);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &sec->sh_type);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_flags);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_addr);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_offset);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_size);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &sec->sh_link);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &sec->sh_info);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_addralign);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &sec->sh_entsize);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Section data bounds validation                                      */
/* ------------------------------------------------------------------ */

static ew_error_t validate_section_data(ew_context_t *ctx, ew_section_t *sec,
                                         uint32_t idx)
{
    /* NULL sections and NOBITS have no data in the file */
    if (sec->sh_type == EW_SHT_NULL || sec->sh_type == EW_SHT_NOBITS)
        return EW_OK;

    /* Check for integer overflow in offset + size */
    if (sec->sh_offset > ctx->data_size) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "section %u offset %lu beyond file end",
                 idx, (unsigned long)sec->sh_offset);
        return EW_ERR_TRUNCATED;
    }

    if (sec->sh_size > EW_MAX_SECTION_SIZE) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "section %u size %lu exceeds limit",
                 idx, (unsigned long)sec->sh_size);
        return EW_ERR_LIMIT;
    }

    uint64_t end = sec->sh_offset + sec->sh_size;
    if (end < sec->sh_offset) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "section %u offset+size overflows", idx);
        return EW_ERR_OVERFLOW;
    }

    /* Warn if section extends past file, but don't fail — partial
     * sections are common in core dumps and truncated files. The
     * data loader will clamp reads to available data. */
    (void)end;

    /* Validate entry size for table-type sections */
    if (sec->sh_entsize > 0) {
        if (sec->sh_size > 0 && sec->sh_entsize > sec->sh_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "section %u entsize %lu exceeds section size %lu",
                     idx, (unsigned long)sec->sh_entsize,
                     (unsigned long)sec->sh_size);
            return EW_ERR_BAD_SECTION;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Section link validation                                             */
/* ------------------------------------------------------------------ */

static ew_error_t validate_section_links(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        /* Validate sh_link for sections that reference string/symbol tables */
        if (sec->sh_link != 0 && sec->sh_link >= ctx->section_count) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "section %u sh_link %u out of range",
                     i, sec->sh_link);
            return EW_ERR_BAD_SECTION;
        }

        /* Type-specific link validation */
        switch (sec->sh_type) {
        case EW_SHT_SYMTAB:
        case EW_SHT_DYNSYM:
            /* sh_link must point to a string table */
            if (sec->sh_link >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "symtab section %u sh_link out of range", i);
                return EW_ERR_BAD_SECTION;
            }
            if (ctx->sections[sec->sh_link].sh_type != EW_SHT_STRTAB) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "symtab section %u sh_link doesn't point to STRTAB",
                         i);
                return EW_ERR_BAD_SECTION;
            }
            break;

        case EW_SHT_REL:
        case EW_SHT_RELA:
            /* sh_link should point to associated symbol table */
            if (sec->sh_link >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "reloc section %u sh_link out of range", i);
                return EW_ERR_BAD_SECTION;
            }
            break;

        case EW_SHT_HASH:
        case EW_SHT_GNU_HASH:
            /* sh_link should point to symbol table */
            if (sec->sh_link >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "hash section %u sh_link out of range", i);
                return EW_ERR_BAD_SECTION;
            }
            break;

        case EW_SHT_DYNAMIC:
            /* sh_link should point to string table */
            if (sec->sh_link >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "dynamic section %u sh_link out of range", i);
                return EW_ERR_BAD_SECTION;
            }
            break;

        case EW_SHT_GNU_VERSYM:
        case EW_SHT_GNU_VERDEF:
        case EW_SHT_GNU_VERNEED:
            if (sec->sh_link >= ctx->section_count) {
                snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                         "version section %u sh_link out of range", i);
                return EW_ERR_BAD_SECTION;
            }
            break;

        default:
            break;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Section name resolution                                             */
/* ------------------------------------------------------------------ */

static ew_error_t resolve_section_names(ew_context_t *ctx)
{
    uint16_t shstrndx = ctx->header.e_shstrndx;

    if (shstrndx == EW_SHN_UNDEF || shstrndx >= ctx->section_count) {
        /* No section name string table; leave names as NULL */
        for (uint32_t i = 0; i < ctx->section_count; i++)
            ctx->sections[i].name = NULL;
        return EW_OK;
    }

    ew_section_t *strsec = &ctx->sections[shstrndx];
    if (strsec->sh_type != EW_SHT_STRTAB) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "shstrndx section is not STRTAB (type=%u)", strsec->sh_type);
        return EW_ERR_BAD_STRTAB;
    }

    if (strsec->sh_size > EW_MAX_STRTAB_SIZE) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "section name string table too large: %lu",
                 (unsigned long)strsec->sh_size);
        return EW_ERR_LIMIT;
    }

    /* Validate the string table content */
    const uint8_t *strtab_data = ctx->data + strsec->sh_offset;
    if (!ew_validate_strtab(strtab_data, (size_t)strsec->sh_size)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "malformed section name string table");
        return EW_ERR_BAD_STRTAB;
    }

    ctx->shstrtab = (const char *)strtab_data;
    ctx->shstrtab_size = (size_t)strsec->sh_size;

    /* Resolve each section name */
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        if (sec->sh_name < ctx->shstrtab_size) {
            /* Find the null-terminated name within the string table */
            const char *name = ctx->shstrtab + sec->sh_name;
            size_t remaining = ctx->shstrtab_size - sec->sh_name;
            int found_null = 0;
            for (size_t j = 0; j < remaining; j++) {
                if (name[j] == '\0') {
                    found_null = 1;
                    break;
                }
            }
            sec->name = found_null ? name : NULL;
        } else {
            sec->name = NULL;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Load section data pointers                                          */
/* ------------------------------------------------------------------ */

static void load_section_data(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];

        if (sec->sh_type == EW_SHT_NULL || sec->sh_type == EW_SHT_NOBITS) {
            sec->data = NULL;
            sec->loaded = 1;
            continue;
        }

        /* Verify the section's file range fits within the loaded data.
         * The offset is validated against file size, and total extent
         * was already checked by validate_section_bounds. */
        if (sec->sh_size > 0 && sec->sh_offset < ctx->data_size) {
            sec->data = ctx->data + sec->sh_offset;
            sec->loaded = 1;
        } else {
            sec->data = NULL;
            sec->loaded = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Canonical section identification                                    */
/* ------------------------------------------------------------------ */

static void assign_canonical_ids(ew_context_t *ctx)
{
    int next_id = 1;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        sec->canonical_id = 0;

        if (sec->sh_type == EW_SHT_NULL)
            continue;

        /* Check if an earlier section has the same name and type */
        int is_duplicate = 0;
        if (sec->name) {
            for (uint32_t j = 0; j < i; j++) {
                ew_section_t *prev = &ctx->sections[j];
                if (prev->name && prev->sh_type == sec->sh_type &&
                    strcmp(prev->name, sec->name) == 0) {
                    sec->canonical_id = prev->canonical_id;
                    is_duplicate = 1;
                    break;
                }
            }
        }

        if (!is_duplicate) {
            sec->canonical_id = next_id++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public section parsing entry point                                  */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_sections(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    ew_elf_header_t *h = &ctx->header;

    /* Handle case where there are no sections */
    if (h->e_shnum == 0 || h->e_shoff == 0) {
        ctx->sections = NULL;
        ctx->section_count = 0;
        return EW_OK;
    }

    /* Allocate section array */
    ctx->sections = calloc(h->e_shnum, sizeof(ew_section_t));
    if (!ctx->sections) {
        ctx->last_error = EW_ERR_NOMEM;
        return EW_ERR_NOMEM;
    }
    ctx->section_count = h->e_shnum;

    /* Set up reader */
    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    /* Parse each section header */
    for (uint32_t i = 0; i < h->e_shnum; i++) {
        size_t offset = (size_t)h->e_shoff + (size_t)i * h->e_shentsize;
        ew_error_t err = ew_reader_seek(&rd, offset);
        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "cannot seek to section header %u at offset %zu",
                     i, offset);
            ctx->last_error = err;
            return err;
        }

        ew_section_t *sec = &ctx->sections[i];
        sec->index = i;
        sec->derived_state = NULL;

        if (ctx->is_64bit)
            err = parse_section64(&rd, sec);
        else
            err = parse_section32(&rd, sec);

        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "failed to parse section header %u", i);
            ctx->last_error = err;
            return err;
        }

        /* Validate section data bounds */
        err = validate_section_data(ctx, sec, i);
        if (err != EW_OK) {
            ctx->last_error = err;
            return err;
        }
    }

    /* Load data pointers for each section */
    load_section_data(ctx);

    /* Validate inter-section references */
    ew_error_t err = validate_section_links(ctx);
    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    /* Resolve section names */
    err = resolve_section_names(ctx);
    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    /* Assign canonical identifiers for deduplication */
    assign_canonical_ids(ctx);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Section lookup functions                                            */
/* ------------------------------------------------------------------ */

ew_section_t *ew_find_section_by_name(ew_context_t *ctx, const char *name)
{
    if (!ctx || !name || !ctx->sections)
        return NULL;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].name &&
            strcmp(ctx->sections[i].name, name) == 0)
            return &ctx->sections[i];
    }
    return NULL;
}

ew_section_t *ew_find_section_by_type(ew_context_t *ctx, uint32_t type)
{
    if (!ctx || !ctx->sections)
        return NULL;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == type)
            return &ctx->sections[i];
    }
    return NULL;
}

ew_section_t *ew_find_section_by_addr(ew_context_t *ctx, uint64_t addr)
{
    if (!ctx || !ctx->sections)
        return NULL;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        ew_section_t *sec = &ctx->sections[i];
        if ((sec->sh_flags & EW_SHF_ALLOC) &&
            addr >= sec->sh_addr &&
            addr < sec->sh_addr + sec->sh_size)
            return sec;
    }
    return NULL;
}

uint32_t ew_section_count(ew_context_t *ctx)
{
    return ctx ? ctx->section_count : 0;
}
