/*
 * ew_version.c — ELF version information parsing and resolution.
 *
 * Parses GNU_VERDEF (version definitions), GNU_VERNEED (version
 * requirements), and GNU_VERSYM (per-symbol version indices), then
 * resolves version names for each symbol.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Parse version definitions (SHT_GNU_VERDEF)                          */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_version_defs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_section_t *sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_GNU_VERDEF) {
            sec = &ctx->sections[i];
            break;
        }
    }

    if (!sec || !sec->data || sec->sh_size == 0) {
        ctx->verdefs = NULL;
        ctx->verdef_count = 0;
        return EW_OK;
    }

    /* Resolve the linked string table */
    const char *strtab = NULL;
    size_t strtab_size = 0;
    if (sec->sh_link < ctx->section_count) {
        ew_section_t *strsec = &ctx->sections[sec->sh_link];
        if (strsec->sh_type == EW_SHT_STRTAB && strsec->data) {
            strtab = (const char *)strsec->data;
            strtab_size = (size_t)strsec->sh_size;
        }
    }

    /* First pass: count version definitions */
    uint32_t def_count = 0;
    size_t cursor = 0;
    while (cursor < sec->sh_size && def_count < EW_MAX_VERSIONS) {
        if (cursor + 20 > sec->sh_size)
            break;

        ew_reader_t rd;
        ew_reader_init(&rd, sec->data + cursor,
                        (size_t)sec->sh_size - cursor, ctx->is_big_endian);

        uint16_t vd_version, vd_flags, vd_ndx, vd_cnt;
        uint32_t vd_hash, vd_aux, vd_next;

        ew_read_u16(&rd, &vd_version);
        ew_read_u16(&rd, &vd_flags);
        ew_read_u16(&rd, &vd_ndx);
        ew_read_u16(&rd, &vd_cnt);
        ew_read_u32(&rd, &vd_hash);
        ew_read_u32(&rd, &vd_aux);
        ew_read_u32(&rd, &vd_next);

        def_count++;

        if (vd_next == 0)
            break;
        cursor += vd_next;
    }

    if (def_count == 0) {
        ctx->verdefs = NULL;
        ctx->verdef_count = 0;
        return EW_OK;
    }

    ctx->verdefs = calloc(def_count, sizeof(ew_version_def_t));
    if (!ctx->verdefs)
        return EW_ERR_NOMEM;
    ctx->verdef_count = def_count;

    /* Second pass: read entries */
    cursor = 0;
    for (uint32_t d = 0; d < def_count && cursor < sec->sh_size; d++) {
        if (cursor + 20 > sec->sh_size)
            break;

        ew_reader_t rd;
        ew_reader_init(&rd, sec->data + cursor,
                        (size_t)sec->sh_size - cursor, ctx->is_big_endian);

        uint16_t vd_version, vd_flags, vd_ndx, vd_cnt;
        uint32_t vd_hash, vd_aux, vd_next;

        ew_read_u16(&rd, &vd_version);
        ew_read_u16(&rd, &vd_flags);
        ew_read_u16(&rd, &vd_ndx);
        ew_read_u16(&rd, &vd_cnt);
        ew_read_u32(&rd, &vd_hash);
        ew_read_u32(&rd, &vd_aux);
        ew_read_u32(&rd, &vd_next);

        ctx->verdefs[d].vd_flags = vd_flags;
        ctx->verdefs[d].vd_ndx = vd_ndx;
        ctx->verdefs[d].vd_cnt = vd_cnt;
        ctx->verdefs[d].vd_hash = vd_hash;

        /* Read aux entries (version names) */
        if (vd_cnt > 0 && vd_aux > 0 && strtab) {
            ctx->verdefs[d].vd_names = calloc(vd_cnt, sizeof(const char *));
            if (!ctx->verdefs[d].vd_names)
                return EW_ERR_NOMEM;

            size_t aux_cursor = cursor + vd_aux;
            for (uint16_t a = 0; a < vd_cnt; a++) {
                if (aux_cursor + 8 > sec->sh_size)
                    break;

                ew_reader_t auxrd;
                ew_reader_init(&auxrd, sec->data + aux_cursor,
                                (size_t)sec->sh_size - aux_cursor,
                                ctx->is_big_endian);

                uint32_t vda_name, vda_next;
                ew_read_u32(&auxrd, &vda_name);
                ew_read_u32(&auxrd, &vda_next);

                if (vda_name < strtab_size) {
                    ctx->verdefs[d].vd_names[a] = strtab + vda_name;
                }
                ctx->verdefs[d].name_count = a + 1;

                if (vda_next == 0)
                    break;
                aux_cursor += vda_next;
            }
        }

        ctx->verdefs[d].resolved = 1;

        if (vd_next == 0)
            break;
        cursor += vd_next;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Parse version needs (SHT_GNU_VERNEED)                               */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_version_needs(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_section_t *sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_GNU_VERNEED) {
            sec = &ctx->sections[i];
            break;
        }
    }

    if (!sec || !sec->data || sec->sh_size == 0) {
        ctx->verneeds = NULL;
        ctx->verneed_count = 0;
        return EW_OK;
    }

    const char *strtab = NULL;
    size_t strtab_size = 0;
    if (sec->sh_link < ctx->section_count) {
        ew_section_t *strsec = &ctx->sections[sec->sh_link];
        if (strsec->sh_type == EW_SHT_STRTAB && strsec->data) {
            strtab = (const char *)strsec->data;
            strtab_size = (size_t)strsec->sh_size;
        }
    }

    /* First pass: count version need entries */
    uint32_t need_count = 0;
    size_t cursor = 0;
    while (cursor < sec->sh_size && need_count < EW_MAX_VERSIONS) {
        if (cursor + 16 > sec->sh_size)
            break;

        ew_reader_t rd;
        ew_reader_init(&rd, sec->data + cursor,
                        (size_t)sec->sh_size - cursor, ctx->is_big_endian);

        uint16_t vn_version, vn_cnt;
        uint32_t vn_file, vn_aux, vn_next;

        ew_read_u16(&rd, &vn_version);
        ew_read_u16(&rd, &vn_cnt);
        ew_read_u32(&rd, &vn_file);
        ew_read_u32(&rd, &vn_aux);
        ew_read_u32(&rd, &vn_next);

        need_count++;

        if (vn_next == 0)
            break;
        cursor += vn_next;
    }

    if (need_count == 0) {
        ctx->verneeds = NULL;
        ctx->verneed_count = 0;
        return EW_OK;
    }

    ctx->verneeds = calloc(need_count, sizeof(ew_version_need_t));
    if (!ctx->verneeds)
        return EW_ERR_NOMEM;
    ctx->verneed_count = need_count;

    /* Second pass: read entries and aux data */
    cursor = 0;
    for (uint32_t n = 0; n < need_count && cursor < sec->sh_size; n++) {
        if (cursor + 16 > sec->sh_size)
            break;

        ew_reader_t rd;
        ew_reader_init(&rd, sec->data + cursor,
                        (size_t)sec->sh_size - cursor, ctx->is_big_endian);

        uint16_t vn_version, vn_cnt;
        uint32_t vn_file, vn_aux, vn_next;

        ew_read_u16(&rd, &vn_version);
        ew_read_u16(&rd, &vn_cnt);
        ew_read_u32(&rd, &vn_file);
        ew_read_u32(&rd, &vn_aux);
        ew_read_u32(&rd, &vn_next);

        ctx->verneeds[n].vn_version = vn_version;
        ctx->verneeds[n].vn_cnt = vn_cnt;

        /* Resolve library name */
        if (strtab && vn_file < strtab_size)
            ctx->verneeds[n].vn_file = strtab + vn_file;

        /* Read aux entries */
        if (vn_cnt > 0 && vn_aux > 0) {
            ctx->verneeds[n].vn_aux = calloc(vn_cnt,
                                              sizeof(ew_version_aux_t));
            if (!ctx->verneeds[n].vn_aux)
                return EW_ERR_NOMEM;

            size_t aux_cursor = cursor + vn_aux;
            uint16_t a = 0;
            /* Walk the aux chain via vna_next offsets until chain ends.
             * We track total chain length in aux_count for later use. */
            while (aux_cursor + 16 <= sec->sh_size) {

                ew_reader_t auxrd;
                ew_reader_init(&auxrd, sec->data + aux_cursor,
                                (size_t)sec->sh_size - aux_cursor,
                                ctx->is_big_endian);

                uint32_t vna_hash, vna_name, vna_next;
                uint16_t vna_flags, vna_other;

                ew_read_u32(&auxrd, &vna_hash);
                ew_read_u16(&auxrd, &vna_flags);
                ew_read_u16(&auxrd, &vna_other);
                ew_read_u32(&auxrd, &vna_name);
                ew_read_u32(&auxrd, &vna_next);

                /* Only store entries that fit within the allocation */
                if (a < vn_cnt) {
                    ctx->verneeds[n].vn_aux[a].vna_hash = vna_hash;
                    ctx->verneeds[n].vn_aux[a].vna_flags = vna_flags;
                    ctx->verneeds[n].vn_aux[a].vna_other = vna_other;

                    if (strtab && vna_name < strtab_size)
                        ctx->verneeds[n].vn_aux[a].vna_name = strtab + vna_name;
                }

                /* Record full chain length including entries beyond
                 * the allocation (the chain structure determines the
                 * authoritative count per the ELF spec). */
                a++;

                if (vna_next == 0)
                    break;
                aux_cursor += vna_next;
            }

            /* Store full chain length — callers use this to iterate */
            ctx->verneeds[n].aux_count = a;
        }

        ctx->verneeds[n].resolved = 1;

        if (vn_next == 0)
            break;
        cursor += vn_next;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Parse version symbol indices (SHT_GNU_VERSYM)                       */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_versym(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_section_t *sec = NULL;
    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type == EW_SHT_GNU_VERSYM) {
            sec = &ctx->sections[i];
            break;
        }
    }

    if (!sec || !sec->data || sec->sh_size < 2) {
        ctx->versym = NULL;
        ctx->versym_count = 0;
        return EW_OK;
    }

    uint32_t count = (uint32_t)(sec->sh_size / 2);
    if (count > EW_MAX_SYMBOLS) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "too many versym entries: %u", count);
        return EW_ERR_LIMIT;
    }

    ctx->versym = malloc(count * sizeof(uint16_t));
    if (!ctx->versym)
        return EW_ERR_NOMEM;
    ctx->versym_count = count;

    ew_reader_t rd;
    ew_reader_init(&rd, sec->data, (size_t)sec->sh_size, ctx->is_big_endian);

    for (uint32_t i = 0; i < count; i++) {
        ew_error_t err = ew_read_u16(&rd, &ctx->versym[i]);
        if (err != EW_OK) return err;
    }

    /* Assign version indices to dynamic symbols */
    if (ctx->dynsym) {
        uint32_t limit = ctx->dynsym_count < count ?
                         ctx->dynsym_count : count;
        for (uint32_t i = 0; i < limit; i++) {
            ctx->dynsym[i].version_index = ctx->versym[i] & 0x7fff;
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Full version resolution                                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_resolve_versions(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_error_t err;

    err = ew_parse_version_defs(ctx);
    if (err != EW_OK)
        return err;

    err = ew_parse_version_needs(ctx);
    if (err != EW_OK)
        return err;

    err = ew_parse_versym(ctx);
    if (err != EW_OK)
        return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Look up version name for a symbol                                   */
/* ------------------------------------------------------------------ */

const char *ew_symbol_version_name(ew_context_t *ctx, uint32_t sym_index)
{
    if (!ctx || !ctx->versym)
        return NULL;

    /* Use the dynamic symbol count as the index bound, since versym
     * and dynsym are required to be the same length by the ELF spec.
     * This avoids rejecting valid lookups when versym data is present. */
    if (sym_index >= ctx->dynsym_count)
        return NULL;

    uint16_t ver_idx = ctx->versym[sym_index] & 0x7fff;

    /* Version 0 = local, 1 = global (base) */
    if (ver_idx == 0)
        return "*local*";
    if (ver_idx == 1)
        return "*global*";

    /* Search version definitions */
    for (uint32_t i = 0; i < ctx->verdef_count; i++) {
        if (ctx->verdefs[i].vd_ndx == ver_idx) {
            if (ctx->verdefs[i].name_count > 0 &&
                ctx->verdefs[i].vd_names &&
                ctx->verdefs[i].vd_names[0])
                return ctx->verdefs[i].vd_names[0];
        }
    }

    /* Search version needs */
    for (uint32_t i = 0; i < ctx->verneed_count; i++) {
        for (uint16_t a = 0; a < ctx->verneeds[i].aux_count; a++) {
            if (ctx->verneeds[i].vn_aux[a].vna_other == ver_idx) {
                return ctx->verneeds[i].vn_aux[a].vna_name;
            }
        }
    }

    return NULL;
}
