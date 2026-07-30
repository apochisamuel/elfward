/*
 * ew_segment.c — Program header table parsing.
 *
 * Reads program headers (segments), validates their bounds, loads
 * data pointers, and detects shared backing between segments that
 * overlap in file layout.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* ELF32 program header parsing                                        */
/* ------------------------------------------------------------------ */

static ew_error_t parse_segment32(ew_reader_t *rd, ew_segment_t *seg)
{
    ew_error_t err;
    uint32_t val32;

    err = ew_read_u32(rd, &seg->p_type);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_offset = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_vaddr = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_paddr = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_filesz = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_memsz = val32;

    err = ew_read_u32(rd, &seg->p_flags);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    seg->p_align = val32;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* ELF64 program header parsing                                        */
/* ------------------------------------------------------------------ */

static ew_error_t parse_segment64(ew_reader_t *rd, ew_segment_t *seg)
{
    ew_error_t err;

    err = ew_read_u32(rd, &seg->p_type);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &seg->p_flags);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_offset);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_vaddr);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_paddr);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_filesz);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_memsz);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &seg->p_align);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Segment validation                                                  */
/* ------------------------------------------------------------------ */

static ew_error_t validate_segment(ew_context_t *ctx, ew_segment_t *seg,
                                    uint32_t idx)
{
    /* NULL segments have no file content */
    if (seg->p_type == EW_PT_NULL)
        return EW_OK;

    /* Check file size bounds */
    if (seg->p_filesz > 0) {
        if (seg->p_offset > ctx->data_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "segment %u offset %lu beyond file end",
                     idx, (unsigned long)seg->p_offset);
            return EW_ERR_TRUNCATED;
        }

        uint64_t end = seg->p_offset + seg->p_filesz;
        if (end < seg->p_offset) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "segment %u offset+filesz overflows", idx);
            return EW_ERR_OVERFLOW;
        }

        if (end > ctx->data_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "segment %u extends past file end", idx);
            return EW_ERR_TRUNCATED;
        }
    }

    /* Memory size must be at least file size */
    if (seg->p_memsz < seg->p_filesz) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "segment %u memsz < filesz", idx);
        return EW_ERR_BAD_SEGMENT;
    }

    /* Check alignment is power of two (or zero) */
    if (seg->p_align > 1) {
        if ((seg->p_align & (seg->p_align - 1)) != 0) {
            /* Non-power-of-two alignment; warn but don't fail */
        }
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Shared backing detection                                            */
/* ------------------------------------------------------------------ */

static int ranges_overlap(uint64_t a_off, uint64_t a_sz,
                           uint64_t b_off, uint64_t b_sz)
{
    if (a_sz == 0 || b_sz == 0)
        return 0;
    uint64_t a_end = a_off + a_sz;
    uint64_t b_end = b_off + b_sz;
    return a_off < b_end && b_off < a_end;
}

static void detect_shared_backing(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg_i = &ctx->segments[i];
        seg_i->backing_shared = 0;
        seg_i->shared_with = i;

        if (seg_i->p_type == EW_PT_NULL || seg_i->p_filesz == 0)
            continue;

        for (uint32_t j = 0; j < i; j++) {
            ew_segment_t *seg_j = &ctx->segments[j];
            if (seg_j->p_type == EW_PT_NULL || seg_j->p_filesz == 0)
                continue;

            if (ranges_overlap(seg_i->p_offset, seg_i->p_filesz,
                               seg_j->p_offset, seg_j->p_filesz)) {
                seg_i->backing_shared = 1;
                seg_i->shared_with = j;
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Load segment data pointers                                          */
/* ------------------------------------------------------------------ */

static void load_segment_data(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg = &ctx->segments[i];

        if (seg->p_type == EW_PT_NULL || seg->p_filesz == 0) {
            seg->data = NULL;
            seg->loaded = (seg->p_type == EW_PT_NULL);
            continue;
        }

        if (seg->p_offset + seg->p_filesz <= ctx->data_size) {
            seg->data = ctx->data + seg->p_offset;
            seg->loaded = 1;
        } else {
            seg->data = NULL;
            seg->loaded = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Section-to-segment mapping                                          */
/* ------------------------------------------------------------------ */

static int section_in_segment(ew_section_t *sec, ew_segment_t *seg)
{
    if (sec->sh_type == EW_SHT_NULL)
        return 0;
    if (seg->p_type == EW_PT_NULL)
        return 0;

    /* NOBITS sections are in segment if virtual addresses overlap */
    if (sec->sh_type == EW_SHT_NOBITS) {
        if (!(sec->sh_flags & EW_SHF_ALLOC))
            return 0;
        return sec->sh_addr >= seg->p_vaddr &&
               sec->sh_addr + sec->sh_size <= seg->p_vaddr + seg->p_memsz;
    }

    /* Regular sections: check both file and virtual address ranges */
    if (!(sec->sh_flags & EW_SHF_ALLOC))
        return 0;

    /* Compute end offsets for containment test. The addition of offset
     * and size can overflow for sections with extreme values, but this
     * is handled by the upper bound checks in validation. */
    uint64_t sec_file_end = sec->sh_offset + sec->sh_size;
    uint64_t seg_file_end = seg->p_offset + seg->p_filesz;
    uint64_t sec_addr_end = sec->sh_addr + sec->sh_size;
    uint64_t seg_addr_end = seg->p_vaddr + seg->p_memsz;

    int file_match = (sec->sh_offset >= seg->p_offset &&
                      sec_file_end <= seg_file_end);
    int addr_match = (sec->sh_addr >= seg->p_vaddr &&
                      sec_addr_end <= seg_addr_end);

    return file_match && addr_match;
}

/* ------------------------------------------------------------------ */
/* Public segment parsing entry point                                  */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_segments(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    ew_elf_header_t *h = &ctx->header;

    if (h->e_phnum == 0 || h->e_phoff == 0) {
        ctx->segments = NULL;
        ctx->segment_count = 0;
        return EW_OK;
    }

    ctx->segments = calloc(h->e_phnum, sizeof(ew_segment_t));
    if (!ctx->segments) {
        ctx->last_error = EW_ERR_NOMEM;
        return EW_ERR_NOMEM;
    }
    ctx->segment_count = h->e_phnum;

    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    for (uint32_t i = 0; i < h->e_phnum; i++) {
        size_t offset = (size_t)h->e_phoff + (size_t)i * h->e_phentsize;
        ew_error_t err = ew_reader_seek(&rd, offset);
        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "cannot seek to program header %u", i);
            ctx->last_error = err;
            return err;
        }

        ew_segment_t *seg = &ctx->segments[i];
        seg->index = i;

        if (ctx->is_64bit)
            err = parse_segment64(&rd, seg);
        else
            err = parse_segment32(&rd, seg);

        if (err != EW_OK) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "failed to parse program header %u", i);
            ctx->last_error = err;
            return err;
        }

        err = validate_segment(ctx, seg, i);
        if (err != EW_OK) {
            ctx->last_error = err;
            return err;
        }
    }

    load_segment_data(ctx);
    detect_shared_backing(ctx);

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Segment lookup functions                                            */
/* ------------------------------------------------------------------ */

ew_segment_t *ew_find_segment_by_type(ew_context_t *ctx, uint32_t type)
{
    if (!ctx || !ctx->segments)
        return NULL;

    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        if (ctx->segments[i].p_type == type)
            return &ctx->segments[i];
    }
    return NULL;
}

ew_segment_t *ew_find_segment_by_addr(ew_context_t *ctx, uint64_t addr)
{
    if (!ctx || !ctx->segments)
        return NULL;

    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg = &ctx->segments[i];
        if (seg->p_type != EW_PT_NULL &&
            addr >= seg->p_vaddr &&
            addr < seg->p_vaddr + seg->p_memsz)
            return seg;
    }
    return NULL;
}

uint32_t ew_segment_count(ew_context_t *ctx)
{
    return ctx ? ctx->segment_count : 0;
}

/* ------------------------------------------------------------------ */
/* Exported utility for section-segment membership                     */
/* ------------------------------------------------------------------ */

int ew_section_in_segment(ew_section_t *sec, ew_segment_t *seg)
{
    if (!sec || !seg)
        return 0;
    return section_in_segment(sec, seg);
}
