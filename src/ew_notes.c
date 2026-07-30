/*
 * ew_notes.c — Note section parsing.
 *
 * Parses SHT_NOTE sections containing variable-length note entries.
 * Each note has a name (owner), a descriptor (payload), and a type.
 * Handles alignment differences between 32-bit and 64-bit notes.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Alignment helpers                                                   */
/* ------------------------------------------------------------------ */

static size_t note_align(size_t val, size_t alignment)
{
    if (alignment <= 1)
        return val;
    return (val + alignment - 1) & ~(alignment - 1);
}

/* ------------------------------------------------------------------ */
/* Parse notes from a single section                                   */
/* ------------------------------------------------------------------ */

static ew_error_t parse_note_section(ew_context_t *ctx, ew_section_t *sec,
                                      ew_note_t **notes, uint32_t *count,
                                      uint32_t *capacity)
{
    if (!sec->data || sec->sh_size == 0)
        return EW_OK;

    /* Notes use 4-byte alignment by convention (even in 64-bit ELFs) */
    size_t align = 4;
    if (sec->sh_addralign == 8)
        align = 8;

    ew_reader_t rd;
    ew_reader_init(&rd, sec->data, (size_t)sec->sh_size, ctx->is_big_endian);

    while (ew_reader_remaining(&rd) >= 12) {
        size_t note_start = ew_reader_tell(&rd);

        uint32_t namesz, descsz, type;
        ew_error_t err;

        err = ew_read_u32(&rd, &namesz);
        if (err != EW_OK) break;

        err = ew_read_u32(&rd, &descsz);
        if (err != EW_OK) break;

        err = ew_read_u32(&rd, &type);
        if (err != EW_OK) break;

        /* Validate sizes to prevent integer overflow */
        if (namesz > sec->sh_size || descsz > sec->sh_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "note entry has excessive namesz=%u or descsz=%u",
                     namesz, descsz);
            break;
        }

        size_t aligned_namesz = note_align(namesz, align);
        size_t aligned_descsz = note_align(descsz, align);

        /* Check that name and desc fit within remaining section data */
        size_t needed = aligned_namesz + aligned_descsz;
        if (needed > ew_reader_remaining(&rd))
            break;

        /* Read the note name */
        const char *name = NULL;
        if (namesz > 0) {
            const uint8_t *name_ptr = ew_reader_ptr_at(
                &rd, ew_reader_tell(&rd), namesz);
            if (name_ptr) {
                /* Verify null termination */
                if (namesz > 0 && name_ptr[namesz - 1] == '\0')
                    name = (const char *)name_ptr;
            }
        }
        ew_reader_seek(&rd, ew_reader_tell(&rd) + aligned_namesz);

        /* Read the note descriptor */
        const uint8_t *desc = NULL;
        if (descsz > 0) {
            desc = ew_reader_ptr_at(&rd, ew_reader_tell(&rd), descsz);
        }
        ew_reader_seek(&rd, ew_reader_tell(&rd) + aligned_descsz);

        /* Store the note */
        if (*count >= EW_MAX_NOTES)
            break;

        if (*count >= *capacity) {
            uint32_t new_cap = *capacity == 0 ? 16 : *capacity * 2;
            if (new_cap > EW_MAX_NOTES)
                new_cap = EW_MAX_NOTES;
            ew_note_t *tmp = realloc(*notes, new_cap * sizeof(ew_note_t));
            if (!tmp)
                return EW_ERR_NOMEM;
            *notes = tmp;
            *capacity = new_cap;
        }

        ew_note_t *note = &(*notes)[*count];
        note->namesz = namesz;
        note->descsz = descsz;
        note->type = type;
        note->name = name;
        note->desc = desc;
        note->section_index = sec->index;
        note->processed = 0;
        (*count)++;

        /* Safety: prevent infinite loops if alignment lands on same spot */
        if (ew_reader_tell(&rd) <= note_start)
            break;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Process GNU ABI tag note                                            */
/* ------------------------------------------------------------------ */

static void process_abi_tag(ew_note_t *note)
{
    if (!note->desc || note->descsz < 16)
        return;

    /* ABI tag format: 4 uint32_t values
     * [0] = OS (0=Linux, 1=Hurd, 2=Solaris)
     * [1] = major version
     * [2] = minor version
     * [3] = subminor version
     */
    note->processed = 1;
}

/* ------------------------------------------------------------------ */
/* Process GNU build-id note                                           */
/* ------------------------------------------------------------------ */

static void process_build_id(ew_note_t *note)
{
    if (!note->desc || note->descsz == 0)
        return;

    /* Build ID is typically 20 bytes (SHA-1) or 16 bytes (MD5/UUID) */
    note->processed = 1;
}

/* ------------------------------------------------------------------ */
/* Process GNU property note                                           */
/* ------------------------------------------------------------------ */

static void process_gnu_property(ew_context_t *ctx, ew_note_t *note)
{
    if (!note->desc || note->descsz < 8)
        return;

    /* GNU property entries are TLV format:
     * uint32_t pr_type
     * uint32_t pr_datasz
     * uint8_t  pr_data[pr_datasz]
     * uint8_t  pr_padding[] (to alignment)
     */
    ew_reader_t rd;
    ew_reader_init(&rd, note->desc, note->descsz, ctx->is_big_endian);

    while (ew_reader_remaining(&rd) >= 8) {
        uint32_t pr_type, pr_datasz;
        ew_error_t err;

        err = ew_read_u32(&rd, &pr_type);
        if (err != EW_OK) break;

        err = ew_read_u32(&rd, &pr_datasz);
        if (err != EW_OK) break;

        size_t aligned_datasz = note_align(pr_datasz,
                                           ctx->is_64bit ? 8 : 4);
        if (aligned_datasz > ew_reader_remaining(&rd))
            break;

        /* Skip the property data for now; just record it was seen */
        ew_read_skip(&rd, aligned_datasz);
    }

    note->processed = 1;
}

/* ------------------------------------------------------------------ */
/* Post-parse processing of known note types                           */
/* ------------------------------------------------------------------ */

static void process_notes(ew_context_t *ctx)
{
    for (uint32_t i = 0; i < ctx->note_count; i++) {
        ew_note_t *note = &ctx->notes[i];

        if (!note->name)
            continue;

        /* Check for GNU notes */
        if (strcmp(note->name, "GNU") == 0) {
            switch (note->type) {
            case EW_NT_GNU_ABI_TAG:
                process_abi_tag(note);
                break;
            case EW_NT_GNU_BUILD_ID:
                process_build_id(note);
                break;
            case EW_NT_GNU_PROPERTY_TYPE_0:
                process_gnu_property(ctx, note);
                break;
            default:
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public entry point: parse all note sections                         */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_notes(ew_context_t *ctx)
{
    if (!ctx)
        return EW_ERR_INVALID;

    ew_note_t *notes = NULL;
    uint32_t count = 0;
    uint32_t capacity = 0;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].sh_type != EW_SHT_NOTE)
            continue;

        ew_error_t err = parse_note_section(ctx, &ctx->sections[i],
                                             &notes, &count, &capacity);
        if (err != EW_OK) {
            free(notes);
            ctx->last_error = err;
            return err;
        }
    }

    /* Also check PT_NOTE segments for notes not in section headers */
    for (uint32_t i = 0; i < ctx->segment_count; i++) {
        ew_segment_t *seg = &ctx->segments[i];
        if (seg->p_type != EW_PT_NOTE || seg->p_filesz == 0)
            continue;

        /* Create a temporary section descriptor for the segment's data */
        ew_section_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.sh_type = EW_SHT_NOTE;
        tmp.sh_offset = seg->p_offset;
        tmp.sh_size = seg->p_filesz;
        tmp.sh_addralign = seg->p_align > 0 ? seg->p_align : 4;
        tmp.data = seg->data;
        tmp.index = 0xffffu;  /* sentinel */

        /* Only parse if this data isn't already covered by a section */
        int already_covered = 0;
        for (uint32_t j = 0; j < ctx->section_count; j++) {
            if (ctx->sections[j].sh_type == EW_SHT_NOTE &&
                ctx->sections[j].sh_offset == seg->p_offset &&
                ctx->sections[j].sh_size == seg->p_filesz) {
                already_covered = 1;
                break;
            }
        }

        if (!already_covered) {
            ew_error_t err = parse_note_section(ctx, &tmp,
                                                 &notes, &count, &capacity);
            if (err != EW_OK) {
                free(notes);
                ctx->last_error = err;
                return err;
            }
        }
    }

    ctx->notes = notes;
    ctx->note_count = count;

    /* Post-process known note types */
    process_notes(ctx);

    return EW_OK;
}
