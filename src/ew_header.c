/*
 * ew_header.c — ELF header parsing and validation.
 *
 * Reads the ELF identification bytes, determines class (32/64) and
 * encoding (LSB/MSB), then parses the full ELF header into the
 * unified representation used by subsequent parsing stages.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Magic validation                                                    */
/* ------------------------------------------------------------------ */

static ew_error_t validate_ident(const uint8_t *ident, ew_context_t *ctx)
{
    if (ident[0] != EW_ELFMAG0 || ident[1] != EW_ELFMAG1 ||
        ident[2] != EW_ELFMAG2 || ident[3] != EW_ELFMAG3) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "bad magic: %02x %02x %02x %02x",
                 ident[0], ident[1], ident[2], ident[3]);
        return EW_ERR_BAD_MAGIC;
    }

    uint8_t ei_class = ident[4];
    if (ei_class != EW_ELFCLASS32 && ei_class != EW_ELFCLASS64) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "unsupported ELF class: %u", ei_class);
        return EW_ERR_BAD_CLASS;
    }

    uint8_t ei_data = ident[5];
    if (ei_data != EW_ELFDATA2LSB && ei_data != EW_ELFDATA2MSB) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "unsupported data encoding: %u", ei_data);
        return EW_ERR_BAD_ENCODING;
    }

    uint8_t ei_version = ident[6];
    if (ei_version != EW_EV_CURRENT) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "unsupported ELF version: %u", ei_version);
        return EW_ERR_BAD_VERSION;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Header size calculations                                            */
/* ------------------------------------------------------------------ */

static size_t elf32_header_size(void) { return 52; }
static size_t elf64_header_size(void) { return 64; }

static size_t expected_header_size(int is_64)
{
    return is_64 ? elf64_header_size() : elf32_header_size();
}

/* ------------------------------------------------------------------ */
/* ELF32 header parsing                                                */
/* ------------------------------------------------------------------ */

static ew_error_t parse_elf32_header(ew_reader_t *rd, ew_elf_header_t *hdr)
{
    ew_error_t err;
    uint32_t val32;

    /* Skip past ident (already read) */
    err = ew_reader_seek(rd, EW_EI_NIDENT);
    if (err != EW_OK)
        return err;

    err = ew_read_u16(rd, &hdr->e_type);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_machine);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &hdr->e_version);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    hdr->e_entry = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    hdr->e_phoff = val32;

    err = ew_read_u32(rd, &val32);
    if (err != EW_OK) return err;
    hdr->e_shoff = val32;

    err = ew_read_u32(rd, &hdr->e_flags);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_ehsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_phentsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_phnum);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shentsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shnum);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shstrndx);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* ELF64 header parsing                                                */
/* ------------------------------------------------------------------ */

static ew_error_t parse_elf64_header(ew_reader_t *rd, ew_elf_header_t *hdr)
{
    ew_error_t err;

    err = ew_reader_seek(rd, EW_EI_NIDENT);
    if (err != EW_OK)
        return err;

    err = ew_read_u16(rd, &hdr->e_type);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_machine);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &hdr->e_version);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &hdr->e_entry);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &hdr->e_phoff);
    if (err != EW_OK) return err;

    err = ew_read_u64(rd, &hdr->e_shoff);
    if (err != EW_OK) return err;

    err = ew_read_u32(rd, &hdr->e_flags);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_ehsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_phentsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_phnum);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shentsize);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shnum);
    if (err != EW_OK) return err;

    err = ew_read_u16(rd, &hdr->e_shstrndx);
    if (err != EW_OK) return err;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Header validation                                                   */
/* ------------------------------------------------------------------ */

static ew_error_t validate_header(ew_context_t *ctx)
{
    ew_elf_header_t *h = &ctx->header;

    /* Validate header size consistency */
    size_t expected = expected_header_size(ctx->is_64bit);
    if (h->e_ehsize != 0 && h->e_ehsize < expected) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "header size %u too small (expected %zu)",
                 h->e_ehsize, expected);
        return EW_ERR_BAD_SECTION;
    }

    /* Validate section header entry size if sections exist */
    if (h->e_shnum > 0) {
        size_t expected_shent = ctx->is_64bit ? 64 : 40;
        if (h->e_shentsize < expected_shent) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "section header entry too small: %u (expected %zu)",
                     h->e_shentsize, expected_shent);
            return EW_ERR_BAD_SECTION;
        }

        if (h->e_shnum > EW_MAX_SECTIONS) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "too many sections: %u (max %u)",
                     h->e_shnum, EW_MAX_SECTIONS);
            return EW_ERR_LIMIT;
        }

        /* Check section table fits in file */
        uint64_t sh_end = h->e_shoff + (uint64_t)h->e_shnum * h->e_shentsize;
        if (sh_end > ctx->data_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "section table extends past end of file");
            return EW_ERR_TRUNCATED;
        }

        /* Validate shstrndx */
        if (h->e_shstrndx != EW_SHN_UNDEF &&
            h->e_shstrndx >= h->e_shnum &&
            h->e_shstrndx != EW_SHN_XINDEX) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "shstrndx %u out of range (shnum %u)",
                     h->e_shstrndx, h->e_shnum);
            return EW_ERR_BAD_SECTION;
        }
    }

    /* Validate program header entry size if segments exist */
    if (h->e_phnum > 0) {
        size_t expected_phent = ctx->is_64bit ? 56 : 32;
        if (h->e_phentsize < expected_phent) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "program header entry too small: %u (expected %zu)",
                     h->e_phentsize, expected_phent);
            return EW_ERR_BAD_SEGMENT;
        }

        if (h->e_phnum > EW_MAX_SEGMENTS) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "too many segments: %u (max %u)",
                     h->e_phnum, EW_MAX_SEGMENTS);
            return EW_ERR_LIMIT;
        }

        /* Check program header table fits in file */
        uint64_t ph_end = h->e_phoff + (uint64_t)h->e_phnum * h->e_phentsize;
        if (ph_end > ctx->data_size) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                     "program header table extends past end of file");
            return EW_ERR_TRUNCATED;
        }
    }

    /* Version check */
    if (h->e_version != EW_EV_CURRENT && h->e_version != 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "unsupported ELF version in header: %u", h->e_version);
        return EW_ERR_BAD_VERSION;
    }

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Public header parsing entry point                                   */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_header(ew_context_t *ctx)
{
    if (!ctx || !ctx->data)
        return EW_ERR_INVALID;

    if (ctx->data_size < EW_EI_NIDENT) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "file too small for ELF identification");
        ctx->last_error = EW_ERR_TRUNCATED;
        return EW_ERR_TRUNCATED;
    }

    /* Read and validate identification bytes */
    memcpy(ctx->header.e_ident, ctx->data, EW_EI_NIDENT);
    ew_error_t err = validate_ident(ctx->header.e_ident, ctx);
    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    /* Determine class and encoding */
    ctx->is_64bit     = (ctx->header.e_ident[4] == EW_ELFCLASS64);
    ctx->is_big_endian = (ctx->header.e_ident[5] == EW_ELFDATA2MSB);

    /* Verify minimum size for complete header */
    size_t min_hdr_size = expected_header_size(ctx->is_64bit);
    if (ctx->data_size < min_hdr_size) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "file too small for %s ELF header",
                 ctx->is_64bit ? "64-bit" : "32-bit");
        ctx->last_error = EW_ERR_TRUNCATED;
        return EW_ERR_TRUNCATED;
    }

    /* Set up reader with correct byte order */
    ew_reader_t rd;
    ew_reader_init(&rd, ctx->data, ctx->data_size, ctx->is_big_endian);

    /* Parse class-specific header */
    if (ctx->is_64bit)
        err = parse_elf64_header(&rd, &ctx->header);
    else
        err = parse_elf32_header(&rd, &ctx->header);

    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    /* Validate parsed header fields */
    err = validate_header(ctx);
    if (err != EW_OK) {
        ctx->last_error = err;
        return err;
    }

    return EW_OK;
}
