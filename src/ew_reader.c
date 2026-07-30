/*
 * ew_reader.c — Endian-aware binary reader implementation.
 *
 * All read operations are bounds-checked. Multi-byte integers are
 * converted from the ELF file's byte order to the host byte order.
 */

#include "ew_reader.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/* Byte-swap helpers                                                   */
/* ------------------------------------------------------------------ */

uint16_t ew_bswap16(uint16_t v)
{
    return (uint16_t)((v >> 8) | (v << 8));
}

uint32_t ew_bswap32(uint32_t v)
{
    return ((v & 0xff000000u) >> 24) |
           ((v & 0x00ff0000u) >>  8) |
           ((v & 0x0000ff00u) <<  8) |
           ((v & 0x000000ffu) << 24);
}

uint64_t ew_bswap64(uint64_t v)
{
    return ((v & 0xff00000000000000ULL) >> 56) |
           ((v & 0x00ff000000000000ULL) >> 40) |
           ((v & 0x0000ff0000000000ULL) >> 24) |
           ((v & 0x000000ff00000000ULL) >>  8) |
           ((v & 0x00000000ff000000ULL) <<  8) |
           ((v & 0x0000000000ff0000ULL) << 24) |
           ((v & 0x000000000000ff00ULL) << 40) |
           ((v & 0x00000000000000ffULL) << 56);
}

/* Detect host endianness at runtime */
static int host_is_big_endian(void)
{
    union { uint32_t i; uint8_t c[4]; } test = { .i = 1 };
    return test.c[0] == 0;
}

static int needs_swap(int file_big_endian)
{
    return file_big_endian != host_is_big_endian();
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

ew_error_t ew_reader_init(ew_reader_t *r, const uint8_t *data,
                           size_t size, int big_endian)
{
    if (!r || !data)
        return EW_ERR_INVALID;
    r->base       = data;
    r->size       = size;
    r->pos        = 0;
    r->big_endian = big_endian;
    return EW_OK;
}

void ew_reader_reset(ew_reader_t *r)
{
    if (r)
        r->pos = 0;
}

ew_error_t ew_reader_seek(ew_reader_t *r, size_t offset)
{
    if (!r)
        return EW_ERR_INVALID;
    if (offset > r->size)
        return EW_ERR_TRUNCATED;
    r->pos = offset;
    return EW_OK;
}

size_t ew_reader_tell(ew_reader_t *r)
{
    return r ? r->pos : 0;
}

size_t ew_reader_remaining(ew_reader_t *r)
{
    if (!r || r->pos >= r->size)
        return 0;
    return r->size - r->pos;
}

/* ------------------------------------------------------------------ */
/* Bounds checking                                                     */
/* ------------------------------------------------------------------ */

int ew_reader_can_read(ew_reader_t *r, size_t nbytes)
{
    if (!r || r->pos > r->size)
        return 0;
    return (r->size - r->pos) >= nbytes;
}

int ew_reader_valid_range(ew_reader_t *r, size_t offset, size_t nbytes)
{
    if (!r)
        return 0;
    if (offset > r->size)
        return 0;
    if (nbytes > r->size - offset)
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Sequential integer reads                                            */
/* ------------------------------------------------------------------ */

ew_error_t ew_read_u8(ew_reader_t *r, uint8_t *out)
{
    if (!ew_reader_can_read(r, 1))
        return EW_ERR_TRUNCATED;
    *out = r->base[r->pos];
    r->pos += 1;
    return EW_OK;
}

ew_error_t ew_read_u16(ew_reader_t *r, uint16_t *out)
{
    if (!ew_reader_can_read(r, 2))
        return EW_ERR_TRUNCATED;
    uint16_t val;
    memcpy(&val, r->base + r->pos, 2);
    if (needs_swap(r->big_endian))
        val = ew_bswap16(val);
    *out = val;
    r->pos += 2;
    return EW_OK;
}

ew_error_t ew_read_u32(ew_reader_t *r, uint32_t *out)
{
    if (!ew_reader_can_read(r, 4))
        return EW_ERR_TRUNCATED;
    uint32_t val;
    memcpy(&val, r->base + r->pos, 4);
    if (needs_swap(r->big_endian))
        val = ew_bswap32(val);
    *out = val;
    r->pos += 4;
    return EW_OK;
}

ew_error_t ew_read_u64(ew_reader_t *r, uint64_t *out)
{
    if (!ew_reader_can_read(r, 8))
        return EW_ERR_TRUNCATED;
    uint64_t val;
    memcpy(&val, r->base + r->pos, 8);
    if (needs_swap(r->big_endian))
        val = ew_bswap64(val);
    *out = val;
    r->pos += 8;
    return EW_OK;
}

ew_error_t ew_read_i32(ew_reader_t *r, int32_t *out)
{
    uint32_t raw;
    ew_error_t err = ew_read_u32(r, &raw);
    if (err != EW_OK)
        return err;
    memcpy(out, &raw, 4);
    return EW_OK;
}

ew_error_t ew_read_i64(ew_reader_t *r, int64_t *out)
{
    uint64_t raw;
    ew_error_t err = ew_read_u64(r, &raw);
    if (err != EW_OK)
        return err;
    memcpy(out, &raw, 8);
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Positional integer reads                                            */
/* ------------------------------------------------------------------ */

ew_error_t ew_read_u8_at(ew_reader_t *r, size_t off, uint8_t *out)
{
    if (!ew_reader_valid_range(r, off, 1))
        return EW_ERR_TRUNCATED;
    *out = r->base[off];
    return EW_OK;
}

ew_error_t ew_read_u16_at(ew_reader_t *r, size_t off, uint16_t *out)
{
    if (!ew_reader_valid_range(r, off, 2))
        return EW_ERR_TRUNCATED;
    uint16_t val;
    memcpy(&val, r->base + off, 2);
    if (needs_swap(r->big_endian))
        val = ew_bswap16(val);
    *out = val;
    return EW_OK;
}

ew_error_t ew_read_u32_at(ew_reader_t *r, size_t off, uint32_t *out)
{
    if (!ew_reader_valid_range(r, off, 4))
        return EW_ERR_TRUNCATED;
    uint32_t val;
    memcpy(&val, r->base + off, 4);
    if (needs_swap(r->big_endian))
        val = ew_bswap32(val);
    *out = val;
    return EW_OK;
}

ew_error_t ew_read_u64_at(ew_reader_t *r, size_t off, uint64_t *out)
{
    if (!ew_reader_valid_range(r, off, 8))
        return EW_ERR_TRUNCATED;
    uint64_t val;
    memcpy(&val, r->base + off, 8);
    if (needs_swap(r->big_endian))
        val = ew_bswap64(val);
    *out = val;
    return EW_OK;
}

ew_error_t ew_read_i32_at(ew_reader_t *r, size_t off, int32_t *out)
{
    uint32_t raw;
    ew_error_t err = ew_read_u32_at(r, off, &raw);
    if (err != EW_OK)
        return err;
    memcpy(out, &raw, 4);
    return EW_OK;
}

ew_error_t ew_read_i64_at(ew_reader_t *r, size_t off, int64_t *out)
{
    uint64_t raw;
    ew_error_t err = ew_read_u64_at(r, off, &raw);
    if (err != EW_OK)
        return err;
    memcpy(out, &raw, 8);
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Class-aware reads (32-bit or 64-bit)                                */
/* ------------------------------------------------------------------ */

ew_error_t ew_read_addr(ew_reader_t *r, int is_64, uint64_t *out)
{
    if (is_64)
        return ew_read_u64(r, out);
    uint32_t val32;
    ew_error_t err = ew_read_u32(r, &val32);
    if (err == EW_OK)
        *out = val32;
    return err;
}

ew_error_t ew_read_off(ew_reader_t *r, int is_64, uint64_t *out)
{
    return ew_read_addr(r, is_64, out);
}

ew_error_t ew_read_xword(ew_reader_t *r, int is_64, uint64_t *out)
{
    return ew_read_addr(r, is_64, out);
}

ew_error_t ew_read_sxword(ew_reader_t *r, int is_64, int64_t *out)
{
    if (is_64)
        return ew_read_i64(r, out);
    int32_t val32;
    ew_error_t err = ew_read_i32(r, &val32);
    if (err == EW_OK)
        *out = val32;
    return err;
}

ew_error_t ew_read_addr_at(ew_reader_t *r, size_t off, int is_64,
                            uint64_t *out)
{
    if (is_64)
        return ew_read_u64_at(r, off, out);
    uint32_t val32;
    ew_error_t err = ew_read_u32_at(r, off, &val32);
    if (err == EW_OK)
        *out = val32;
    return err;
}

ew_error_t ew_read_off_at(ew_reader_t *r, size_t off, int is_64,
                           uint64_t *out)
{
    return ew_read_addr_at(r, off, is_64, out);
}

/* ------------------------------------------------------------------ */
/* Raw data reading                                                    */
/* ------------------------------------------------------------------ */

ew_error_t ew_read_bytes(ew_reader_t *r, void *buf, size_t nbytes)
{
    if (!ew_reader_can_read(r, nbytes))
        return EW_ERR_TRUNCATED;
    memcpy(buf, r->base + r->pos, nbytes);
    r->pos += nbytes;
    return EW_OK;
}

const uint8_t *ew_reader_ptr_at(ew_reader_t *r, size_t offset, size_t nbytes)
{
    if (!ew_reader_valid_range(r, offset, nbytes))
        return NULL;
    return r->base + offset;
}

ew_error_t ew_read_skip(ew_reader_t *r, size_t nbytes)
{
    if (!ew_reader_can_read(r, nbytes))
        return EW_ERR_TRUNCATED;
    r->pos += nbytes;
    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* String reading                                                      */
/* ------------------------------------------------------------------ */

const char *ew_read_string_at(ew_reader_t *r, size_t offset,
                               size_t strtab_size)
{
    if (!r || offset >= strtab_size)
        return NULL;
    const char *base = (const char *)r->base;
    const char *s = base + offset;
    /* Verify null termination within the string table bounds */
    size_t max_len = strtab_size - offset;
    for (size_t i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return s;
    }
    return NULL;
}

int ew_validate_strtab(const uint8_t *data, size_t size)
{
    if (!data || size == 0)
        return 0;
    /* First byte should be null */
    if (data[0] != '\0')
        return 0;
    /* Last byte must be null */
    if (data[size - 1] != '\0')
        return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Hash functions                                                      */
/* ------------------------------------------------------------------ */

uint32_t ew_elf_hash(const char *name)
{
    uint32_t h = 0;
    uint32_t g;
    const uint8_t *s = (const uint8_t *)name;

    while (*s) {
        h = (h << 4) + *s++;
        g = h & 0xf0000000;
        if (g)
            h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

uint32_t ew_gnu_hash(const char *name)
{
    uint32_t h = 5381;
    const uint8_t *s = (const uint8_t *)name;

    while (*s)
        h = h * 33 + *s++;
    return h;
}
