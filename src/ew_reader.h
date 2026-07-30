/*
 * ew_reader.h — Endian-aware binary reader for raw ELF data.
 *
 * Provides bounds-checked reading of multi-byte integers, strings,
 * and raw byte sequences with configurable byte order.
 */

#ifndef EW_READER_H
#define EW_READER_H

#include "elfward.h"

struct ew_reader {
    const uint8_t *base;
    size_t         size;
    size_t         pos;
    int            big_endian;
};

/* Lifecycle */
ew_error_t ew_reader_init(ew_reader_t *r, const uint8_t *data,
                           size_t size, int big_endian);
void       ew_reader_reset(ew_reader_t *r);
ew_error_t ew_reader_seek(ew_reader_t *r, size_t offset);
size_t     ew_reader_tell(ew_reader_t *r);
size_t     ew_reader_remaining(ew_reader_t *r);

/* Bounds checking */
int ew_reader_can_read(ew_reader_t *r, size_t nbytes);
int ew_reader_valid_range(ew_reader_t *r, size_t offset, size_t nbytes);

/* Integer reading (advances position) */
ew_error_t ew_read_u8(ew_reader_t *r, uint8_t *out);
ew_error_t ew_read_u16(ew_reader_t *r, uint16_t *out);
ew_error_t ew_read_u32(ew_reader_t *r, uint32_t *out);
ew_error_t ew_read_u64(ew_reader_t *r, uint64_t *out);
ew_error_t ew_read_i32(ew_reader_t *r, int32_t *out);
ew_error_t ew_read_i64(ew_reader_t *r, int64_t *out);

/* Reading at specific offset (does not advance position) */
ew_error_t ew_read_u8_at(ew_reader_t *r, size_t off, uint8_t *out);
ew_error_t ew_read_u16_at(ew_reader_t *r, size_t off, uint16_t *out);
ew_error_t ew_read_u32_at(ew_reader_t *r, size_t off, uint32_t *out);
ew_error_t ew_read_u64_at(ew_reader_t *r, size_t off, uint64_t *out);
ew_error_t ew_read_i32_at(ew_reader_t *r, size_t off, int32_t *out);
ew_error_t ew_read_i64_at(ew_reader_t *r, size_t off, int64_t *out);

/* Class-aware reading (32 or 64 bit) */
ew_error_t ew_read_addr(ew_reader_t *r, int is_64, uint64_t *out);
ew_error_t ew_read_off(ew_reader_t *r, int is_64, uint64_t *out);
ew_error_t ew_read_xword(ew_reader_t *r, int is_64, uint64_t *out);
ew_error_t ew_read_sxword(ew_reader_t *r, int is_64, int64_t *out);

ew_error_t ew_read_addr_at(ew_reader_t *r, size_t off, int is_64,
                            uint64_t *out);
ew_error_t ew_read_off_at(ew_reader_t *r, size_t off, int is_64,
                           uint64_t *out);

/* Raw data reading */
ew_error_t    ew_read_bytes(ew_reader_t *r, void *buf, size_t nbytes);
const uint8_t *ew_reader_ptr_at(ew_reader_t *r, size_t offset, size_t nbytes);
ew_error_t    ew_read_skip(ew_reader_t *r, size_t nbytes);

/* String reading */
const char *ew_read_string_at(ew_reader_t *r, size_t offset,
                               size_t strtab_size);
int         ew_validate_strtab(const uint8_t *data, size_t size);

/* Byte-order utilities */
uint16_t ew_bswap16(uint16_t v);
uint32_t ew_bswap32(uint32_t v);
uint64_t ew_bswap64(uint64_t v);

/* Hash utilities */
uint32_t ew_elf_hash(const char *name);
uint32_t ew_gnu_hash(const char *name);

#endif /* EW_READER_H */
