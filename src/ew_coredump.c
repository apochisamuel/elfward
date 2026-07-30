/*
 * ew_coredump.c — Core dump note parsing.
 *
 * Parses core dump-specific note types found in ELF core files:
 * NT_PRSTATUS (register state), NT_PRPSINFO (process info),
 * NT_AUXV (auxiliary vector), and NT_FILE (memory-mapped files).
 * Provides structured access to process state at crash time.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define EW_NT_PRSTATUS      1
#define EW_NT_PRPSINFO      3
#define EW_NT_AUXV          6
#define EW_NT_FILE          0x46494c45  /* "FILE" */
#define EW_NT_SIGINFO       0x53494749  /* "SIGI" */

typedef struct {
    int32_t  si_signo;
    int32_t  si_code;
    int32_t  si_errno;
    uint16_t pr_cursig;
    uint64_t pr_sigpend;
    uint64_t pr_sighold;
    int32_t  pr_pid;
    int32_t  pr_ppid;
    int32_t  pr_pgrp;
    int32_t  pr_sid;
    uint64_t pr_utime_sec;
    uint64_t pr_utime_usec;
    uint64_t pr_stime_sec;
    uint64_t pr_stime_usec;
    uint64_t pr_cutime_sec;
    uint64_t pr_cutime_usec;
    uint64_t pr_cstime_sec;
    uint64_t pr_cstime_usec;
    uint64_t regs[27];
    int      regs_valid;
    int      parsed;
} ew_prstatus_t;

typedef struct {
    char     pr_state;
    char     pr_sname;
    char     pr_zomb;
    char     pr_nice;
    uint64_t pr_flag;
    uint32_t pr_uid;
    uint32_t pr_gid;
    int32_t  pr_pid;
    int32_t  pr_ppid;
    int32_t  pr_pgrp;
    int32_t  pr_sid;
    char     pr_fname[16];
    char     pr_psargs[80];
    int      parsed;
} ew_prpsinfo_t;

typedef struct {
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t file_offset;
    const char *filename;
} ew_mapped_file_t;

typedef struct {
    uint64_t type;
    uint64_t value;
} ew_auxv_entry_t;

typedef struct {
    ew_prstatus_t  *prstatus;
    uint32_t        prstatus_count;
    ew_prpsinfo_t  *prpsinfo;
    int             has_prpsinfo;
    ew_auxv_entry_t *auxv;
    uint32_t        auxv_count;
    ew_mapped_file_t *mapped_files;
    uint32_t        mapped_file_count;
    int             is_core;
} ew_coredump_info_t;

static ew_error_t parse_prstatus_64(const uint8_t *desc, uint32_t descsz,
                                     int is_big_endian,
                                     ew_prstatus_t *out)
{
    if (descsz < 112)
        return EW_ERR_TRUNCATED;

    ew_reader_t rd;
    ew_reader_init(&rd, desc, descsz, is_big_endian);

    ew_read_i32(&rd, &out->si_signo);
    ew_read_i32(&rd, &out->si_code);
    ew_read_i32(&rd, &out->si_errno);

    ew_read_u16(&rd, &out->pr_cursig);
    ew_read_skip(&rd, 2);

    ew_read_u64(&rd, &out->pr_sigpend);
    ew_read_u64(&rd, &out->pr_sighold);

    ew_read_i32(&rd, &out->pr_pid);
    ew_read_i32(&rd, &out->pr_ppid);
    ew_read_i32(&rd, &out->pr_pgrp);
    ew_read_i32(&rd, &out->pr_sid);

    ew_read_u64(&rd, &out->pr_utime_sec);
    ew_read_u64(&rd, &out->pr_utime_usec);
    ew_read_u64(&rd, &out->pr_stime_sec);
    ew_read_u64(&rd, &out->pr_stime_usec);
    ew_read_u64(&rd, &out->pr_cutime_sec);
    ew_read_u64(&rd, &out->pr_cutime_usec);
    ew_read_u64(&rd, &out->pr_cstime_sec);
    ew_read_u64(&rd, &out->pr_cstime_usec);

    size_t remaining = ew_reader_remaining(&rd);
    uint32_t nregs = (uint32_t)(remaining / 8);
    if (nregs > 27)
        nregs = 27;

    for (uint32_t i = 0; i < nregs; i++) {
        ew_error_t err = ew_read_u64(&rd, &out->regs[i]);
        if (err != EW_OK)
            break;
    }
    out->regs_valid = (nregs >= 17);
    out->parsed = 1;

    return EW_OK;
}

static ew_error_t parse_prpsinfo_64(const uint8_t *desc, uint32_t descsz,
                                     int is_big_endian,
                                     ew_prpsinfo_t *out)
{
    if (descsz < 136)
        return EW_ERR_TRUNCATED;

    ew_reader_t rd;
    ew_reader_init(&rd, desc, descsz, is_big_endian);

    uint8_t byte;
    ew_read_u8(&rd, &byte); out->pr_state = (char)byte;
    ew_read_u8(&rd, &byte); out->pr_sname = (char)byte;
    ew_read_u8(&rd, &byte); out->pr_zomb = (char)byte;
    ew_read_u8(&rd, &byte); out->pr_nice = (char)byte;

    ew_read_skip(&rd, 4);
    ew_read_u64(&rd, &out->pr_flag);

    uint32_t uid32, gid32;
    ew_read_u32(&rd, &uid32); out->pr_uid = uid32;
    ew_read_u32(&rd, &gid32); out->pr_gid = gid32;

    ew_read_i32(&rd, &out->pr_pid);
    ew_read_i32(&rd, &out->pr_ppid);
    ew_read_i32(&rd, &out->pr_pgrp);
    ew_read_i32(&rd, &out->pr_sid);

    ew_read_bytes(&rd, (uint8_t *)out->pr_fname, 16);
    out->pr_fname[15] = '\0';

    ew_read_bytes(&rd, (uint8_t *)out->pr_psargs, 80);
    out->pr_psargs[79] = '\0';

    out->parsed = 1;
    return EW_OK;
}

static ew_error_t parse_auxv_64(const uint8_t *desc, uint32_t descsz,
                                 int is_big_endian,
                                 ew_auxv_entry_t **out, uint32_t *count)
{
    if (descsz < 16)
        return EW_ERR_TRUNCATED;

    uint32_t max_entries = descsz / 16;
    ew_auxv_entry_t *entries = calloc(max_entries, sizeof(ew_auxv_entry_t));
    if (!entries)
        return EW_ERR_NOMEM;

    ew_reader_t rd;
    ew_reader_init(&rd, desc, descsz, is_big_endian);

    uint32_t n = 0;
    while (ew_reader_remaining(&rd) >= 16 && n < max_entries) {
        ew_read_u64(&rd, &entries[n].type);
        ew_read_u64(&rd, &entries[n].value);
        if (entries[n].type == 0)
            break;
        n++;
    }

    *out = entries;
    *count = n;
    return EW_OK;
}

static ew_error_t parse_nt_file_64(const uint8_t *desc, uint32_t descsz,
                                    int is_big_endian,
                                    ew_mapped_file_t **out, uint32_t *count)
{
    if (descsz < 16)
        return EW_ERR_TRUNCATED;

    ew_reader_t rd;
    ew_reader_init(&rd, desc, descsz, is_big_endian);

    uint64_t file_count, page_size;
    ew_read_u64(&rd, &file_count);
    ew_read_u64(&rd, &page_size);

    if (file_count > 4096 || file_count == 0) {
        *out = NULL;
        *count = 0;
        return EW_OK;
    }

    size_t entry_data_size = (size_t)file_count * 24;
    if (ew_reader_remaining(&rd) < entry_data_size) {
        *out = NULL;
        *count = 0;
        return EW_ERR_TRUNCATED;
    }

    ew_mapped_file_t *files = calloc((uint32_t)file_count,
                                      sizeof(ew_mapped_file_t));
    if (!files)
        return EW_ERR_NOMEM;

    for (uint32_t i = 0; i < (uint32_t)file_count; i++) {
        ew_read_u64(&rd, &files[i].start_addr);
        ew_read_u64(&rd, &files[i].end_addr);
        ew_read_u64(&rd, &files[i].file_offset);
        files[i].file_offset *= page_size;
    }

    size_t str_offset = ew_reader_tell(&rd);
    for (uint32_t i = 0; i < (uint32_t)file_count; i++) {
        if (str_offset >= descsz)
            break;
        const uint8_t *name_start = desc + str_offset;
        size_t max_len = descsz - str_offset;
        size_t name_len = 0;
        while (name_len < max_len && name_start[name_len] != '\0')
            name_len++;

        if (name_len < max_len) {
            files[i].filename = (const char *)name_start;
            str_offset += name_len + 1;
        } else {
            str_offset = descsz;
        }
    }

    *out = files;
    *count = (uint32_t)file_count;
    return EW_OK;
}

ew_error_t ew_parse_coredump(ew_context_t *ctx, ew_coredump_info_t *info)
{
    if (!ctx || !info)
        return EW_ERR_INVALID;

    memset(info, 0, sizeof(*info));

    if (ctx->header.e_type != EW_ET_CORE) {
        info->is_core = 0;
        return EW_OK;
    }
    info->is_core = 1;

    uint32_t prstatus_cap = 0;
    for (uint32_t i = 0; i < ctx->note_count; i++) {
        ew_note_t *note = &ctx->notes[i];
        if (!note->name || !note->desc)
            continue;

        if (strcmp(note->name, "CORE") != 0 &&
            strcmp(note->name, "LINUX") != 0)
            continue;

        switch (note->type) {
        case EW_NT_PRSTATUS:
            if (info->prstatus_count >= prstatus_cap) {
                uint32_t new_cap = prstatus_cap == 0 ? 4 : prstatus_cap * 2;
                ew_prstatus_t *tmp = realloc(info->prstatus,
                                              new_cap * sizeof(ew_prstatus_t));
                if (!tmp)
                    return EW_ERR_NOMEM;
                info->prstatus = tmp;
                prstatus_cap = new_cap;
            }
            if (ctx->is_64bit) {
                parse_prstatus_64(note->desc, note->descsz,
                                   ctx->is_big_endian,
                                   &info->prstatus[info->prstatus_count]);
            }
            info->prstatus_count++;
            break;

        case EW_NT_PRPSINFO:
            if (!info->has_prpsinfo) {
                info->prpsinfo = calloc(1, sizeof(ew_prpsinfo_t));
                if (!info->prpsinfo)
                    return EW_ERR_NOMEM;
                if (ctx->is_64bit) {
                    parse_prpsinfo_64(note->desc, note->descsz,
                                       ctx->is_big_endian,
                                       info->prpsinfo);
                }
                info->has_prpsinfo = 1;
            }
            break;

        case EW_NT_AUXV:
            if (!info->auxv) {
                if (ctx->is_64bit) {
                    parse_auxv_64(note->desc, note->descsz,
                                   ctx->is_big_endian,
                                   &info->auxv, &info->auxv_count);
                }
            }
            break;

        case EW_NT_FILE:
            if (!info->mapped_files) {
                if (ctx->is_64bit) {
                    parse_nt_file_64(note->desc, note->descsz,
                                      ctx->is_big_endian,
                                      &info->mapped_files,
                                      &info->mapped_file_count);
                }
            }
            break;

        default:
            break;
        }
    }

    return EW_OK;
}

void ew_coredump_info_destroy(ew_coredump_info_t *info)
{
    if (!info)
        return;
    free(info->prstatus);
    free(info->prpsinfo);
    free(info->auxv);
    free(info->mapped_files);
    memset(info, 0, sizeof(*info));
}

const char *ew_coredump_signal_name(int signo)
{
    switch (signo) {
    case 1:  return "SIGHUP";
    case 2:  return "SIGINT";
    case 3:  return "SIGQUIT";
    case 4:  return "SIGILL";
    case 5:  return "SIGTRAP";
    case 6:  return "SIGABRT";
    case 7:  return "SIGBUS";
    case 8:  return "SIGFPE";
    case 9:  return "SIGKILL";
    case 10: return "SIGUSR1";
    case 11: return "SIGSEGV";
    case 12: return "SIGUSR2";
    case 13: return "SIGPIPE";
    case 14: return "SIGALRM";
    case 15: return "SIGTERM";
    default: return "UNKNOWN";
    }
}
