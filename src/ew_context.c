/*
 * ew_context.c — Context lifecycle management.
 *
 * Handles creation, data loading, and destruction of the main
 * analysis context. Destruction walks every owned resource and
 * releases it in dependency order.
 */

#include "elfward.h"
#include "ew_reader.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Error descriptions                                                  */
/* ------------------------------------------------------------------ */

static const char *error_strings[EW_ERR_COUNT] = {
    [EW_OK]                = "success",
    [EW_ERR_NOMEM]         = "out of memory",
    [EW_ERR_INVALID]       = "invalid argument",
    [EW_ERR_TRUNCATED]     = "data truncated",
    [EW_ERR_BAD_MAGIC]     = "invalid ELF magic",
    [EW_ERR_BAD_CLASS]     = "unsupported ELF class",
    [EW_ERR_BAD_ENCODING]  = "unsupported data encoding",
    [EW_ERR_BAD_VERSION]   = "unsupported ELF version",
    [EW_ERR_BAD_SECTION]   = "malformed section header",
    [EW_ERR_BAD_SEGMENT]   = "malformed program header",
    [EW_ERR_BAD_SYMBOL]    = "malformed symbol table",
    [EW_ERR_BAD_RELOC]     = "malformed relocation",
    [EW_ERR_BAD_DYNAMIC]   = "malformed dynamic section",
    [EW_ERR_BAD_NOTE]      = "malformed note",
    [EW_ERR_BAD_HASH]      = "malformed hash table",
    [EW_ERR_BAD_VERSION_INFO] = "malformed version information",
    [EW_ERR_BAD_STRTAB]    = "malformed string table",
    [EW_ERR_OVERFLOW]      = "integer overflow",
    [EW_ERR_CYCLE]         = "dependency cycle detected",
    [EW_ERR_UNRESOLVED]    = "unresolved reference",
    [EW_ERR_DUPLICATE]     = "duplicate entry",
    [EW_ERR_NOT_FOUND]     = "entry not found",
    [EW_ERR_READONLY]      = "object is read-only",
    [EW_ERR_STATE]         = "invalid state transition",
    [EW_ERR_LIMIT]         = "limit exceeded",
    [EW_ERR_INTERNAL]      = "internal error",
};

const char *ew_error_string(ew_error_t err)
{
    if (err < 0 || err >= EW_ERR_COUNT)
        return "unknown error";
    return error_strings[err];
}

/* ------------------------------------------------------------------ */
/* Context creation                                                    */
/* ------------------------------------------------------------------ */

ew_context_t *ew_context_create(void)
{
    ew_context_t *ctx = calloc(1, sizeof(ew_context_t));
    if (!ctx)
        return NULL;

    ctx->generation = 1;
    ctx->last_error = EW_OK;
    ctx->error_msg[0] = '\0';

    return ctx;
}

/* ------------------------------------------------------------------ */
/* Data loading                                                        */
/* ------------------------------------------------------------------ */

ew_error_t ew_context_load(ew_context_t *ctx, const uint8_t *data, size_t size)
{
    if (!ctx || !data)
        return EW_ERR_INVALID;

    if (size < EW_MIN_INPUT_SIZE) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "input too small: %zu bytes", size);
        ctx->last_error = EW_ERR_TRUNCATED;
        return EW_ERR_TRUNCATED;
    }

    if (size > EW_MAX_INPUT_SIZE) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg),
                 "input too large: %zu bytes", size);
        ctx->last_error = EW_ERR_LIMIT;
        return EW_ERR_LIMIT;
    }

    /* Make an owned copy of the input data */
    ctx->data = malloc(size);
    if (!ctx->data) {
        ctx->last_error = EW_ERR_NOMEM;
        return EW_ERR_NOMEM;
    }
    memcpy(ctx->data, data, size);
    ctx->data_size = size;

    return EW_OK;
}

/* ------------------------------------------------------------------ */
/* Internal helpers for destroying sub-structures                      */
/* ------------------------------------------------------------------ */

static void destroy_sections(ew_context_t *ctx)
{
    if (!ctx->sections)
        return;

    for (uint32_t i = 0; i < ctx->section_count; i++) {
        if (ctx->sections[i].derived_state) {
            free(ctx->sections[i].derived_state);
            ctx->sections[i].derived_state = NULL;
        }
    }
    free(ctx->sections);
    ctx->sections = NULL;
    ctx->section_count = 0;
}

static void destroy_segments(ew_context_t *ctx)
{
    free(ctx->segments);
    ctx->segments = NULL;
    ctx->segment_count = 0;
}

static void destroy_symtab(ew_context_t *ctx)
{
    free(ctx->symtab);
    ctx->symtab = NULL;
    ctx->symtab_count = 0;

    free(ctx->dynsym);
    ctx->dynsym = NULL;
    ctx->dynsym_count = 0;
}

static void destroy_relocs(ew_context_t *ctx)
{
    free(ctx->relocs);
    ctx->relocs = NULL;
    ctx->reloc_count = 0;
    ctx->reloc_capacity = 0;
}

static void destroy_dynamics(ew_context_t *ctx)
{
    free(ctx->dynamics);
    ctx->dynamics = NULL;
    ctx->dynamic_count = 0;
}

static void destroy_notes(ew_context_t *ctx)
{
    free(ctx->notes);
    ctx->notes = NULL;
    ctx->note_count = 0;
}

static void destroy_version_defs(ew_context_t *ctx)
{
    if (ctx->verdefs) {
        for (uint32_t i = 0; i < ctx->verdef_count; i++) {
            free(ctx->verdefs[i].vd_names);
        }
        free(ctx->verdefs);
        ctx->verdefs = NULL;
        ctx->verdef_count = 0;
    }
}

static void destroy_version_needs(ew_context_t *ctx)
{
    if (ctx->verneeds) {
        for (uint32_t i = 0; i < ctx->verneed_count; i++) {
            free(ctx->verneeds[i].vn_aux);
        }
        free(ctx->verneeds);
        ctx->verneeds = NULL;
        ctx->verneed_count = 0;
    }
}

static void destroy_versym(ew_context_t *ctx)
{
    free(ctx->versym);
    ctx->versym = NULL;
    ctx->versym_count = 0;
}

static void destroy_sysv_hash(ew_context_t *ctx)
{
    free(ctx->sysv_hash.buckets);
    free(ctx->sysv_hash.chains);
    memset(&ctx->sysv_hash, 0, sizeof(ctx->sysv_hash));
}

static void destroy_gnu_hash(ew_context_t *ctx)
{
    free(ctx->gnu_hash.bloom);
    free(ctx->gnu_hash.buckets);
    free(ctx->gnu_hash.chains);
    memset(&ctx->gnu_hash, 0, sizeof(ctx->gnu_hash));
}

static void destroy_snapshots(ew_context_t *ctx)
{
    if (ctx->snapshots) {
        for (uint32_t i = 0; i < ctx->snapshot_count; i++) {
            if (ctx->snapshots[i]) {
                ew_snapshot_destroy(ctx->snapshots[i]);
            }
        }
        free(ctx->snapshots);
        ctx->snapshots = NULL;
        ctx->snapshot_count = 0;
        ctx->snapshot_capacity = 0;
    }
}

static void unregister_from_registry(ew_context_t *ctx)
{
    if (ctx->registry && ctx->registry_entry) {
        ctx->registry_entry->active = 0;
        ctx->registry_entry->ctx = NULL;
        ctx->registry_entry = NULL;
        ctx->registry = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Context destruction                                                 */
/* ------------------------------------------------------------------ */

void ew_context_destroy(ew_context_t *ctx)
{
    if (!ctx)
        return;

    /* Unregister from global registry first */
    unregister_from_registry(ctx);

    /* Destroy snapshots before underlying data */
    destroy_snapshots(ctx);

    /* Destroy caches */
    if (ctx->resolve_cache) {
        ew_cache_destroy(ctx->resolve_cache);
        ctx->resolve_cache = NULL;
    }
    if (ctx->section_cache) {
        ew_cache_destroy(ctx->section_cache);
        ctx->section_cache = NULL;
    }

    /* Destroy plans */
    if (ctx->plan) {
        ew_plan_destroy(ctx->plan);
        ctx->plan = NULL;
    }
    if (ctx->alt_plan) {
        ew_plan_destroy(ctx->alt_plan);
        ctx->alt_plan = NULL;
    }

    /* Destroy dependency graph */
    if (ctx->dep_graph) {
        ew_dep_graph_destroy(ctx->dep_graph);
        ctx->dep_graph = NULL;
    }

    /* Destroy hash tables */
    destroy_gnu_hash(ctx);
    destroy_sysv_hash(ctx);

    /* Destroy version information */
    destroy_versym(ctx);
    destroy_version_needs(ctx);
    destroy_version_defs(ctx);

    /* Destroy parsed structures */
    destroy_notes(ctx);
    destroy_dynamics(ctx);
    destroy_relocs(ctx);
    destroy_symtab(ctx);
    destroy_segments(ctx);
    destroy_sections(ctx);

    /* Release input data */
    free(ctx->data);
    ctx->data = NULL;
    ctx->data_size = 0;

    free(ctx);
}

/* ------------------------------------------------------------------ */
/* Convenience name lookup tables                                      */
/* ------------------------------------------------------------------ */

const char *ew_machine_name(uint16_t machine)
{
    switch (machine) {
    case EW_EM_NONE:    return "None";
    case EW_EM_SPARC:   return "SPARC";
    case EW_EM_386:     return "Intel 80386";
    case EW_EM_MIPS:    return "MIPS";
    case EW_EM_PPC:     return "PowerPC";
    case EW_EM_PPC64:   return "PowerPC 64-bit";
    case EW_EM_ARM:     return "ARM";
    case EW_EM_X86_64:  return "AMD x86-64";
    case EW_EM_AARCH64: return "ARM AARCH64";
    case EW_EM_RISCV:   return "RISC-V";
    default:            return "Unknown";
    }
}

const char *ew_type_name(uint16_t type)
{
    switch (type) {
    case EW_ET_NONE: return "NONE";
    case EW_ET_REL:  return "REL";
    case EW_ET_EXEC: return "EXEC";
    case EW_ET_DYN:  return "DYN";
    case EW_ET_CORE: return "CORE";
    default:         return "Unknown";
    }
}

const char *ew_section_type_name(uint32_t sh_type)
{
    switch (sh_type) {
    case EW_SHT_NULL:          return "NULL";
    case EW_SHT_PROGBITS:      return "PROGBITS";
    case EW_SHT_SYMTAB:        return "SYMTAB";
    case EW_SHT_STRTAB:        return "STRTAB";
    case EW_SHT_RELA:          return "RELA";
    case EW_SHT_HASH:          return "HASH";
    case EW_SHT_DYNAMIC:       return "DYNAMIC";
    case EW_SHT_NOTE:          return "NOTE";
    case EW_SHT_NOBITS:        return "NOBITS";
    case EW_SHT_REL:           return "REL";
    case EW_SHT_SHLIB:         return "SHLIB";
    case EW_SHT_DYNSYM:        return "DYNSYM";
    case EW_SHT_INIT_ARRAY:    return "INIT_ARRAY";
    case EW_SHT_FINI_ARRAY:    return "FINI_ARRAY";
    case EW_SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
    case EW_SHT_GROUP:         return "GROUP";
    case EW_SHT_SYMTAB_SHNDX:  return "SYMTAB_SHNDX";
    case EW_SHT_GNU_HASH:      return "GNU_HASH";
    case EW_SHT_GNU_VERDEF:    return "GNU_VERDEF";
    case EW_SHT_GNU_VERNEED:   return "GNU_VERNEED";
    case EW_SHT_GNU_VERSYM:    return "GNU_VERSYM";
    default:                   return "Unknown";
    }
}

const char *ew_segment_type_name(uint32_t p_type)
{
    switch (p_type) {
    case EW_PT_NULL:         return "NULL";
    case EW_PT_LOAD:         return "LOAD";
    case EW_PT_DYNAMIC:      return "DYNAMIC";
    case EW_PT_INTERP:       return "INTERP";
    case EW_PT_NOTE:         return "NOTE";
    case EW_PT_SHLIB:        return "SHLIB";
    case EW_PT_PHDR:         return "PHDR";
    case EW_PT_TLS:          return "TLS";
    case EW_PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case EW_PT_GNU_STACK:    return "GNU_STACK";
    case EW_PT_GNU_RELRO:    return "GNU_RELRO";
    case EW_PT_GNU_PROPERTY: return "GNU_PROPERTY";
    default:                 return "Unknown";
    }
}

const char *ew_symbol_binding_name(uint8_t binding)
{
    switch (binding) {
    case EW_STB_LOCAL:  return "LOCAL";
    case EW_STB_GLOBAL: return "GLOBAL";
    case EW_STB_WEAK:   return "WEAK";
    default:            return "Unknown";
    }
}

const char *ew_symbol_type_name(uint8_t stype)
{
    switch (stype) {
    case EW_STT_NOTYPE:   return "NOTYPE";
    case EW_STT_OBJECT:   return "OBJECT";
    case EW_STT_FUNC:     return "FUNC";
    case EW_STT_SECTION:  return "SECTION";
    case EW_STT_FILE:     return "FILE";
    case EW_STT_COMMON:   return "COMMON";
    case EW_STT_TLS:      return "TLS";
    case EW_STT_GNU_IFUNC: return "GNU_IFUNC";
    default:              return "Unknown";
    }
}

const char *ew_reloc_type_name(uint16_t machine, uint32_t rtype)
{
    if (machine == EW_EM_X86_64) {
        switch (rtype) {
        case EW_R_X86_64_NONE:       return "R_X86_64_NONE";
        case EW_R_X86_64_64:         return "R_X86_64_64";
        case EW_R_X86_64_PC32:       return "R_X86_64_PC32";
        case EW_R_X86_64_GOT32:      return "R_X86_64_GOT32";
        case EW_R_X86_64_PLT32:      return "R_X86_64_PLT32";
        case EW_R_X86_64_COPY:       return "R_X86_64_COPY";
        case EW_R_X86_64_GLOB_DAT:   return "R_X86_64_GLOB_DAT";
        case EW_R_X86_64_JUMP_SLOT:  return "R_X86_64_JUMP_SLOT";
        case EW_R_X86_64_RELATIVE:   return "R_X86_64_RELATIVE";
        case EW_R_X86_64_GOTPCREL:   return "R_X86_64_GOTPCREL";
        case EW_R_X86_64_32:         return "R_X86_64_32";
        case EW_R_X86_64_32S:        return "R_X86_64_32S";
        case EW_R_X86_64_16:         return "R_X86_64_16";
        case EW_R_X86_64_PC16:       return "R_X86_64_PC16";
        case EW_R_X86_64_8:          return "R_X86_64_8";
        case EW_R_X86_64_PC8:        return "R_X86_64_PC8";
        case EW_R_X86_64_TPOFF64:    return "R_X86_64_TPOFF64";
        case EW_R_X86_64_TPOFF32:    return "R_X86_64_TPOFF32";
        case EW_R_X86_64_IRELATIVE:  return "R_X86_64_IRELATIVE";
        default:                     return "R_X86_64_UNKNOWN";
        }
    }
    return "R_UNKNOWN";
}

const char *ew_dynamic_tag_name(int64_t tag)
{
    switch (tag) {
    case EW_DT_NULL:         return "NULL";
    case EW_DT_NEEDED:       return "NEEDED";
    case EW_DT_PLTRELSZ:     return "PLTRELSZ";
    case EW_DT_PLTGOT:       return "PLTGOT";
    case EW_DT_HASH:         return "HASH";
    case EW_DT_STRTAB:       return "STRTAB";
    case EW_DT_SYMTAB:       return "SYMTAB";
    case EW_DT_RELA:         return "RELA";
    case EW_DT_RELASZ:       return "RELASZ";
    case EW_DT_RELAENT:      return "RELAENT";
    case EW_DT_STRSZ:        return "STRSZ";
    case EW_DT_SYMENT:       return "SYMENT";
    case EW_DT_INIT:         return "INIT";
    case EW_DT_FINI:         return "FINI";
    case EW_DT_SONAME:       return "SONAME";
    case EW_DT_RPATH:        return "RPATH";
    case EW_DT_SYMBOLIC:     return "SYMBOLIC";
    case EW_DT_REL:          return "REL";
    case EW_DT_RELSZ:        return "RELSZ";
    case EW_DT_RELENT:       return "RELENT";
    case EW_DT_PLTREL:       return "PLTREL";
    case EW_DT_DEBUG:        return "DEBUG";
    case EW_DT_TEXTREL:      return "TEXTREL";
    case EW_DT_JMPREL:       return "JMPREL";
    case EW_DT_BIND_NOW:     return "BIND_NOW";
    case EW_DT_INIT_ARRAY:   return "INIT_ARRAY";
    case EW_DT_FINI_ARRAY:   return "FINI_ARRAY";
    case EW_DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ";
    case EW_DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
    case EW_DT_RUNPATH:      return "RUNPATH";
    case EW_DT_FLAGS:        return "FLAGS";
    case EW_DT_GNU_HASH:     return "GNU_HASH";
    case EW_DT_VERSYM:       return "VERSYM";
    case EW_DT_VERNEED:      return "VERNEED";
    case EW_DT_VERNEEDNUM:   return "VERNEEDNUM";
    case EW_DT_VERDEF:       return "VERDEF";
    case EW_DT_VERDEFNUM:    return "VERDEFNUM";
    default:                 return "Unknown";
    }
}
