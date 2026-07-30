/*
 * elfward.h — ELF analysis and inspection library
 *
 * Provides comprehensive parsing, resolution, and querying of ELF
 * (Executable and Linkable Format) binaries for both 32-bit and 64-bit
 * variants across little-endian and big-endian architectures.
 */

#ifndef ELFWARD_H
#define ELFWARD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* ELF magic and identification constants                              */
/* ------------------------------------------------------------------ */

#define EW_EI_NIDENT      16
#define EW_ELFMAG0        0x7f
#define EW_ELFMAG1        'E'
#define EW_ELFMAG2        'L'
#define EW_ELFMAG3        'F'

/* EI_CLASS */
#define EW_ELFCLASSNONE   0
#define EW_ELFCLASS32     1
#define EW_ELFCLASS64     2

/* EI_DATA */
#define EW_ELFDATANONE    0
#define EW_ELFDATA2LSB    1
#define EW_ELFDATA2MSB    2

/* EI_OSABI */
#define EW_ELFOSABI_NONE       0
#define EW_ELFOSABI_HPUX       1
#define EW_ELFOSABI_NETBSD     2
#define EW_ELFOSABI_GNU        3
#define EW_ELFOSABI_LINUX      3
#define EW_ELFOSABI_SOLARIS    6
#define EW_ELFOSABI_AIX        7
#define EW_ELFOSABI_IRIX       8
#define EW_ELFOSABI_FREEBSD    9
#define EW_ELFOSABI_TRU64      10
#define EW_ELFOSABI_MODESTO    11
#define EW_ELFOSABI_OPENBSD    12
#define EW_ELFOSABI_ARM_AEABI  64
#define EW_ELFOSABI_ARM        97
#define EW_ELFOSABI_STANDALONE 255

/* e_type */
#define EW_ET_NONE   0
#define EW_ET_REL    1
#define EW_ET_EXEC   2
#define EW_ET_DYN    3
#define EW_ET_CORE   4
#define EW_ET_LOOS   0xfe00
#define EW_ET_HIOS   0xfeff
#define EW_ET_LOPROC 0xff00
#define EW_ET_HIPROC 0xffff

/* e_machine (common values) */
#define EW_EM_NONE     0
#define EW_EM_SPARC    2
#define EW_EM_386      3
#define EW_EM_MIPS     8
#define EW_EM_PPC      20
#define EW_EM_PPC64    21
#define EW_EM_ARM      40
#define EW_EM_X86_64   62
#define EW_EM_AARCH64  183
#define EW_EM_RISCV    243

/* e_version */
#define EW_EV_NONE    0
#define EW_EV_CURRENT 1

/* Section header types */
#define EW_SHT_NULL          0
#define EW_SHT_PROGBITS      1
#define EW_SHT_SYMTAB        2
#define EW_SHT_STRTAB        3
#define EW_SHT_RELA          4
#define EW_SHT_HASH          5
#define EW_SHT_DYNAMIC       6
#define EW_SHT_NOTE          7
#define EW_SHT_NOBITS        8
#define EW_SHT_REL           9
#define EW_SHT_SHLIB         10
#define EW_SHT_DYNSYM        11
#define EW_SHT_INIT_ARRAY    14
#define EW_SHT_FINI_ARRAY    15
#define EW_SHT_PREINIT_ARRAY 16
#define EW_SHT_GROUP         17
#define EW_SHT_SYMTAB_SHNDX  18
#define EW_SHT_GNU_HASH      0x6ffffff6
#define EW_SHT_GNU_VERDEF    0x6ffffffd
#define EW_SHT_GNU_VERNEED   0x6ffffffe
#define EW_SHT_GNU_VERSYM    0x6fffffff

/* Section header flags */
#define EW_SHF_WRITE            0x1
#define EW_SHF_ALLOC            0x2
#define EW_SHF_EXECINSTR        0x4
#define EW_SHF_MERGE            0x10
#define EW_SHF_STRINGS          0x20
#define EW_SHF_INFO_LINK        0x40
#define EW_SHF_LINK_ORDER       0x80
#define EW_SHF_OS_NONCONFORMING 0x100
#define EW_SHF_GROUP            0x200
#define EW_SHF_TLS              0x400

/* Special section indices */
#define EW_SHN_UNDEF     0
#define EW_SHN_LORESERVE 0xff00
#define EW_SHN_LOPROC    0xff00
#define EW_SHN_HIPROC    0xff1f
#define EW_SHN_ABS       0xfff1
#define EW_SHN_COMMON    0xfff2
#define EW_SHN_XINDEX    0xffff
#define EW_SHN_HIRESERVE 0xffff

/* Program header types */
#define EW_PT_NULL         0
#define EW_PT_LOAD         1
#define EW_PT_DYNAMIC      2
#define EW_PT_INTERP       3
#define EW_PT_NOTE         4
#define EW_PT_SHLIB        5
#define EW_PT_PHDR         6
#define EW_PT_TLS          7
#define EW_PT_GNU_EH_FRAME 0x6474e550
#define EW_PT_GNU_STACK    0x6474e551
#define EW_PT_GNU_RELRO    0x6474e552
#define EW_PT_GNU_PROPERTY 0x6474e553

/* Program header flags */
#define EW_PF_X 0x1
#define EW_PF_W 0x2
#define EW_PF_R 0x4

/* Symbol binding */
#define EW_STB_LOCAL  0
#define EW_STB_GLOBAL 1
#define EW_STB_WEAK   2

/* Symbol type */
#define EW_STT_NOTYPE  0
#define EW_STT_OBJECT  1
#define EW_STT_FUNC    2
#define EW_STT_SECTION 3
#define EW_STT_FILE    4
#define EW_STT_COMMON  5
#define EW_STT_TLS     6
#define EW_STT_GNU_IFUNC 10

/* Symbol visibility */
#define EW_STV_DEFAULT   0
#define EW_STV_INTERNAL  1
#define EW_STV_HIDDEN    2
#define EW_STV_PROTECTED 3

/* Symbol info macros */
#define EW_ELF_ST_BIND(info)       ((info) >> 4)
#define EW_ELF_ST_TYPE(info)       ((info) & 0xf)
#define EW_ELF_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))
#define EW_ELF_ST_VISIBILITY(o)    ((o) & 0x3)

/* Relocation macros (64-bit) */
#define EW_ELF64_R_SYM(info)  ((info) >> 32)
#define EW_ELF64_R_TYPE(info) ((uint32_t)(info))
#define EW_ELF64_R_INFO(sym, type) \
    (((uint64_t)(sym) << 32) + (uint64_t)(type))

/* Relocation macros (32-bit) */
#define EW_ELF32_R_SYM(info)  ((info) >> 8)
#define EW_ELF32_R_TYPE(info) ((uint8_t)(info))
#define EW_ELF32_R_INFO(sym, type) \
    (((uint32_t)(sym) << 8) + (uint8_t)(type))

/* Common x86_64 relocation types */
#define EW_R_X86_64_NONE       0
#define EW_R_X86_64_64         1
#define EW_R_X86_64_PC32       2
#define EW_R_X86_64_GOT32      3
#define EW_R_X86_64_PLT32      4
#define EW_R_X86_64_COPY       5
#define EW_R_X86_64_GLOB_DAT   6
#define EW_R_X86_64_JUMP_SLOT  7
#define EW_R_X86_64_RELATIVE   8
#define EW_R_X86_64_GOTPCREL   9
#define EW_R_X86_64_32         10
#define EW_R_X86_64_32S        11
#define EW_R_X86_64_16         12
#define EW_R_X86_64_PC16       13
#define EW_R_X86_64_8          14
#define EW_R_X86_64_PC8        15
#define EW_R_X86_64_TPOFF64    18
#define EW_R_X86_64_TPOFF32    23
#define EW_R_X86_64_IRELATIVE  37

/* Dynamic section tags */
#define EW_DT_NULL         0
#define EW_DT_NEEDED       1
#define EW_DT_PLTRELSZ     2
#define EW_DT_PLTGOT       3
#define EW_DT_HASH         4
#define EW_DT_STRTAB       5
#define EW_DT_SYMTAB       6
#define EW_DT_RELA         7
#define EW_DT_RELASZ       8
#define EW_DT_RELAENT      9
#define EW_DT_STRSZ        10
#define EW_DT_SYMENT       11
#define EW_DT_INIT         12
#define EW_DT_FINI         13
#define EW_DT_SONAME       14
#define EW_DT_RPATH        15
#define EW_DT_SYMBOLIC     16
#define EW_DT_REL          17
#define EW_DT_RELSZ        18
#define EW_DT_RELENT       19
#define EW_DT_PLTREL       20
#define EW_DT_DEBUG        21
#define EW_DT_TEXTREL      22
#define EW_DT_JMPREL       23
#define EW_DT_BIND_NOW     24
#define EW_DT_INIT_ARRAY   25
#define EW_DT_FINI_ARRAY   26
#define EW_DT_INIT_ARRAYSZ 27
#define EW_DT_FINI_ARRAYSZ 28
#define EW_DT_RUNPATH      29
#define EW_DT_FLAGS        30
#define EW_DT_ENCODING     32
#define EW_DT_GNU_HASH     0x6ffffef5
#define EW_DT_VERSYM       0x6ffffff0
#define EW_DT_VERNEED      0x6ffffffe
#define EW_DT_VERNEEDNUM   0x6fffffff
#define EW_DT_VERDEF       0x6ffffffc
#define EW_DT_VERDEFNUM    0x6ffffffd

/* Note types */
#define EW_NT_GNU_ABI_TAG     1
#define EW_NT_GNU_HWCAP       2
#define EW_NT_GNU_BUILD_ID    3
#define EW_NT_GNU_GOLD_VERSION 4
#define EW_NT_GNU_PROPERTY_TYPE_0 5

/* Version definition flags */
#define EW_VER_DEF_CURRENT 1
#define EW_VER_FLG_BASE    1
#define EW_VER_FLG_WEAK    2

/* Version need flags */
#define EW_VER_NEED_CURRENT 1

/* ------------------------------------------------------------------ */
/* Library error codes                                                 */
/* ------------------------------------------------------------------ */

typedef enum {
    EW_OK = 0,
    EW_ERR_NOMEM,
    EW_ERR_INVALID,
    EW_ERR_TRUNCATED,
    EW_ERR_BAD_MAGIC,
    EW_ERR_BAD_CLASS,
    EW_ERR_BAD_ENCODING,
    EW_ERR_BAD_VERSION,
    EW_ERR_BAD_SECTION,
    EW_ERR_BAD_SEGMENT,
    EW_ERR_BAD_SYMBOL,
    EW_ERR_BAD_RELOC,
    EW_ERR_BAD_DYNAMIC,
    EW_ERR_BAD_NOTE,
    EW_ERR_BAD_HASH,
    EW_ERR_BAD_VERSION_INFO,
    EW_ERR_BAD_STRTAB,
    EW_ERR_OVERFLOW,
    EW_ERR_CYCLE,
    EW_ERR_UNRESOLVED,
    EW_ERR_DUPLICATE,
    EW_ERR_NOT_FOUND,
    EW_ERR_READONLY,
    EW_ERR_STATE,
    EW_ERR_LIMIT,
    EW_ERR_INTERNAL,
    EW_ERR_COUNT
} ew_error_t;

/* ------------------------------------------------------------------ */
/* Library limits                                                      */
/* ------------------------------------------------------------------ */

#define EW_MAX_SECTIONS       4096
#define EW_MAX_SEGMENTS       256
#define EW_MAX_SYMBOLS        262144
#define EW_MAX_RELOCS         524288
#define EW_MAX_DYNAMIC_ENTRIES 1024
#define EW_MAX_NOTES          256
#define EW_MAX_DEPENDENCIES   256
#define EW_MAX_VERSIONS       1024
#define EW_MAX_STRTAB_SIZE    (16 * 1024 * 1024)
#define EW_MAX_SECTION_SIZE   (64 * 1024 * 1024)
#define EW_MAX_INPUT_SIZE     (256 * 1024 * 1024)
#define EW_MIN_INPUT_SIZE     64
#define EW_MAX_HASH_BUCKETS   65536
#define EW_MAX_GNU_BUCKETS    131072
#define EW_MAX_PLAN_STEPS     512
#define EW_MAX_GRAPH_NODES    4096
#define EW_MAX_GRAPH_EDGES    16384
#define EW_MAX_CACHE_ENTRIES  65536
#define EW_MAX_RECOVERY_DEPTH 8

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

typedef struct ew_context       ew_context_t;
typedef struct ew_reader        ew_reader_t;
typedef struct ew_section       ew_section_t;
typedef struct ew_segment       ew_segment_t;
typedef struct ew_symbol        ew_symbol_t;
typedef struct ew_relocation    ew_relocation_t;
typedef struct ew_dynamic_entry ew_dynamic_entry_t;
typedef struct ew_note          ew_note_t;
typedef struct ew_version_def   ew_version_def_t;
typedef struct ew_version_need  ew_version_need_t;
typedef struct ew_version_aux   ew_version_aux_t;
typedef struct ew_hash_table    ew_hash_table_t;
typedef struct ew_gnu_hash      ew_gnu_hash_t;
typedef struct ew_dep_graph     ew_dep_graph_t;
typedef struct ew_dep_node      ew_dep_node_t;
typedef struct ew_plan          ew_plan_t;
typedef struct ew_plan_step     ew_plan_step_t;
typedef struct ew_cache         ew_cache_t;
typedef struct ew_cache_entry   ew_cache_entry_t;
typedef struct ew_snapshot      ew_snapshot_t;
typedef struct ew_query_result  ew_query_result_t;
typedef struct ew_report        ew_report_t;
typedef struct ew_registry      ew_registry_t;
typedef struct ew_registry_entry ew_registry_entry_t;

/* ------------------------------------------------------------------ */
/* ELF header (unified representation)                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  e_ident[EW_EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ew_elf_header_t;

/* ------------------------------------------------------------------ */
/* Section descriptor                                                  */
/* ------------------------------------------------------------------ */

struct ew_section {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
    /* Resolved fields */
    const char *name;
    const uint8_t *data;
    uint32_t index;
    int      loaded;
    int      canonical_id;
    void    *derived_state;
};

/* ------------------------------------------------------------------ */
/* Segment descriptor                                                  */
/* ------------------------------------------------------------------ */

struct ew_segment {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
    /* Resolved fields */
    const uint8_t *data;
    uint32_t index;
    int      loaded;
    int      backing_shared;
    uint32_t shared_with;
};

/* ------------------------------------------------------------------ */
/* Symbol descriptor                                                   */
/* ------------------------------------------------------------------ */

struct ew_symbol {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
    /* Resolved fields */
    const char *name;
    uint32_t    index;
    int         resolved;
    int         version_index;
    int         is_dynamic;
    uint32_t    hash_chain_next;
    uint32_t    gnu_hash_val;
    uint64_t    resolved_addr;
    ew_section_t *target_section;
    int         ownership_stage;
    int         generation;
};

/* ------------------------------------------------------------------ */
/* Relocation descriptor                                               */
/* ------------------------------------------------------------------ */

struct ew_relocation {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
    int      has_addend;
    /* Resolved fields */
    uint32_t sym_index;
    uint32_t type;
    uint32_t section_index;
    int      applied;
    uint64_t computed_value;
    ew_symbol_t *target_symbol;
    int      generation;
};

/* ------------------------------------------------------------------ */
/* Dynamic entry                                                       */
/* ------------------------------------------------------------------ */

struct ew_dynamic_entry {
    int64_t  d_tag;
    uint64_t d_val;
    /* Resolved fields */
    const char *string_val;
    int         resolved;
};

/* ------------------------------------------------------------------ */
/* Note descriptor                                                     */
/* ------------------------------------------------------------------ */

struct ew_note {
    uint32_t    namesz;
    uint32_t    descsz;
    uint32_t    type;
    const char *name;
    const uint8_t *desc;
    uint32_t    section_index;
    int         processed;
};

/* ------------------------------------------------------------------ */
/* Version information                                                 */
/* ------------------------------------------------------------------ */

struct ew_version_aux {
    uint32_t    vna_hash;
    uint16_t    vna_flags;
    uint16_t    vna_other;
    const char *vna_name;
};

struct ew_version_def {
    uint16_t    vd_flags;
    uint16_t    vd_ndx;
    uint16_t    vd_cnt;
    uint32_t    vd_hash;
    const char **vd_names;
    uint16_t    name_count;
    int         resolved;
};

struct ew_version_need {
    uint16_t          vn_version;
    uint16_t          vn_cnt;
    const char       *vn_file;
    ew_version_aux_t *vn_aux;
    uint16_t          aux_count;
    int               resolved;
};

/* ------------------------------------------------------------------ */
/* Hash tables                                                         */
/* ------------------------------------------------------------------ */

struct ew_hash_table {
    uint32_t  nbucket;
    uint32_t  nchain;
    uint32_t *buckets;
    uint32_t *chains;
    int       valid;
};

struct ew_gnu_hash {
    uint32_t  nbuckets;
    uint32_t  symoffset;
    uint32_t  bloom_size;
    uint32_t  bloom_shift;
    uint64_t *bloom;
    uint32_t *buckets;
    uint32_t *chains;
    uint32_t  chain_count;
    int       is_64bit;
    int       valid;
};

/* ------------------------------------------------------------------ */
/* Dependency graph                                                    */
/* ------------------------------------------------------------------ */

struct ew_dep_node {
    const char *name;
    uint32_t    node_id;
    uint32_t   *edges;
    uint32_t    edge_count;
    uint32_t    edge_capacity;
    int         visited;
    int         in_stack;
    uint32_t    topo_order;
    void       *user_data;
    int         generation;
};

struct ew_dep_graph {
    ew_dep_node_t *nodes;
    uint32_t       node_count;
    uint32_t       node_capacity;
    uint32_t      *topo_sorted;
    uint32_t       topo_count;
    int            has_cycle;
    int            sorted;
    int            generation;
};

/* ------------------------------------------------------------------ */
/* Analysis plan                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    EW_STEP_PARSE_HEADER,
    EW_STEP_PARSE_SECTIONS,
    EW_STEP_PARSE_SEGMENTS,
    EW_STEP_RESOLVE_STRTABS,
    EW_STEP_PARSE_SYMTABS,
    EW_STEP_PARSE_DYNAMICS,
    EW_STEP_PARSE_RELOCS,
    EW_STEP_PARSE_NOTES,
    EW_STEP_BUILD_HASH,
    EW_STEP_RESOLVE_VERSIONS,
    EW_STEP_BUILD_GRAPH,
    EW_STEP_RESOLVE_SYMBOLS,
    EW_STEP_APPLY_RELOCS,
    EW_STEP_VALIDATE,
    EW_STEP_NORMALIZE,
    EW_STEP_REGISTER,
    EW_STEP_CACHE,
    EW_STEP_COUNT
} ew_step_type_t;

struct ew_plan_step {
    ew_step_type_t type;
    int            completed;
    int            skipped;
    ew_error_t     result;
    uint32_t       items_processed;
};

struct ew_plan {
    ew_plan_step_t steps[EW_MAX_PLAN_STEPS];
    uint32_t       step_count;
    uint32_t       current_step;
    int            finalized;
    int            generation;
    void          *shared_cache;
};

/* ------------------------------------------------------------------ */
/* Resolution cache                                                    */
/* ------------------------------------------------------------------ */

struct ew_cache_entry {
    uint64_t    key;
    void       *value;
    uint32_t    generation;
    int         pinned;
    int         valid;
    ew_cache_entry_t *next;
};

struct ew_cache {
    ew_cache_entry_t **buckets;
    uint32_t           bucket_count;
    uint32_t           entry_count;
    uint32_t           generation;
    int                frozen;
};

/* ------------------------------------------------------------------ */
/* Query snapshot                                                      */
/* ------------------------------------------------------------------ */

struct ew_snapshot {
    ew_symbol_t    *symbols;
    uint32_t        symbol_count;
    ew_section_t   *sections;
    uint32_t        section_count;
    ew_relocation_t *relocs;
    uint32_t        reloc_count;
    uint32_t        generation;
    int             detached;
    ew_context_t   *owner;
};

/* ------------------------------------------------------------------ */
/* Query result                                                        */
/* ------------------------------------------------------------------ */

struct ew_query_result {
    ew_symbol_t   **symbols;
    uint32_t        count;
    uint32_t        capacity;
    int             sorted;
    ew_snapshot_t  *source_snap;
};

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    EW_REPORT_SUMMARY,
    EW_REPORT_SECTIONS,
    EW_REPORT_SEGMENTS,
    EW_REPORT_SYMBOLS,
    EW_REPORT_RELOCS,
    EW_REPORT_DYNAMIC,
    EW_REPORT_NOTES,
    EW_REPORT_VERSIONS,
    EW_REPORT_GRAPH,
    EW_REPORT_FULL
} ew_report_type_t;

struct ew_report {
    char    *buffer;
    size_t   length;
    size_t   capacity;
    ew_report_type_t type;
};

/* ------------------------------------------------------------------ */
/* Global registry                                                     */
/* ------------------------------------------------------------------ */

struct ew_registry_entry {
    const char     *name;
    uint64_t        base_addr;
    ew_context_t   *ctx;
    uint32_t        ref_count;
    int             active;
    int             generation;
    ew_registry_entry_t *next;
};

struct ew_registry {
    ew_registry_entry_t **buckets;
    uint32_t              bucket_count;
    uint32_t              entry_count;
    uint32_t              generation;
};

/* ------------------------------------------------------------------ */
/* Main context                                                        */
/* ------------------------------------------------------------------ */

struct ew_context {
    /* Input data (owned copy) */
    uint8_t        *data;
    size_t          data_size;

    /* Parsed header */
    ew_elf_header_t header;
    int             is_64bit;
    int             is_big_endian;

    /* Sections */
    ew_section_t   *sections;
    uint32_t        section_count;
    const char     *shstrtab;
    size_t          shstrtab_size;

    /* Segments */
    ew_segment_t   *segments;
    uint32_t        segment_count;

    /* Symbol tables */
    ew_symbol_t    *symtab;
    uint32_t        symtab_count;
    ew_symbol_t    *dynsym;
    uint32_t        dynsym_count;
    const char     *symstrtab;
    size_t          symstrtab_size;
    const char     *dynstrtab;
    size_t          dynstrtab_size;

    /* Relocations */
    ew_relocation_t *relocs;
    uint32_t         reloc_count;
    uint32_t         reloc_capacity;

    /* Dynamic entries */
    ew_dynamic_entry_t *dynamics;
    uint32_t            dynamic_count;

    /* Notes */
    ew_note_t      *notes;
    uint32_t        note_count;

    /* Version information */
    ew_version_def_t  *verdefs;
    uint32_t           verdef_count;
    ew_version_need_t *verneeds;
    uint32_t           verneed_count;
    uint16_t          *versym;
    uint32_t           versym_count;

    /* Hash tables */
    ew_hash_table_t  sysv_hash;
    ew_gnu_hash_t    gnu_hash;

    /* Dependency graph */
    ew_dep_graph_t  *dep_graph;

    /* Analysis plan */
    ew_plan_t       *plan;
    ew_plan_t       *alt_plan;

    /* Resolution cache */
    ew_cache_t      *resolve_cache;
    ew_cache_t      *section_cache;

    /* Snapshots */
    ew_snapshot_t  **snapshots;
    uint32_t         snapshot_count;
    uint32_t         snapshot_capacity;

    /* Global registry membership */
    ew_registry_t   *registry;
    ew_registry_entry_t *registry_entry;

    /* State tracking */
    int              parsed;
    int              resolved;
    int              validated;
    int              normalized;
    int              cached;
    int              registered;
    int              generation;
    ew_error_t       last_error;
    char             error_msg[256];

    /* Recovery state */
    int              in_recovery;
    int              recovery_depth;
    ew_error_t       recovery_errors[EW_MAX_RECOVERY_DEPTH];
};

/* ------------------------------------------------------------------ */
/* Public API — Context lifecycle                                      */
/* ------------------------------------------------------------------ */

ew_context_t *ew_context_create(void);
ew_error_t    ew_context_load(ew_context_t *ctx, const uint8_t *data, size_t size);
void          ew_context_destroy(ew_context_t *ctx);
const char   *ew_error_string(ew_error_t err);

/* ------------------------------------------------------------------ */
/* Public API — Parsing                                                */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_header(ew_context_t *ctx);
ew_error_t ew_parse_sections(ew_context_t *ctx);
ew_error_t ew_parse_segments(ew_context_t *ctx);
ew_error_t ew_resolve_strtabs(ew_context_t *ctx);
ew_error_t ew_parse_symtabs(ew_context_t *ctx);
ew_error_t ew_parse_dynamics(ew_context_t *ctx);
ew_error_t ew_parse_relocs(ew_context_t *ctx);
ew_error_t ew_parse_notes(ew_context_t *ctx);
ew_error_t ew_parse_full(ew_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Public API — Hash tables                                            */
/* ------------------------------------------------------------------ */

ew_error_t    ew_build_sysv_hash(ew_context_t *ctx);
ew_error_t    ew_build_gnu_hash(ew_context_t *ctx);
ew_symbol_t  *ew_hash_lookup(ew_context_t *ctx, const char *name);
ew_symbol_t  *ew_gnu_hash_lookup(ew_context_t *ctx, const char *name);

/* ------------------------------------------------------------------ */
/* Public API — Version resolution                                     */
/* ------------------------------------------------------------------ */

ew_error_t ew_parse_version_defs(ew_context_t *ctx);
ew_error_t ew_parse_version_needs(ew_context_t *ctx);
ew_error_t ew_parse_versym(ew_context_t *ctx);
ew_error_t ew_resolve_versions(ew_context_t *ctx);
const char *ew_symbol_version_name(ew_context_t *ctx, uint32_t sym_index);

/* ------------------------------------------------------------------ */
/* Public API — Dependency graph                                       */
/* ------------------------------------------------------------------ */

ew_error_t ew_build_dep_graph(ew_context_t *ctx);
ew_error_t ew_dep_graph_sort(ew_dep_graph_t *g);
int        ew_dep_graph_has_cycle(ew_dep_graph_t *g);
ew_error_t ew_dep_graph_add_edge(ew_dep_graph_t *g,
                                  uint32_t from, uint32_t to);
void       ew_dep_graph_destroy(ew_dep_graph_t *g);

/* ------------------------------------------------------------------ */
/* Public API — Symbol resolution                                     */
/* ------------------------------------------------------------------ */

ew_error_t   ew_resolve_symbols(ew_context_t *ctx);
ew_error_t   ew_resolve_symbol(ew_context_t *ctx, ew_symbol_t *sym);
ew_error_t   ew_apply_relocations(ew_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Public API — Validation                                             */
/* ------------------------------------------------------------------ */

ew_error_t ew_validate(ew_context_t *ctx);
ew_error_t ew_validate_sections(ew_context_t *ctx);
ew_error_t ew_validate_symbols(ew_context_t *ctx);
ew_error_t ew_validate_relocs(ew_context_t *ctx);
ew_error_t ew_validate_dynamics(ew_context_t *ctx);
ew_error_t ew_validate_graph(ew_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Public API — Normalization                                          */
/* ------------------------------------------------------------------ */

ew_error_t ew_normalize(ew_context_t *ctx);
ew_error_t ew_canonicalize_sections(ew_context_t *ctx);
ew_error_t ew_normalize_symbols(ew_context_t *ctx);
ew_error_t ew_deduplicate_relocs(ew_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Public API — Plan construction                                      */
/* ------------------------------------------------------------------ */

ew_plan_t *ew_plan_create(void);
ew_error_t ew_plan_add_step(ew_plan_t *plan, ew_step_type_t type);
ew_error_t ew_plan_execute(ew_context_t *ctx, ew_plan_t *plan);
void       ew_plan_destroy(ew_plan_t *plan);

/* ------------------------------------------------------------------ */
/* Public API — Cache                                                  */
/* ------------------------------------------------------------------ */

ew_cache_t *ew_cache_create(uint32_t bucket_count);
ew_error_t  ew_cache_put(ew_cache_t *cache, uint64_t key, void *value);
void       *ew_cache_get(ew_cache_t *cache, uint64_t key);
ew_error_t  ew_cache_invalidate(ew_cache_t *cache, uint64_t key);
ew_error_t  ew_cache_clear(ew_cache_t *cache);
void        ew_cache_freeze(ew_cache_t *cache);
void        ew_cache_destroy(ew_cache_t *cache);

/* ------------------------------------------------------------------ */
/* Public API — Registry                                               */
/* ------------------------------------------------------------------ */

ew_registry_t *ew_registry_create(uint32_t bucket_count);
ew_error_t     ew_registry_add(ew_registry_t *reg, const char *name,
                                uint64_t base_addr, ew_context_t *ctx);
ew_registry_entry_t *ew_registry_find(ew_registry_t *reg, const char *name);
ew_error_t     ew_registry_remove(ew_registry_t *reg, const char *name);
void           ew_registry_destroy(ew_registry_t *reg);

/* ------------------------------------------------------------------ */
/* Public API — Snapshots                                              */
/* ------------------------------------------------------------------ */

ew_snapshot_t *ew_snapshot_create(ew_context_t *ctx);
ew_error_t     ew_snapshot_refresh(ew_snapshot_t *snap);
void           ew_snapshot_detach(ew_snapshot_t *snap);
void           ew_snapshot_destroy(ew_snapshot_t *snap);

/* ------------------------------------------------------------------ */
/* Public API — Query                                                  */
/* ------------------------------------------------------------------ */

ew_query_result_t *ew_query_symbols_by_name(ew_context_t *ctx,
                                             const char *pattern);
ew_query_result_t *ew_query_symbols_by_type(ew_context_t *ctx,
                                             uint8_t sym_type);
ew_query_result_t *ew_query_symbols_by_section(ew_context_t *ctx,
                                                uint32_t section_idx);
ew_query_result_t *ew_query_symbols_by_binding(ew_context_t *ctx,
                                                uint8_t binding);
ew_query_result_t *ew_query_undefined_symbols(ew_context_t *ctx);
ew_query_result_t *ew_query_exported_symbols(ew_context_t *ctx);
ew_error_t         ew_query_sort_by_addr(ew_query_result_t *result);
ew_error_t         ew_query_sort_by_name(ew_query_result_t *result);
void               ew_query_result_destroy(ew_query_result_t *result);

ew_section_t *ew_find_section_by_name(ew_context_t *ctx, const char *name);
ew_section_t *ew_find_section_by_type(ew_context_t *ctx, uint32_t type);
ew_section_t *ew_find_section_by_addr(ew_context_t *ctx, uint64_t addr);
ew_segment_t *ew_find_segment_by_type(ew_context_t *ctx, uint32_t type);
ew_segment_t *ew_find_segment_by_addr(ew_context_t *ctx, uint64_t addr);

/* ------------------------------------------------------------------ */
/* Public API — Reporting                                              */
/* ------------------------------------------------------------------ */

ew_report_t *ew_report_create(ew_context_t *ctx, ew_report_type_t type);
ew_error_t   ew_report_write(ew_report_t *report, int fd);
const char  *ew_report_get_text(ew_report_t *report);
void         ew_report_destroy(ew_report_t *report);

/* ------------------------------------------------------------------ */
/* Public API — Recovery                                               */
/* ------------------------------------------------------------------ */

ew_error_t ew_recover_parse(ew_context_t *ctx);
ew_error_t ew_recover_resolve(ew_context_t *ctx);
int        ew_is_recoverable(ew_error_t err);

/* ------------------------------------------------------------------ */
/* Public API — Convenience                                            */
/* ------------------------------------------------------------------ */

ew_error_t ew_full_analysis(ew_context_t *ctx);
ew_error_t ew_batch_resolve(ew_context_t *ctx, const char **names,
                             uint32_t count, ew_symbol_t **results);
uint32_t   ew_section_count(ew_context_t *ctx);
uint32_t   ew_segment_count(ew_context_t *ctx);
uint32_t   ew_symbol_count(ew_context_t *ctx, int dynamic);
uint32_t   ew_reloc_count(ew_context_t *ctx);
const char *ew_machine_name(uint16_t machine);
const char *ew_type_name(uint16_t type);
const char *ew_section_type_name(uint32_t sh_type);
const char *ew_segment_type_name(uint32_t p_type);
const char *ew_symbol_binding_name(uint8_t binding);
const char *ew_symbol_type_name(uint8_t stype);
const char *ew_reloc_type_name(uint16_t machine, uint32_t rtype);
const char *ew_dynamic_tag_name(int64_t tag);

#ifdef __cplusplus
}
#endif

#endif /* ELFWARD_H */
