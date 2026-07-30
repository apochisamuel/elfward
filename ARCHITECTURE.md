# elfward Architecture

## Processing Pipeline

elfward follows a phased analysis pipeline, each stage building on
the results of preceding stages:

```
  header → sections → segments → strtabs → symtabs → dynamics
    → relocs → notes → hash → versions → graph → resolve
    → validate → normalize → report
```

## Module Inventory

### Core Parsing

| Module           | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| ew_reader.c/h    | Endian-aware binary reader with bounds checking |
| ew_header.c      | ELF header parsing and validation               |
| ew_section.c     | Section header table parsing and name resolution |
| ew_segment.c     | Program header (segment) parsing and mapping     |
| ew_symtab.c      | Symbol table and string table resolution         |
| ew_reloc.c       | Relocation parsing (REL/RELA for ELF32/64)       |
| ew_dynamic.c     | Dynamic section (.dynamic) parsing               |
| ew_notes.c       | Note section parsing (GNU ABI, build-id, etc.)   |

### Hash and Resolution

| Module           | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| ew_hash.c        | SysV and GNU hash table construction/lookup     |
| ew_version.c     | GNU version definitions, needs, and per-symbol indices |
| ew_graph.c       | Dependency graph (DT_NEEDED) with topo sort     |
| ew_resolve.c     | Multi-strategy symbol resolution with caching    |

### Infrastructure

| Module           | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| ew_context.c     | Context lifecycle and name lookup tables         |
| ew_cache.c       | Fibonacci-hashed key-value cache                 |
| ew_registry.c    | Multi-binary context registry                    |
| ew_plan.c        | Analysis plan construction and execution         |

### Post-Processing

| Module           | Purpose                                        |
| ---------------- | ---------------------------------------------- |
| ew_validate.c    | Structural validation passes                     |
| ew_normalize.c   | Section canonicalization and symbol normalization |
| ew_query.c       | Snapshot creation and symbol query API            |
| ew_report.c      | Formatted text report generation                 |
| ew_recover.c     | Error recovery and full parse orchestration      |

## Data Flow

1. **Loading**: Raw binary data is copied into a context via `ew_context_load`
2. **Header**: `ew_parse_header` extracts class, endianness, type, machine
3. **Sections**: `ew_parse_sections` reads section header table, loads data pointers
4. **Segments**: `ew_parse_segments` reads program headers, maps section-to-segment
5. **Strtabs**: `ew_resolve_strtabs` locates and validates string tables
6. **Symtabs**: `ew_parse_symtabs` reads .symtab and .dynsym, resolves names
7. **Dynamics**: `ew_parse_dynamics` reads DT_* entries, resolves string tags
8. **Relocs**: `ew_parse_relocs` reads REL/RELA sections, links to symbols
9. **Notes**: `ew_parse_notes` reads note sections and segments
10. **Hash**: `ew_build_sysv_hash` / `ew_build_gnu_hash` build lookup tables
11. **Versions**: `ew_resolve_versions` parses VERDEF/VERNEED/VERSYM
12. **Graph**: `ew_build_dep_graph` constructs dependency graph from DT_NEEDED
13. **Resolve**: `ew_resolve_symbols` resolves undefined symbols via hash/linear
14. **Validate**: `ew_validate` checks structural consistency
15. **Normalize**: `ew_normalize` canonicalizes sections and symbols

## Error Model

All functions return `ew_error_t`. Errors are classified as:

- **Fatal**: EW_ERR_NOMEM, EW_ERR_BAD_MAGIC — prevent further processing
- **Recoverable**: EW_ERR_BAD_SECTION, etc. — `ew_recover_parse` can continue

The `ew_is_recoverable()` function classifies each error code.
