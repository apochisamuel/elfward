# elfward

A pure-C library for parsing and analyzing ELF (Executable and Linkable Format) binary files.

## Overview

elfward provides comprehensive ELF binary analysis with support for:

- ELF32 and ELF64 formats
- Little and big endian byte ordering
- Section headers and program headers
- Symbol tables (static and dynamic)
- Relocation processing (REL and RELA)
- Dynamic section and DT_NEEDED dependency tracking
- Note sections (GNU ABI tag, build-id, properties)
- SysV and GNU hash table construction and lookup
- GNU version definitions and requirements
- Dependency graph construction with cycle detection
- Symbol resolution with caching
- Structural validation
- Formatted reporting (readelf-style output)
- Error recovery for malformed binaries
- Snapshot-based query API

## Building

```
make          # Build library and tools
make test     # Build and run tests
```

Or use the build script:

```
./build.sh
```

For sanitizer builds (ASan, UBSan, MSan):

```
SANITIZER=address ./build.sh
```

## Usage

```c
#include "elfward.h"

ew_context_t *ctx = ew_context_create();
ew_context_load(ctx, data, size);
ew_full_analysis(ctx);

// Query symbols
ew_query_result_t *result = ew_query_symbols_by_name(ctx, "main");
// ...
ew_query_result_destroy(result);

// Generate report
ew_report_t *report = ew_report_create(ctx, EW_REPORT_FULL);
printf("%s", ew_report_get_text(report));
ew_report_destroy(report);

ew_context_destroy(ctx);
```

## Tools

- `tools/ew_dump` — CLI tool for inspecting ELF files (similar to readelf)

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed module descriptions.

## License

MIT
