#!/bin/bash -eu

# ClusterFuzzLite build script for elfward fuzz targets.
# Fenrir sets $SRC to the extracted repository root.

cd "$SRC"

# Compile library objects with fuzzer-compatible flags
for src in src/*.c; do
    obj="${src%.c}.o"
    $CC $CFLAGS -Isrc -c -o "$obj" "$src"
done

ar rcs libelfward.a src/*.o

# Build each fuzz target
for fuzzer in fuzz/*_fuzzer.c; do
    name=$(basename "${fuzzer%.c}")
    $CC $CFLAGS -Isrc -c -o "fuzz/${name}.o" "$fuzzer"
    $CXX $CXXFLAGS -o "$OUT/${name}" "fuzz/${name}.o" \
        libelfward.a $LIB_FUZZING_ENGINE

    # Copy seed corpus if available
    corpus_dir="fuzz/corpus/${name}"
    if [ -d "$corpus_dir" ]; then
        zip -j "$OUT/${name}_seed_corpus.zip" "$corpus_dir"/* 2>/dev/null || true
    fi
done
