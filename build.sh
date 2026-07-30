#!/bin/bash
set -e

CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--Wall -Wextra -O2 -std=c11}"
SANITIZER="${SANITIZER:-}"

# Apply sanitizer flags
if [ "$SANITIZER" = "address" ]; then
    CFLAGS="$CFLAGS -fsanitize=address -fsanitize-coverage=trace-pc-guard"
    LDFLAGS="${LDFLAGS:-} -fsanitize=address"
elif [ "$SANITIZER" = "undefined" ]; then
    CFLAGS="$CFLAGS -fsanitize=undefined -fsanitize-coverage=trace-pc-guard"
    LDFLAGS="${LDFLAGS:-} -fsanitize=undefined"
elif [ "$SANITIZER" = "memory" ]; then
    CFLAGS="$CFLAGS -fsanitize=memory -fsanitize-coverage=trace-pc-guard"
    LDFLAGS="${LDFLAGS:-} -fsanitize=memory"
fi

echo "Building elfward library..."
echo "CC=$CC"
echo "CFLAGS=$CFLAGS"
echo "SANITIZER=$SANITIZER"

# Compile all source files
OBJS=""
for src in src/*.c; do
    obj="${src%.c}.o"
    $CC $CFLAGS -Isrc -c -o "$obj" "$src"
    OBJS="$OBJS $obj"
done

# Create static library
ar rcs libelfward.a $OBJS
echo "Built libelfward.a"

# Build tools
if [ -d tools ] && ls tools/*.c 1>/dev/null 2>&1; then
    for tool in tools/*.c; do
        bin="${tool%.c}"
        $CC $CFLAGS -Isrc -o "$bin" "$tool" -L. -lelfward ${LDFLAGS:-}
        echo "Built $bin"
    done
fi

echo "Build complete."
