/*
 * ew_dump.c — Command-line ELF inspection tool.
 *
 * Reads an ELF file and prints analysis results to stdout,
 * similar to readelf but using the elfward library.
 */

#include "elfward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options] <elf-file>\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -a, --all       Display all information\n");
    fprintf(stderr, "  -h, --header    Display ELF header\n");
    fprintf(stderr, "  -S, --sections  Display section headers\n");
    fprintf(stderr, "  -l, --segments  Display program headers\n");
    fprintf(stderr, "  -s, --symbols   Display symbol tables\n");
    fprintf(stderr, "  -d, --dynamic   Display dynamic section\n");
    fprintf(stderr, "  -r, --recovery  Use recovery mode\n");
    fprintf(stderr, "  --help          Display this help\n");
}

static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror(path);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 256 * 1024 * 1024) {
        fprintf(stderr, "Invalid file size: %ld\n", file_size);
        fclose(fp);
        return NULL;
    }

    uint8_t *data = malloc((size_t)file_size);
    if (!data) {
        fprintf(stderr, "Out of memory\n");
        fclose(fp);
        return NULL;
    }

    size_t read_count = fread(data, 1, (size_t)file_size, fp);
    fclose(fp);

    if (read_count != (size_t)file_size) {
        fprintf(stderr, "Short read: %zu of %ld bytes\n",
                read_count, file_size);
        free(data);
        return NULL;
    }

    *out_size = (size_t)file_size;
    return data;
}

int main(int argc, char *argv[])
{
    int show_header = 0, show_sections = 0, show_segments = 0;
    int show_symbols = 0, show_dynamic = 0, use_recovery = 0;
    const char *filename = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            show_header = show_sections = show_segments = 1;
            show_symbols = show_dynamic = 1;
        } else if (strcmp(argv[i], "-h") == 0 ||
                   strcmp(argv[i], "--header") == 0) {
            show_header = 1;
        } else if (strcmp(argv[i], "-S") == 0 ||
                   strcmp(argv[i], "--sections") == 0) {
            show_sections = 1;
        } else if (strcmp(argv[i], "-l") == 0 ||
                   strcmp(argv[i], "--segments") == 0) {
            show_segments = 1;
        } else if (strcmp(argv[i], "-s") == 0 ||
                   strcmp(argv[i], "--symbols") == 0) {
            show_symbols = 1;
        } else if (strcmp(argv[i], "-d") == 0 ||
                   strcmp(argv[i], "--dynamic") == 0) {
            show_dynamic = 1;
        } else if (strcmp(argv[i], "-r") == 0 ||
                   strcmp(argv[i], "--recovery") == 0) {
            use_recovery = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        } else {
            filename = argv[i];
        }
    }

    if (!filename) {
        usage(argv[0]);
        return 1;
    }

    /* Default: show summary */
    if (!show_header && !show_sections && !show_segments &&
        !show_symbols && !show_dynamic) {
        show_header = 1;
    }

    size_t file_size;
    uint8_t *data = read_file(filename, &file_size);
    if (!data)
        return 1;

    ew_context_t *ctx = ew_context_create();
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        free(data);
        return 1;
    }

    ew_error_t err = ew_context_load(ctx, data, file_size);
    if (err != EW_OK) {
        fprintf(stderr, "Failed to load: %s\n", ew_error_string(err));
        ew_context_destroy(ctx);
        free(data);
        return 1;
    }

    if (use_recovery) {
        err = ew_recover_parse(ctx);
        if (err != EW_OK) {
            fprintf(stderr, "Recovery parse: %s\n", ew_error_string(err));
        }
        ew_recover_resolve(ctx);
    } else {
        err = ew_full_analysis(ctx);
        if (err != EW_OK) {
            fprintf(stderr, "Analysis failed at: %s\n",
                    ew_error_string(err));
            fprintf(stderr, "Detail: %s\n", ctx->error_msg);
            /* Continue with partial results */
        }
    }

    if (show_header) {
        ew_report_t *report = ew_report_create(ctx, EW_REPORT_SUMMARY);
        if (report) {
            printf("%s\n", ew_report_get_text(report));
            ew_report_destroy(report);
        }
    }

    if (show_sections) {
        ew_report_t *report = ew_report_create(ctx, EW_REPORT_SECTIONS);
        if (report) {
            printf("%s\n", ew_report_get_text(report));
            ew_report_destroy(report);
        }
    }

    if (show_segments) {
        ew_report_t *report = ew_report_create(ctx, EW_REPORT_SEGMENTS);
        if (report) {
            printf("%s\n", ew_report_get_text(report));
            ew_report_destroy(report);
        }
    }

    if (show_symbols) {
        ew_report_t *report = ew_report_create(ctx, EW_REPORT_SYMBOLS);
        if (report) {
            printf("%s\n", ew_report_get_text(report));
            ew_report_destroy(report);
        }
    }

    if (show_dynamic) {
        ew_report_t *report = ew_report_create(ctx, EW_REPORT_DYNAMIC);
        if (report) {
            printf("%s\n", ew_report_get_text(report));
            ew_report_destroy(report);
        }
    }

    ew_context_destroy(ctx);
    free(data);
    return 0;
}
