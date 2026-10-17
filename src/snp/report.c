#include "report.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Search order for the base report. keys_gen uses the same order. */
static const char* REPORT_PATHS[] = {"/etc/sev-guest/report.bin", "report.bin"};

static bool has_custom_measurement = false;
static uint8 custom_measurement[48];

static bool has_custom_policy = false;
static uint64 custom_policy;

void override_measurement(const uint8* new_measurement) {
    memcpy(custom_measurement, new_measurement, sizeof(custom_measurement));
    has_custom_measurement = true;
}

void override_policy(uint64 new_policy) {
    custom_policy = new_policy;
    has_custom_policy = true;
}

int get_report(struct attestation_report* report) {
    FILE* fp = NULL;
    const char* path = NULL;
    for (size_t i = 0; i < sizeof(REPORT_PATHS) / sizeof(REPORT_PATHS[0]) && fp == NULL; i++) {
        path = REPORT_PATHS[i];
        fp = fopen(path, "rb");
    }

    if (fp == NULL) {
        fprintf(stderr, "[error] report.bin not found in /etc/sev-guest/report.bin or current directory\n");
        return -1;
    }

    size_t bytes_read = fread(report, 1, sizeof(struct attestation_report), fp);
    fclose(fp);

    if (bytes_read != sizeof(struct attestation_report)) {
        fprintf(stderr, "[error] failed to read complete attestation report from %s (read %zu of %zu bytes)\n",
                path, bytes_read, sizeof(struct attestation_report));
        return -1;
    }

    if (has_custom_measurement) {
        memcpy(report->measurement, custom_measurement, sizeof(custom_measurement));
    }

    if (has_custom_policy) {
        report->policy = custom_policy;
    }

    return 0;
}
