#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void generate_random_array(uint8* array, int length) {
    srand(time(NULL));
    int i;
    for (i = 0; i < length; i++) {
        array[i] = rand() % 256;
    }
}

void get_report(struct attestation_report* report) {
    FILE* fp = fopen("/etc/sev-guest/report.bin", "rb");
    if (fp == NULL) {
        fp = fopen("report.bin", "rb");
    }

    if (fp == NULL) {
        fprintf(stderr, "Error: report.bin not found in /etc/sev-guest/report.bin or current directory\n");
        exit(1);
    }

    size_t bytes_read = fread(report, 1, sizeof(struct attestation_report), fp);
    fclose(fp);

    if (bytes_read != sizeof(struct attestation_report)) {
        fprintf(stderr, "Error: Failed to read complete attestation report from report.bin (read %zu of %zu bytes)\n",
                bytes_read, sizeof(struct attestation_report));
        exit(1);
    }

    printf("[info] Successfully loaded mock attestation report from report.bin\n");
    return;
}
