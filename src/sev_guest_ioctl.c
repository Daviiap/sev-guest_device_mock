#include <errno.h>
#include <fcntl.h>
#include <fuse/cuse_lowlevel.h>
#include <linux/types.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "snp/attestation.h"
#include "snp/sev-guest.h"

#define KEY_SEL_DEFAULT 0
#define KEY_SEL_VCEK 1
#define KEY_SEL_VLEK 2

char PRIVATE_VCEK_PATH[128] = "/etc/sev-guest/vcek/private.pem";
char PRIVATE_VLEK_PATH[128] = "/etc/sev-guest/vlek/private.pem";

EVP_PKEY* read_ecdsa_key_from_file(const char* key_file) {
    FILE* key_fp = fopen(key_file, "r");
    if (key_fp == NULL) {
        fprintf(stderr, "Error opening key file\n");
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (pkey == NULL) {
        fprintf(stderr, "Error reading ECDSA key from file\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return pkey;
}

void generate_random_array(uint8* array, int length) {
    srand(time(NULL));
    int i;
    for (i = 0; i < length; i++) {
        array[i] = rand() % 256;
    }
}

int is_vlek_present() { return access(PRIVATE_VLEK_PATH, F_OK) == 0; }

EVP_PKEY* read_ek(int key_sel) {
    EVP_PKEY* eckey = NULL;
    switch (key_sel) {
        case KEY_SEL_DEFAULT:
            if (is_vlek_present()) {
                eckey = read_ecdsa_key_from_file(PRIVATE_VLEK_PATH);
            } else {
                eckey = read_ecdsa_key_from_file(PRIVATE_VCEK_PATH);
            }
            break;
        case KEY_SEL_VCEK:
            eckey = read_ecdsa_key_from_file(PRIVATE_VCEK_PATH);
            break;
        case KEY_SEL_VLEK:
            eckey = read_ecdsa_key_from_file(PRIVATE_VLEK_PATH);
            break;
    }

    if (eckey == NULL) {
        fprintf(stderr, "Error reading endorsement key\n");
        return NULL;
    }

    return eckey;
}

void sha384(unsigned char* data, unsigned int* hash_len,
            unsigned char hash[SHA384_DIGEST_LENGTH]) {
    size_t data_len = offsetof(struct attestation_report, signature);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Error creating SHA-384 context\n");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) != 1) {
        fprintf(stderr, "Error initializing SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, data, data_len) != 1) {
        fprintf(stderr, "Error updating SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        fprintf(stderr, "Error finalizing SHA-384 context\n");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);
}

void sign_attestation_report(struct attestation_report* report, __u32 key_sel) {
    unsigned char* data = (unsigned char*)report;

    EVP_PKEY* eckey = read_ek(key_sel);
    if (eckey == NULL) {
        fprintf(stderr, "Error loading key\n");
        return;
    }

    if (key_sel == KEY_SEL_VLEK ||
        (key_sel == KEY_SEL_DEFAULT && is_vlek_present())) {
        report->flags |= 0b00000100;
    } else {
        report->flags &= 0b11111011;
    }

    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(data, sizeof(struct attestation_report), hash);

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        EVP_PKEY_free(eckey);
        return;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, eckey) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignInit\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return;
    }

    if (EVP_DigestSignUpdate(mdctx, hash, SHA384_DIGEST_LENGTH) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignUpdate\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return;
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "Error determining signature length\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return;
    }
    
    unsigned char* signature = OPENSSL_malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Error allocating memory for signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return;
    }

    if (EVP_DigestSignFinal(mdctx, signature, &sig_len) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignFinal\n");
        OPENSSL_free(signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return;
    }

    // Assuming signature is split into two parts: R and S, equally
    size_t half_sig_len = sig_len / 2;
    memcpy(report->signature.r, signature, half_sig_len);
    memcpy(report->signature.s, signature + half_sig_len, half_sig_len);

    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(eckey);
}

void get_report(struct attestation_report* report) {
    uint8 measurement[] = {
        0x72, 0xD9, 0x9E, 0x55, 0x0E, 0x7C, 0xB1, 0x2A, 0xBA, 0xB9, 0xC9, 0x61,
        0xE4, 0x7F, 0x34, 0x3A, 0xCC, 0x8F, 0xF3, 0x0B, 0x6A, 0x62, 0xB4, 0x2B,
        0x5B, 0x59, 0x3E, 0x78, 0xDD, 0xBD, 0x54, 0xDF, 0x6B, 0x09, 0x0B, 0x2F,
        0x66, 0x29, 0x9A, 0x48, 0x0E, 0x52, 0x0A, 0xC9, 0xE2, 0x95, 0x5F, 0x70};

    uint8 chip_id[] = {
        0x20, 0x02, 0x87, 0x46, 0x36, 0xC2, 0x68, 0xB3, 0xBD, 0x52, 0x5B,
        0x42, 0x9D, 0x33, 0x3C, 0x28, 0x27, 0x3C, 0xFC, 0xB6, 0x38, 0x74,
        0xF8, 0xCF, 0xF7, 0x8F, 0xA6, 0x13, 0x88, 0x70, 0x02, 0x99, 0x0E,
        0xFE, 0xC7, 0x0C, 0x4C, 0x53, 0x8B, 0xAC, 0x5E, 0x08, 0x43, 0x71,
        0xF3, 0xD7, 0x66, 0x59, 0x36, 0x0A, 0x8E, 0x51, 0x57, 0xD5, 0xE7,
        0x58, 0x80, 0x57, 0xA7, 0x15, 0xA8, 0x27, 0x2D, 0xBA};

    /*  Set to 2h on SNP specification */
    report->version = 0x02;

    report->guest_svn = 0x00;
    report->policy = 0x30000;
    memset(&report->family_id, 0x00, sizeof(report->family_id));
    memset(&report->image_id, 0x00, sizeof(report->image_id));
    report->vmpl = 0x00;
    report->signature_algo = 0x01;
    report->platform_version.boot_loader = 0x03;
    report->platform_version.microcode = 0x73;
    memset(&report->platform_version.reserved, 0x00,
           sizeof(report->platform_version.reserved));
    report->platform_version.snp = 0x08;
    report->platform_version.tee = 0x00;
    report->platform_info = 0x03;
    report->flags = 0x00;
    report->reserved0 = 0x00;
    memcpy(&report->measurement, measurement, sizeof(measurement));
    memset(&report->report_data, 0x00, sizeof(report->report_data));
    generate_random_array(report->report_id, 32);
    memset(&report->host_data, 0x00, sizeof(report->host_data));
    memset(&report->id_key_digest, 0x00, sizeof(report->id_key_digest));
    memset(&report->author_key_digest, 0x00, sizeof(report->author_key_digest));
    memset(&report->report_id_ma, 0xFF, sizeof(report->report_id_ma));
    report->reported_tcb.boot_loader = 0x03;
    report->reported_tcb.microcode = 0x73;
    memset(&report->reported_tcb.reserved, 0x00,
           sizeof(report->reported_tcb.reserved));
    report->reported_tcb.snp = 0x08;
    report->reported_tcb.tee = 0x00;
    memset(&report->reserved1, 0x00, sizeof(report->reserved1));
    memcpy(report->chip_id, &chip_id, sizeof(chip_id));
    report->current_build = 0x04;
    report->current_minor = 0x34;
    report->current_major = 0x01;
    report->reserved2 = 0x00;
    report->commited_tcb.boot_loader = 0x03;
    report->commited_tcb.microcode = 0x73;
    memset(&report->commited_tcb.reserved, 0x00,
           sizeof(report->commited_tcb.reserved));
    report->commited_tcb.snp = 0x08;
    report->commited_tcb.tee = 0x00;
    report->commited_build = 0x04;
    report->commited_minor = 0x34;
    report->commited_major = 0x01;
    report->reserved3 = 0x00;
    report->launch_tcb.boot_loader = 0x03;
    report->launch_tcb.microcode = 0x73;
    memset(&report->launch_tcb.reserved, 0x00,
           sizeof(report->launch_tcb.reserved));
    report->launch_tcb.snp = 0x08;
    report->launch_tcb.tee = 0x00;
    memset(&report->reserved4, 0x00, sizeof(report->reserved4));
    memset(&report->signature.reserved, 0x00,
           sizeof(report->signature.reserved));
}
