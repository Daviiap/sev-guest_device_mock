#include "crypto.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIGNING_KEY_MASK (0x7u << 2)
#define SIGNING_KEY_VLEK (0x1u << 2)

char PRIVATE_VCEK_PATH[128] = "/etc/sev-guest/vcek/private.pem";
char PRIVATE_VLEK_PATH[128] = "/etc/sev-guest/vlek/private.pem";

EVP_PKEY* read_ecdsa_key_from_file(const char* key_file) {
    FILE* key_fp = fopen(key_file, "r");
    if (key_fp == NULL) {
        fprintf(stderr, "Error opening key file %s\n", key_file);
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
    fclose(key_fp);

    if (pkey == NULL) {
        fprintf(stderr, "Error reading ECDSA key from file %s\n", key_file);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return pkey;
}

static int is_vlek_present() { return access(PRIVATE_VLEK_PATH, F_OK) == 0; }

int resolve_key_sel(__u32 key_sel) {
    switch (key_sel) {
        case KEY_SEL_DEFAULT:
            return is_vlek_present() ? KEY_SEL_VLEK : KEY_SEL_VCEK;
        case KEY_SEL_VCEK:
        case KEY_SEL_VLEK:
            return (int)key_sel;
        default:
            return -1;
    }
}

static EVP_PKEY* read_ek(int resolved_key_sel) {
    switch (resolved_key_sel) {
        case KEY_SEL_VCEK:
            return read_ecdsa_key_from_file(PRIVATE_VCEK_PATH);
        case KEY_SEL_VLEK:
            return read_ecdsa_key_from_file(PRIVATE_VLEK_PATH);
        default:
            return NULL;
    }
}

/* Writes a big-endian integer into a little-endian, zero-padded field. */
static int bn_to_le_field(const BIGNUM* bn, uint8* field, size_t field_size) {
    int len = BN_num_bytes(bn);
    if (len < 0 || (size_t)len > field_size) {
        return -1;
    }

    unsigned char be[72];
    BN_bn2bin(bn, be);

    memset(field, 0, field_size);
    for (int i = 0; i < len; i++) {
        field[i] = be[len - 1 - i];
    }
    return 0;
}

int sign_attestation_report(struct attestation_report* report, int resolved_key_sel) {
    int ret = -1;
    EVP_MD_CTX* mdctx = NULL;
    unsigned char* signature = NULL;
    ECDSA_SIG* ecdsa_sig = NULL;

    EVP_PKEY* eckey = read_ek(resolved_key_sel);
    if (eckey == NULL) {
        fprintf(stderr, "Error reading endorsement key\n");
        return -1;
    }

    /* flags[4:2] is SIGNING_KEY: 0 = VCEK, 1 = VLEK */
    report->flags &= ~SIGNING_KEY_MASK;
    if (resolved_key_sel == KEY_SEL_VLEK) {
        report->flags |= SIGNING_KEY_VLEK;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Error creating EVP_MD_CTX\n");
        goto out;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, eckey) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignInit\n");
        goto out;
    }

    size_t data_len = sizeof(struct attestation_report) - sizeof(struct signature);
    if (EVP_DigestSignUpdate(mdctx, report, data_len) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignUpdate\n");
        goto out;
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "Error determining signature length\n");
        goto out;
    }

    signature = OPENSSL_malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Error allocating memory for signature\n");
        goto out;
    }

    if (EVP_DigestSignFinal(mdctx, signature, &sig_len) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignFinal\n");
        goto out;
    }

    const unsigned char* p = signature;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);
    if (!ecdsa_sig) {
        fprintf(stderr, "Error decoding ECDSA signature\n");
        goto out;
    }

    if (bn_to_le_field(ECDSA_SIG_get0_r(ecdsa_sig), report->signature.r, sizeof(report->signature.r)) != 0 ||
        bn_to_le_field(ECDSA_SIG_get0_s(ecdsa_sig), report->signature.s, sizeof(report->signature.s)) != 0) {
        fprintf(stderr, "ECDSA signature component too large\n");
        goto out;
    }

    ret = 0;
out:
    ECDSA_SIG_free(ecdsa_sig);
    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(eckey);
    return ret;
}
