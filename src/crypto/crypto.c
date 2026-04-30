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

int sign_attestation_report(struct attestation_report* report, __u32 key_sel) {
    unsigned char* data = (unsigned char*)report;

    EVP_PKEY* eckey = read_ek(key_sel);
    if (eckey == NULL) {
        fprintf(stderr, "Error loading key\n");
        return -1;
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
        return -1;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, eckey) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignInit\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return -1;
    }

    if (EVP_DigestSignUpdate(mdctx, hash, SHA384_DIGEST_LENGTH) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignUpdate\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return -1;
    }

    size_t sig_len;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        fprintf(stderr, "Error determining signature length\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return -1;
    }
    
    unsigned char* signature = OPENSSL_malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Error allocating memory for signature\n");
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return -1;
    }

    if (EVP_DigestSignFinal(mdctx, signature, &sig_len) != 1) {
        fprintf(stderr, "Error in EVP_DigestSignFinal\n");
        OPENSSL_free(signature);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(eckey);
        return -1;
    }

    // Assuming signature is split into two parts: R and S, equally
    size_t half_sig_len = sig_len / 2;
    memcpy(report->signature.r, signature, half_sig_len);
    memcpy(report->signature.s, signature + half_sig_len, half_sig_len);

    OPENSSL_free(signature);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(eckey);
    return 0;
}
