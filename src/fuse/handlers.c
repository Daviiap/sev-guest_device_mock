#include "handlers.h"

#include <errno.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto/crypto.h"
#include "../snp/cert-table.h"
#include "../snp/report.h"
#include "../snp/sev-guest.h"

#define MAX_VMPL 3
#define MAX_CERTS 3 /* endorsement key, ASK, ARK */

/* MSG_REPORT_RSP status for invalid request parameters (SNP firmware ABI). */
#define MSG_REPORT_STATUS_INVALID_PARAM 0x16

/*
 * exitinfo2 value the kernel reports when the certificate buffer is too small:
 * SNP_GUEST_VMM_ERR(SNP_GUEST_VMM_ERR_INVALID_LEN), i.e. the VMM error lives
 * in the upper 32 bits.
 */
#define SNP_GUEST_VMM_ERR_INVALID_LEN (1ULL << 32)

char PUBLIC_VCEK_PATH[128] = "/etc/sev-guest/vcek/public.pem";
char PUBLIC_VLEK_PATH[128] = "/etc/sev-guest/vlek/public.pem";
char CERT_CHAIN_VCEK_PATH[128] = "/etc/sev-guest/vcek/cert_chain.pem";
char CERT_CHAIN_VLEK_PATH[128] = "/etc/sev-guest/vlek/cert_chain.pem";

static int is_zeroed(const __u8 *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i]) return 0;
    }
    return 1;
}

/*
 * Fills resp with a MSG_REPORT_RSP for rreq. Invalid parameters are reported
 * through the status field, as the firmware does. Returns 0 or -errno.
 */
static int build_report_resp(const struct snp_report_req *rreq,
                             struct snp_report_resp *resp) {
    struct msg_report_resp msg;
    memset(&msg, 0, sizeof(msg));

    int key_sel = resolve_key_sel(rreq->key_sel);
    if (rreq->vmpl > MAX_VMPL || key_sel < 0 ||
        !is_zeroed(rreq->rsvd, sizeof(rreq->rsvd))) {
        printf("[debug] invalid report request (key_sel=%u, vmpl=%u)\n",
               rreq->key_sel, rreq->vmpl);
        msg.status = MSG_REPORT_STATUS_INVALID_PARAM;
    } else {
        if (get_report(&msg.report) != 0) return -EIO;

        memcpy(msg.report.report_data, rreq->user_data, sizeof(rreq->user_data));
        msg.report.vmpl = rreq->vmpl;

        if (sign_attestation_report(&msg.report, key_sel) != 0) {
            fprintf(stderr, "[error] sign_attestation_report failed\n");
            return -EIO;
        }
        msg.report_size = sizeof(msg.report);
        printf("[debug] report generated and signed (key_sel=%u, vmpl=%u)\n",
               rreq->key_sel, rreq->vmpl);
    }

    memset(resp, 0, sizeof(*resp));
    memcpy(resp->data, &msg, sizeof(msg));
    return 0;
}

void handle_snp_get_report(fuse_req_t req, void *arg,
                           const void *in_buf, size_t in_bufsz) {
    if (in_bufsz == 0) {
        struct iovec in_iov = {arg, sizeof(struct snp_guest_request_ioctl)};
        fuse_reply_ioctl_retry(req, &in_iov, 1, NULL, 0);
        return;
    }

    const struct snp_guest_request_ioctl *ioctl_req = in_buf;

    if (in_bufsz == sizeof(*ioctl_req)) {
        struct iovec in_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(struct snp_report_req)},
        };
        struct iovec out_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->resp_data, sizeof(struct snp_report_resp)},
        };
        fuse_reply_ioctl_retry(req, in_iov, 2, out_iov, 2);
        return;
    }

    if (in_bufsz != sizeof(*ioctl_req) + sizeof(struct snp_report_req)) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    const struct snp_report_req *report_req =
        (const struct snp_report_req *)((const char *)in_buf + sizeof(*ioctl_req));

    struct {
        struct snp_guest_request_ioctl ioctl_out;
        struct snp_report_resp resp_out;
    } out;
    memset(&out, 0, sizeof(out));
    out.ioctl_out = *ioctl_req;
    out.ioctl_out.fw_err = 0;

    int err = build_report_resp(report_req, &out.resp_out);
    if (err) {
        fuse_reply_err(req, -err);
        return;
    }

    fuse_reply_ioctl(req, 0, &out, sizeof(out));
}

/* Reads every certificate of a PEM file. Returns the number of certs read. */
static int read_pem_certs(const char *path, X509 **certs, int max) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    int n = 0;
    while (n < max) {
        X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
        if (!cert) break;
        certs[n++] = cert;
    }
    fclose(fp);
    return n;
}

/*
 * Builds the GHCB certificate blob (cert table followed by DER certificates)
 * for the given endorsement key: the VCEK/VLEK plus the ASK and ARK of its
 * chain, as a real host provides. On success *blob is malloc'ed and must be
 * freed. An endorsement key certificate that cannot be read yields an empty
 * blob, like a host that has no certificates loaded.
 */
static int build_cert_blob(int key_sel, uint8_t **blob, size_t *blob_len) {
    const char *ek_path = key_sel == KEY_SEL_VLEK ? PUBLIC_VLEK_PATH : PUBLIC_VCEK_PATH;
    const char *chain_path = key_sel == KEY_SEL_VLEK ? CERT_CHAIN_VLEK_PATH : CERT_CHAIN_VCEK_PATH;
    const char *ek_guid = key_sel == KEY_SEL_VLEK ? vlek_guid : vcek_guid;

    const char *guids[MAX_CERTS];
    unsigned char *ders[MAX_CERTS] = {0};
    int der_lens[MAX_CERTS] = {0};
    size_t nr_certs = 0;
    struct cert_table table = {0};
    int ret = -EIO;

    *blob = NULL;
    *blob_len = 0;

    X509 *ek = NULL;
    if (read_pem_certs(ek_path, &ek, 1) != 1) {
        fprintf(stderr, "[warn] could not read %s, returning no certificates\n", ek_path);
        return 0;
    }
    guids[nr_certs] = ek_guid;
    der_lens[nr_certs] = i2d_X509(ek, &ders[nr_certs]);
    nr_certs++;
    X509_free(ek);

    X509 *chain[MAX_CERTS] = {0};
    int chain_len = read_pem_certs(chain_path, chain, MAX_CERTS);
    for (int i = 0; i < chain_len; i++) {
        if (nr_certs < MAX_CERTS) {
            int self_signed = X509_check_issued(chain[i], chain[i]) == X509_V_OK;
            guids[nr_certs] = self_signed ? ark_guid : ask_guid;
            der_lens[nr_certs] = i2d_X509(chain[i], &ders[nr_certs]);
            nr_certs++;
        }
        X509_free(chain[i]);
    }

    for (size_t i = 0; i < nr_certs; i++) {
        if (der_lens[i] <= 0) goto out;
    }

    if (cert_table_alloc(&table, nr_certs) != 0) goto out;
    for (size_t i = 0; i < nr_certs; i++) {
        if (cert_table_add_entry(&table, guids[i], der_lens[i]) != 0) goto out;
    }

    size_t certs_size = 0;
    if (cert_table_get_certs_size(&table, &certs_size) != 0) goto out;
    size_t total = cert_table_get_size(&table) + certs_size;

    uint8_t *buf = calloc(1, total);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }
    if (cert_table_copy(&table, buf, total) != 0) {
        free(buf);
        goto out;
    }
    for (size_t i = 0; i < nr_certs; i++) {
        if (cert_table_append_cert(&table, buf, total, guids[i], ders[i], der_lens[i]) != 0) {
            free(buf);
            goto out;
        }
    }

    *blob = buf;
    *blob_len = total;
    ret = 0;
out:
    cert_table_free(&table);
    for (size_t i = 0; i < nr_certs; i++) OPENSSL_free(ders[i]);
    return ret;
}

/* Size of the certificate blob for an extended report request (0 when none). */
static size_t ext_report_certs_size(const struct snp_ext_report_req *ext_req) {
    int key_sel = resolve_key_sel(ext_req->data.key_sel);
    if (key_sel < 0) return 0;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    if (build_cert_blob(key_sel, &blob, &blob_len) != 0) return 0;
    free(blob);
    return blob_len;
}

/*
 * Replies that the certificate buffer is too small: the ioctl fails with EIO,
 * fw_err carries the VMM error and certs_len the required size.
 */
static void reply_certs_too_small(fuse_req_t req,
                                  const struct snp_guest_request_ioctl *ioctl_req,
                                  const struct snp_ext_report_req *ext_req,
                                  size_t certs_size) {
    struct {
        struct snp_guest_request_ioctl ioctl_out;
        struct snp_ext_report_req ext_out;
    } out;
    memset(&out, 0, sizeof(out));
    out.ioctl_out = *ioctl_req;
    out.ioctl_out.fw_err = SNP_GUEST_VMM_ERR_INVALID_LEN;
    out.ext_out = *ext_req;
    out.ext_out.certs_len = certs_size;

    fuse_reply_ioctl(req, -EIO, &out, sizeof(out));
}

/*
 * SNP_GET_EXT_REPORT is served in phases, each one a retry that asks the
 * kernel for more of the caller's memory. in_bufsz tells the phases apart:
 *   0                          -> fetch the ioctl struct
 *   ioctl                      -> fetch the ext request
 *   ioctl + ext_req            -> decide whether the cert buffer is big enough
 *   ioctl + ext_req + 1        -> buffer too small: report the required size
 *   ioctl + ext_req + resp     -> write the report and the certificates
 */
void handle_snp_get_ext_report(fuse_req_t req, void *arg,
                               const void *in_buf, size_t in_bufsz) {
    if (in_bufsz == 0) {
        struct iovec in_iov = {arg, sizeof(struct snp_guest_request_ioctl)};
        fuse_reply_ioctl_retry(req, &in_iov, 1, NULL, 0);
        return;
    }

    const struct snp_guest_request_ioctl *ioctl_req = in_buf;

    if (in_bufsz == sizeof(*ioctl_req)) {
        struct iovec in_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(struct snp_ext_report_req)},
        };
        fuse_reply_ioctl_retry(req, in_iov, 2, NULL, 0);
        return;
    }

    const size_t req_size = sizeof(*ioctl_req) + sizeof(struct snp_ext_report_req);
    if (in_bufsz < req_size) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    const struct snp_ext_report_req *ext_req =
        (const struct snp_ext_report_req *)((const char *)in_buf + sizeof(*ioctl_req));

    if (in_bufsz == req_size) {
        size_t certs_size = ext_report_certs_size(ext_req);

        if (ext_req->certs_len < certs_size) {
            printf("[debug] EXT_REPORT: certs_len (%u) is smaller than required (%zu)\n",
                   ext_req->certs_len, certs_size);
            struct iovec in_iov[3] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
                {(void *)(uintptr_t)ioctl_req->resp_data, 1} /* "too small" phase marker */
            };
            struct iovec out_iov[2] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)}
            };
            fuse_reply_ioctl_retry(req, in_iov, 3, out_iov, 2);
            return;
        }

        struct iovec in_iov[3] = {
            {arg, sizeof(*ioctl_req)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
            {(void *)(uintptr_t)ioctl_req->resp_data, sizeof(struct snp_report_resp)} /* "report" phase marker */
        };
        struct iovec out_iov[4] = {
            {arg, sizeof(*ioctl_req)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
            {(void *)(uintptr_t)ioctl_req->resp_data, sizeof(struct snp_report_resp)},
            {(void *)(uintptr_t)ext_req->certs_address, certs_size}
        };
        fuse_reply_ioctl_retry(req, in_iov, 3, out_iov, certs_size ? 4 : 3);
        return;
    }

    if (in_bufsz == req_size + 1) {
        reply_certs_too_small(req, ioctl_req, ext_req, ext_report_certs_size(ext_req));
        return;
    }

    if (in_bufsz != req_size + sizeof(struct snp_report_resp)) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    uint8_t *certs = NULL;
    size_t certs_size = 0;
    int key_sel = resolve_key_sel(ext_req->data.key_sel);
    if (key_sel >= 0) {
        int err = build_cert_blob(key_sel, &certs, &certs_size);
        if (err) {
            fuse_reply_err(req, -err);
            return;
        }
    }

    /* The certificates changed since the size was checked. */
    if (certs_size > ext_req->certs_len) {
        reply_certs_too_small(req, ioctl_req, ext_req, certs_size);
        free(certs);
        return;
    }

    size_t out_sz = req_size + sizeof(struct snp_report_resp) + certs_size;
    char *out_buf = calloc(1, out_sz);
    if (!out_buf) {
        free(certs);
        fuse_reply_err(req, ENOMEM);
        return;
    }
    char *p = out_buf;

    struct snp_guest_request_ioctl *ioctl_out = (struct snp_guest_request_ioctl *)p;
    *ioctl_out = *ioctl_req;
    ioctl_out->fw_err = 0;
    p += sizeof(*ioctl_out);

    struct snp_ext_report_req *ext_out = (struct snp_ext_report_req *)p;
    *ext_out = *ext_req;
    ext_out->certs_len = certs_size;
    p += sizeof(*ext_out);

    int err = build_report_resp(&ext_req->data, (struct snp_report_resp *)p);
    p += sizeof(struct snp_report_resp);

    if (err) {
        fuse_reply_err(req, -err);
    } else {
        if (certs_size) memcpy(p, certs, certs_size);
        fuse_reply_ioctl(req, 0, out_buf, out_sz);
    }

    free(out_buf);
    free(certs);
}
