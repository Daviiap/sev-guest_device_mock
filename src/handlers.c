#include "handlers.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "./sev_guest_ioctl.h"
#include "snp/cert-table.h"

char PUBLIC_VCEK_PATH[128] = "/etc/sev-guest/vcek/public.pem";
char PUBLIC_VLEK_PATH[128] = "/etc/sev-guest/vlek/public.pem";

void handle_snp_get_report(fuse_req_t req, int cmd, void *arg,
                           const void *in_buf, size_t in_bufsz) {
    if (in_bufsz == 0) {
        struct iovec in_iov = {arg, sizeof(struct snp_guest_request_ioctl)};
        fuse_reply_ioctl_retry(req, &in_iov, 1, NULL, 0);
        return;
    }

    if (in_bufsz == sizeof(struct snp_guest_request_ioctl)) {
        const struct snp_guest_request_ioctl *ioctl_req =
            (const struct snp_guest_request_ioctl *)in_buf;

        struct iovec in_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(struct snp_report_req)},
        };
        struct iovec out_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->resp_data,
             sizeof(struct snp_report_resp)},
        };
        fuse_reply_ioctl_retry(req, in_iov, 2, out_iov, 2);
        return;
    }

    const struct snp_guest_request_ioctl *ioctl_req =
        (const struct snp_guest_request_ioctl *)in_buf;
    const struct snp_report_req *report_req =
        (const struct snp_report_req *)((const char *)in_buf + sizeof(*ioctl_req));

    struct {
        struct snp_guest_request_ioctl ioctl_out;
        struct snp_report_resp resp_out;
    } out;
    memset(&out, 0, sizeof(out));
    out.ioctl_out = *ioctl_req;
    out.ioctl_out.fw_err = 0;

    struct attestation_report report;
    memset(&report, 0, sizeof(report));
    get_report(&report);

    memcpy(report.report_data, report_req->user_data,
           sizeof(report_req->user_data));
    report.vmpl = report_req->vmpl;

    sign_attestation_report(&report, report_req->key_sel);

    struct msg_report_resp report_resp_msg;
    memset(&report_resp_msg, 0, sizeof(report_resp_msg));
    report_resp_msg.report_size = (int)sizeof(report);
    memcpy(&report_resp_msg.report, &report, sizeof(report));

    memcpy(out.resp_out.data, &report_resp_msg, sizeof(report_resp_msg));

    fuse_reply_ioctl(req, 0, &out, sizeof(out));
}

static size_t get_certs_size(uint32_t key_sel, char *ek_guid, uint8_t **certs_out, uint32_t *certs_len_out) {
    int cert_fd = -1;
    switch (key_sel) {
        case 0:
            cert_fd = open(PUBLIC_VLEK_PATH, O_RDWR);
            if (ek_guid) memcpy(ek_guid, vlek_guid, 37);
            if (cert_fd == -1) {
                cert_fd = open(PUBLIC_VCEK_PATH, O_RDWR);
                if (ek_guid) memcpy(ek_guid, vcek_guid, 37);
            }
            break;
        case 1:
            cert_fd = open(PUBLIC_VCEK_PATH, O_RDWR);
            if (ek_guid) memcpy(ek_guid, vcek_guid, 37);
            break;
        case 2:
            cert_fd = open(PUBLIC_VLEK_PATH, O_RDWR);
            if (ek_guid) memcpy(ek_guid, vlek_guid, 37);
            break;
    }
    if (cert_fd == -1) return 0;

    struct stat stat_buf;
    if (fstat(cert_fd, &stat_buf) == -1) {
        close(cert_fd);
        return 0;
    }

    uint32_t certs_len = (uint32_t)stat_buf.st_size;
    uint8_t *certs = malloc(certs_len);
    if (read(cert_fd, certs, certs_len) != certs_len) {
        free(certs);
        close(cert_fd);
        return 0;
    }
    close(cert_fd);

    if (certs_out) *certs_out = certs;
    else free(certs);

    if (certs_len_out) *certs_len_out = certs_len;

    struct cert_table table;
    cert_table_alloc(&table, 1);
    cert_table_add_entry(&table, ek_guid, certs_len);
    size_t total_size = cert_table_get_size(&table) + certs_len;
    cert_table_free(&table);

    return total_size;
}

void handle_snp_get_ext_report(fuse_req_t req, int cmd, void *arg,
                               const void *in_buf, size_t in_bufsz) {
    if (in_bufsz == 0) {
        struct iovec in_iov = {arg, sizeof(struct snp_guest_request_ioctl)};
        fuse_reply_ioctl_retry(req, &in_iov, 1, NULL, 0);
        return;
    }

    if (in_bufsz == sizeof(struct snp_guest_request_ioctl)) {
        const struct snp_guest_request_ioctl *ioctl_req =
            (const struct snp_guest_request_ioctl *)in_buf;

        struct iovec in_iov[2] = {
            {arg, sizeof(struct snp_guest_request_ioctl)},
            {(void *)(uintptr_t)ioctl_req->req_data, sizeof(struct snp_ext_report_req)},
        };
        fuse_reply_ioctl_retry(req, in_iov, 2, NULL, 0);
        return;
    }

    const struct snp_guest_request_ioctl *ioctl_req =
        (const struct snp_guest_request_ioctl *)in_buf;
    const struct snp_ext_report_req *ext_req =
        (const struct snp_ext_report_req *)((const char *)in_buf + sizeof(*ioctl_req));

    if (in_bufsz == sizeof(*ioctl_req) + sizeof(*ext_req)) {
        size_t total_certs_size = get_certs_size(ext_req->data.key_sel, NULL, NULL, NULL);

        if (ext_req->certs_len < total_certs_size) {
            struct iovec in_iov[3] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
                {(void *)(uintptr_t)ioctl_req->resp_data, 1} /* Phase 4a marker */
            };
            struct iovec out_iov[2] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)}
            };
            fuse_reply_ioctl_retry(req, in_iov, 3, out_iov, 2);
            return;
        } else {
            struct iovec in_iov[3] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
                {(void *)(uintptr_t)ioctl_req->resp_data, sizeof(struct snp_report_resp)} /* Phase 4b marker */
            };
            struct iovec out_iov[4] = {
                {arg, sizeof(*ioctl_req)},
                {(void *)(uintptr_t)ioctl_req->req_data, sizeof(*ext_req)},
                {(void *)(uintptr_t)ioctl_req->resp_data, sizeof(struct snp_report_resp)},
                {(void *)(uintptr_t)ext_req->certs_address, total_certs_size}
            };
            fuse_reply_ioctl_retry(req, in_iov, 3, out_iov, 4);
            return;
        }
    }

    if (in_bufsz == sizeof(*ioctl_req) + sizeof(*ext_req) + 1) {
        /* Phase 4a: Error Phase - Buffer too small */
        size_t total_certs_size = get_certs_size(ext_req->data.key_sel, NULL, NULL, NULL);

        struct {
            struct snp_guest_request_ioctl ioctl_out;
            struct snp_ext_report_req ext_out;
        } out;
        memset(&out, 0, sizeof(out));
        out.ioctl_out = *ioctl_req;
        out.ioctl_out.fw_err = 1; /* SNP_GUEST_VMM_ERR_INVALID_LEN */
        out.ext_out = *ext_req;
        out.ext_out.certs_len = total_certs_size;

        fuse_reply_ioctl(req, 0, &out, sizeof(out));
        return;
    }

    if (in_bufsz == sizeof(*ioctl_req) + sizeof(*ext_req) + sizeof(struct snp_report_resp)) {
        /* Phase 4b: Success Phase - Write report and certs */
        char ek_guid[37] = {0};
        uint8_t *certs = NULL;
        uint32_t certs_len = 0;
        size_t total_certs_size = get_certs_size(ext_req->data.key_sel, ek_guid, &certs, &certs_len);

        struct cert_table table;
        cert_table_alloc(&table, 1);
        cert_table_add_entry(&table, ek_guid, certs_len);

        uint8_t *certs_buffer = calloc(1, total_certs_size);
        memcpy(certs_buffer, &table.entry[0], sizeof(struct cert_table_entry));
        cert_table_append_cert(&table, certs_buffer, total_certs_size, ek_guid, certs, certs_len);

        cert_table_free(&table);
        if (certs) free(certs);

        struct attestation_report report;
        memset(&report, 0, sizeof(report));
        get_report(&report);
        memcpy(report.report_data, ext_req->data.user_data, sizeof(ext_req->data.user_data));
        report.vmpl = ext_req->data.vmpl;
        sign_attestation_report(&report, ext_req->data.key_sel);

        struct msg_report_resp report_resp_msg;
        memset(&report_resp_msg, 0, sizeof(report_resp_msg));
        report_resp_msg.report_size = (int)sizeof(report);
        memcpy(&report_resp_msg.report, &report, sizeof(report));

        size_t out_sz = sizeof(*ioctl_req) + sizeof(*ext_req) + sizeof(struct snp_report_resp) + total_certs_size;
        void *out_buf = calloc(1, out_sz);
        char *p = out_buf;

        struct snp_guest_request_ioctl ioctl_out = *ioctl_req;
        ioctl_out.fw_err = 0;
        memcpy(p, &ioctl_out, sizeof(ioctl_out)); p += sizeof(ioctl_out);

        struct snp_ext_report_req ext_out = *ext_req;
        ext_out.certs_len = total_certs_size;
        memcpy(p, &ext_out, sizeof(ext_out)); p += sizeof(ext_out);

        struct snp_report_resp resp_out;
        memset(&resp_out, 0, sizeof(resp_out));
        memcpy(resp_out.data, &report_resp_msg, sizeof(report_resp_msg));
        memcpy(p, &resp_out, sizeof(resp_out)); p += sizeof(resp_out);

        memcpy(p, certs_buffer, total_certs_size);

        fuse_reply_ioctl(req, 0, out_buf, out_sz);
        free(out_buf);
        free(certs_buffer);
        return;
    }

    fuse_reply_err(req, EINVAL);
}
