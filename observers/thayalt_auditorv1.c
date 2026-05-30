/* ============================================================
 * THAYALT_AUDITOR.C — LEDGER CONTRACT AUDITOR
 *
 * Connects to a THAYALT sentinel, validates the ledger
 * certificate, then enforces a contract against every frame
 * in the binary ledger produced by thayalt_core.
 *
 * ============================================================
 * BUG-FIX LOG (audited):
 *
 * FIX-1  handshake_request_t: added __attribute__((packed)) and
 *        corrected reserved[] from [55] to [54].
 *        Without packed, the compiler inserts 7 bytes of implicit
 *        padding before ledger_id (uint64_t), making sizeof == 72.
 *        With packed but reserved[55], sizeof == 65.  The correct
 *        layout is auditor_id(1) + ledger_id(8) + policy_version(1)
 *        + reserved(54) = 64 bytes exactly.
 *        The receiver on the other end of the wire now sees the
 *        correct ledger_id and policy_version.
 *
 * FIX-2  sentinel_receive_response: changed return type from
 *        int to ssize_t to match the declaration used by the
 *        caller.  The caller stored the result in ssize_t and
 *        compared it to sizeof(resp) (size_t).  Returning int
 *        caused a signed/unsigned mismatch and would truncate
 *        on any platform where sizeof(resp) > INT_MAX.
 *
 * FIX-3  enforce_contract: added ferror(fp) check after the
 *        fread loop.  fread returns 0 on both EOF and I/O
 *        error; without the check a mid-ledger read failure is
 *        silently treated as clean EOF and the audit passes on
 *        partial data.  We now return a sentinel result with
 *        violations = UINT64_MAX to force a hard FAIL.
 *
 * FIX-4  Post-audit integrity cross-check: after enforce_
 *        contract, result.checked is compared against
 *        cert.frame_count, and the last observed sequence_id
 *        is compared against cert.last_sequence.  A truncated,
 *        padded, or mismatched ledger previously passed
 *        silently; it now fails with an explicit message.
 *
 * FIX-5  Sequence continuity check in enforce_contract: the
 *        auditor now verifies that each frame's sequence_id is
 *        exactly prev+1.  Gaps or duplicates are counted as
 *        violations and reported in the audit result.
 *
 * FIX-6  Format strings: replaced %lu with the portable
 *        PRIu64 specifier (from <inttypes.h>) for all
 *        uint64_t fields.  %lu is correct on LP64 Linux but
 *        wrong on LLP64 (Windows) and produces -Wformat
 *        warnings with strict compilers.
 *
 * ============================================================ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>   /* PRIu64 — FIX-6 */

/* ============================================================
   FRAME DEFINITION (must match kernel + sentinel exactly)
   ============================================================ */
typedef struct {
    uint64_t sequence_id;
    uint64_t timestamp;
    uint32_t sensor_id;
    uint32_t metric_value;
    uint8_t  active_regime;
    uint8_t  pressure_ratio;
    uint8_t  reserved[70];
    uint8_t  block_hash[32];
} __attribute__((packed, aligned(128))) thayalt_stride_t;

_Static_assert(sizeof(thayalt_stride_t) == 128, "Frame mismatch");

/* ============================================================
   SENTINEL CERTIFICATE (trusted input)
   ============================================================ */
typedef struct {
    uint64_t ledger_hash_root;
    uint64_t frame_count;
    uint64_t last_sequence;
    uint8_t  integrity_score;
    uint8_t  valid;
    uint8_t  reserved[14];
} sentinel_certificate_t;

/* ============================================================
   HANDSHAKE PROTOCOL STRUCTURES
   ============================================================ */
/* FIX-1: added __attribute__((packed)) and corrected reserved[] size.
 * Without packed, 7 bytes of implicit padding before ledger_id makes
 * sizeof == 72.  With packed but reserved[55], sizeof == 65.  The
 * correct packed layout is:
 *   auditor_id(1) + ledger_id(8) + policy_version(1) + reserved(54) = 64
 * reserved[] is zero-initialised by C partial-initialisation rules
 * when the struct is built with a designated-initialiser list. */
typedef struct {
    uint8_t  auditor_id;
    uint64_t ledger_id;
    uint8_t  policy_version;
    uint8_t  reserved[54];   /* was [55] — off by one once packed */
} __attribute__((packed)) handshake_request_t;

_Static_assert(sizeof(handshake_request_t) == 64, "handshake_request_t wire size");

typedef struct {
    uint8_t  sentinel_id;
    uint8_t  status; /* 1 = OK, 0 = REJECT */
    sentinel_certificate_t cert;
} handshake_response_t;

/* ============================================================
   CONTRACT MODEL
   ============================================================ */
typedef struct {
    float speed_limit_kmh;
    uint8_t require_limiter_signal;
    uint8_t min_integrity_score;
} contract_t;

/* Default contract */
static contract_t default_contract = {
    .speed_limit_kmh     = 80.0f,
    .require_limiter_signal = 1,
    .min_integrity_score = 90
};

/* ============================================================
   AUDITOR STATE MACHINE
   ============================================================ */
typedef enum {
    AUD_IDLE = 0,
    AUD_REQUEST_SENT,
    AUD_CERT_RECEIVED,
    AUD_REJECTED
} auditor_state_t;

static auditor_state_t state = AUD_IDLE;

/* ============================================================
   MOCKED SENTINEL INTERFACE (replace with IPC / socket / hw)
   ============================================================ */
int sentinel_send_handshake(void *req, size_t len);
/* FIX-2: return type changed from int to ssize_t.
 * The caller stores the result in ssize_t and compares it to
 * sizeof(resp) (size_t); returning int caused a signed/unsigned
 * mismatch and would truncate on platforms where sizeof > INT_MAX. */
ssize_t sentinel_receive_response(void *resp, size_t len);

/* ============================================================
   CERTIFICATE VALIDATION
   ============================================================ */
static bool validate_certificate(const sentinel_certificate_t *c,
                                  const contract_t *contract) {
    if (!c->valid)                                       return false;
    if (c->integrity_score < contract->min_integrity_score) return false;
    if (c->frame_count == 0)                             return false;
    return true;
}

/* ============================================================
   HANDSHAKE INITIATION
   ============================================================ */
static int auditor_request_certificate(uint64_t ledger_id) {
    handshake_request_t req = {
        .auditor_id     = 1,
        .ledger_id      = ledger_id,
        .policy_version = 1
        /* reserved[55] zero-initialised by partial-init rules */
    };
    state = AUD_REQUEST_SENT;
    return sentinel_send_handshake(&req, sizeof(req));
}

/* ============================================================
   HANDSHAKE RESPONSE HANDLER
   ============================================================ */
static int auditor_receive_certificate(sentinel_certificate_t *out,
                                        const contract_t *contract) {
    handshake_response_t resp;
    /* FIX-2: ssize_t return; comparison against sizeof(resp) is now
     * a signed-vs-unsigned comparison between matching-width types. */
    ssize_t r = sentinel_receive_response(&resp, sizeof(resp));
    if (r != (ssize_t)sizeof(resp)) { state = AUD_REJECTED; return -1; }
    if (resp.status == 0)           { state = AUD_REJECTED; return -2; }
    if (!validate_certificate(&resp.cert, contract)) {
        state = AUD_REJECTED;
        return -3;
    }
    memcpy(out, &resp.cert, sizeof(*out));
    state = AUD_CERT_RECEIVED;
    return 0;
}

/* ============================================================
   LEDGER CONTRACT ENFORCEMENT
   ============================================================ */
typedef struct {
    uint64_t violations;       /* contract + continuity violations */
    uint64_t checked;          /* frames successfully read */
    float    max_speed;
    uint64_t last_sequence_id; /* sequence_id of the last frame read */
    bool     io_error;         /* FIX-3: true if fread aborted on error */
} audit_result_t;

static audit_result_t enforce_contract(FILE *fp, const contract_t *c) {
    audit_result_t r = { .last_sequence_id = UINT64_MAX };
    thayalt_stride_t f;
    bool first_frame = true;

    while (fread(&f, sizeof(f), 1, fp) == 1) {

        /* FIX-5: Sequence continuity check.
         * Each frame must have sequence_id == previous + 1.
         * Gaps or duplicates are logged as violations. */
        if (!first_frame && f.sequence_id != r.last_sequence_id + 1) {
            fprintf(stderr,
                "[AUDIT WARN] Sequence gap: expected %" PRIu64
                " got %" PRIu64 "\n",
                r.last_sequence_id + 1, f.sequence_id);
            r.violations++;
        }
        first_frame = false;
        r.last_sequence_id = f.sequence_id;

        r.checked++;

        float speed = (float)f.metric_value / 100.0f;
        if (speed > r.max_speed) r.max_speed = speed;

        uint8_t limiter_active = f.reserved[0] & 1;

        if (c->require_limiter_signal &&
            speed > c->speed_limit_kmh &&
            !limiter_active) {
            r.violations++;
        }
    }

    /* FIX-3: Distinguish clean EOF from I/O error.
     * fread returns 0 on both; ferror() tells us which.
     * On error we poison the result so the audit always fails. */
    if (ferror(fp)) {
        fprintf(stderr, "[AUDIT ERR] fread error after %" PRIu64
                        " frames — audit result is unreliable\n", r.checked);
        r.io_error = true;
        r.violations = UINT64_MAX; /* force FAIL */
    }

    return r;
}

/* ============================================================
   MAIN AUDITOR PIPELINE
   ============================================================ */
int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ledger.bin>\n", argv[0]);
        return 1;
    }

    const char *ledger_path = argv[1];
    contract_t contract = default_contract;

    /* ================================
       1. HANDSHAKE PHASE
       ================================ */
    uint64_t ledger_id = 1;
    sentinel_certificate_t cert;

    if (auditor_request_certificate(ledger_id) != 0) {
        fprintf(stderr, "Handshake request failed\n");
        return 1;
    }

    int rc = auditor_receive_certificate(&cert, &contract);
    if (rc != 0) {
        fprintf(stderr, "Certificate rejected (code=%d)\n", rc);
        return 2;
    }

    printf("✓ Ledger certified\n");
    printf("  integrity_score=%" PRIu8  "\n", cert.integrity_score); /* FIX-6 */
    printf("  frame_count    =%" PRIu64 "\n", cert.frame_count);
    printf("  last_sequence  =%" PRIu64 "\n", cert.last_sequence);

    /* ================================
       2. LEDGER ACCESS PHASE
       ================================ */
    FILE *fp = fopen(ledger_path, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open ledger: %s\n", strerror(errno));
        return 3;
    }

    /* ================================
       3. CONTRACT ENFORCEMENT PHASE
       ================================ */
    audit_result_t result = enforce_contract(fp, &contract);
    fclose(fp);

    /* ================================
       4. POST-AUDIT INTEGRITY CHECKS
       ================================ */
    /* FIX-4a: Cross-check actual frame count against certified count.
     * A truncated or padded ledger previously passed silently. */
    if (result.checked != cert.frame_count) {
        fprintf(stderr,
            "[INTEGRITY FAIL] Frame count mismatch: "
            "certified=%" PRIu64 " actual=%" PRIu64 "\n",
            cert.frame_count, result.checked);
        result.violations++;
    }

    /* FIX-4b: Cross-check last sequence_id against certified value.
     * Ensures the ledger covers the exact range the sentinel signed. */
    if (result.checked > 0 &&
        result.last_sequence_id != cert.last_sequence) {
        fprintf(stderr,
            "[INTEGRITY FAIL] Last sequence mismatch: "
            "certified=%" PRIu64 " actual=%" PRIu64 "\n",
            cert.last_sequence, result.last_sequence_id);
        result.violations++;
    }

    /* ================================
       5. FINAL VERDICT
       ================================ */
    printf("\n========================\n");
    printf("AUDIT COMPLETE\n");
    printf("========================\n");
    printf("Frames checked : %" PRIu64  "\n", result.checked);     /* FIX-6 */
    printf("Max speed      : %.2f km/h\n",    result.max_speed);
    printf("Violations     : %" PRIu64  "\n", result.violations);  /* FIX-6 */

    if (result.violations == 0) {
        printf("STATUS         : PASS\n");
        return 0;
    } else {
        printf("STATUS         : FAIL\n");
        return 4;
    }
}

/* ============================================================
   MOCK IMPLEMENTATIONS (replace with real IPC later)
   ============================================================ */
int sentinel_send_handshake(void *req, size_t len) {
    (void)req; (void)len;
    /* In real system: send via socket / bus / shared memory */
    return 0;
}

/* FIX-2: return type is now ssize_t */
ssize_t sentinel_receive_response(void *resp, size_t len) {
    (void)len;

    sentinel_certificate_t cert = {
        .ledger_hash_root = 0xABCDEF,
        .frame_count      = 1000,
        .last_sequence    = 999,
        .integrity_score  = 95,
        .valid            = 1
        /* reserved[14] zero-initialised */
    };

    handshake_response_t r = {
        .sentinel_id = 1,
        .status      = 1,
        .cert        = cert
    };

    memcpy(resp, &r, sizeof(r));
    return (ssize_t)sizeof(r);
}