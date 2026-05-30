#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

/* ----------------------------
   SHA-256 (self-contained, same as kernel)
---------------------------- */
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ror(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16)
             | ((uint32_t)data[j+2] << 8) | (uint32_t)data[j+3];
    for (; i < 64; ++i)
        m[i] = m[i-16] + (ror(m[i-15],7) ^ ror(m[i-15],18) ^ (m[i-15]>>3))
               + m[i-7] + (ror(m[i-2],17) ^ ror(m[i-2],19) ^ (m[i-2]>>10));
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + (ror(e,6) ^ ror(e,11) ^ ror(e,25)) + ((e & f) ^ (~e & g)) + sha256_k[i] + m[i];
        t2 = (ror(a,2) ^ ror(a,13) ^ ror(a,22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    for (i = 0; i < 8; ++i)
        ctx->data[56 + i] = (ctx->bitlen >> (56 - i*8)) & 0xFF;
    sha256_transform(ctx, ctx->data);
    /* FIX: output all 8 state words → 32 bytes (was only 4) */
    for (i = 0; i < 8; ++i) {
        hash[i*4]   = (ctx->state[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i*4+3] = ctx->state[i] & 0xFF;
    }
}

/* ----------------------------
   FRAME (must match kernel exactly)
---------------------------- */
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

_Static_assert(sizeof(thayalt_stride_t) == 128, "Frame size mismatch");

/* ----------------------------
   Sentinel Certificate
---------------------------- */
typedef struct {
    uint64_t ledger_hash_root;   // placeholder – full root hash can be added later
    uint64_t frame_count;
    uint64_t last_sequence;
    uint8_t  integrity_score;    // 0-100
    uint8_t  valid;
    uint8_t  reserved[14];
} sentinel_certificate_t;

/* ----------------------------
   Sentinel State
---------------------------- */
typedef struct {
    uint64_t expected_seq;
    uint64_t frame_count;
    uint64_t errors;
    uint8_t  prev_hash[32];
    bool first;
} sentinel_t;

static sentinel_t S;

/* ----------------------------
   Compute frame hash (chain rule)
---------------------------- */
static void compute_frame_hash(uint8_t out[32], const uint8_t prev[32], const thayalt_stride_t *f) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, prev, 32);
    sha256_update(&ctx, (const uint8_t*)f, sizeof(thayalt_stride_t) - 32);
    sha256_final(&ctx, out);
}

/* ----------------------------
   Structural check (pressure ratio range)
---------------------------- */
static inline bool check_structure(const thayalt_stride_t *f) {
    return f->pressure_ratio <= 100;
}

/* ----------------------------
   Sequence check
---------------------------- */
static inline bool check_sequence(const thayalt_stride_t *f) {
    return f->sequence_id == S.expected_seq;
}

/* ----------------------------
   Sentinel initialisation
---------------------------- */
static void sentinel_init(void) {
    memset(&S, 0, sizeof(S));
    S.first = true;
}

/* ----------------------------
   Emit certificate (binary)
---------------------------- */
static void emit_certificate(FILE *out) {
    sentinel_certificate_t cert;
    memset(&cert, 0, sizeof(cert));

    uint64_t integrity = (S.frame_count == 0)
        ? 100
        : (100 - (S.errors * 100 / S.frame_count));

    cert.frame_count = S.frame_count;
    cert.last_sequence = (S.frame_count > 0) ? S.expected_seq - 1 : 0;
    cert.integrity_score = (uint8_t)integrity;
    cert.valid = (S.errors == 0) ? 1 : 0;

    // ledger_hash_root could be final hash of whole chain – optional for v1
    cert.ledger_hash_root = 0;
    memcpy(cert.reserved, S.prev_hash, 14);

    fwrite(&cert, sizeof(cert), 1, out);
}

/* ----------------------------
   Main verification loop
---------------------------- */
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ledger.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Error opening ledger: %s\n", strerror(errno));
        return 1;
    }

    sentinel_init();

    thayalt_stride_t frame;

    while (fread(&frame, sizeof(frame), 1, fp) == 1) {
        S.frame_count++;

        /* --- first frame: initialise expected seq --- */
        if (S.first) {
            S.expected_seq = frame.sequence_id;
            S.first = false;
        }

        /* --- sequence check --- */
        if (!check_sequence(&frame)) {
            S.errors++;
        }

        /* --- structural check --- */
        if (!check_structure(&frame)) {
            S.errors++;
        }

        /* --- hash validation --- */
        uint8_t computed_hash[32];
        compute_frame_hash(computed_hash, S.prev_hash, &frame);
        if (memcmp(computed_hash, frame.block_hash, 32) != 0) {
            S.errors++;
        }

        /* --- update state for next frame --- */
        memcpy(S.prev_hash, frame.block_hash, 32);
        S.expected_seq++;
    }

    /* FIX: distinguish clean EOF from I/O error */
    if (ferror(fp)) {
        fprintf(stderr, "I/O error while reading ledger\n");
        fclose(fp);
        return 2;
    }
    fclose(fp);

    /* --- output certificate --- */
    emit_certificate(stdout);

    return (S.errors == 0) ? 0 : 2;
}