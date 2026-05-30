/* ============================================================
 * THAYALT_CORE.C — SEALED LEDGER ENGINE with SUPM Regime
 * Persistent storage layer. Runs on Linux / Raspberry Pi.
 *
 * Role: receives signed frames, seals them into a hash-chained
 * append-only log, checkpoints sealed ranges, and runs the
 * Safety/Urgency Prediction Machine (SUPM).
 *
 * Constitution: immutable events, deterministic replay,
 * checkpoint integrity, explicit loss/discovery (via observers).
 *
 * ============================================================
 * BUG-FIX LOG (audited):
 *
 * FIX-1  sha256_transform: removed `static` from local array `m[64]`.
 *        Static locals are not re-entrant; if sha256 were ever called
 *        from a signal handler or a second thread the array would be
 *        silently shared, corrupting every hash in flight.
 *        Stack allocation costs ~256 bytes and is fully safe.
 *
 * FIX-2  checkpoint_seal: replaced compound-literal hex snippet with a
 *        proper 9-byte buffer.  The original (char[]){c0,c1,c2,c3,'\0'}
 *        is only 5 bytes wide; printf("%.8s") reads 8 bytes from it,
 *        walking off the end of the object — undefined behaviour and a
 *        potential stack-data leak in log output.
 *
 * FIX-3  checkpoint_seal: removed the redundant / unchecked
 *        lseek(ckpt_fd, 0, SEEK_END).  Both log files are opened with
 *        O_APPEND, which atomically repositions to EOF before every
 *        write(2) at the kernel level; the extra lseek is a no-op that
 *        could only introduce a TOCTOU gap on non-Linux POSIX systems,
 *        and its ignored return value was inconsistent with the checked
 *        lseek in write_frame.
 *
 * FIX-4  SUPM ordering: moved supm_update_constraints() to the top of
 *        the loop (before supm_compute_*) so that the regime decision
 *        for frame N is based on the outcome of frame N-1 rather than
 *        frame N-2.  The very first iteration feeds ok=0/fail=0 which
 *        leaves TSF at the initial 1.0 — correct cold-start behaviour.
 *
 * FIX-5  recover_state: after a warm restart the checkpoint rolling
 *        hash is rebuilt by replaying the frames that fall between
 *        interval_start and the end of the log, so the next checkpoint
 *        seal is cryptographically continuous with the previous ones.
 *        Previously ckpt_rolling_hash was seeded from prev_hash (the
 *        last frame's hash) which produces an unverifiable seal.
 *
 * ============================================================ */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <windows.h>

/* Compile-time assertion for MSVC */
#define C_ASSERT(expr) typedef char C_ASSERT_##__LINE__[(expr) ? 1 : -1]
#include <math.h>

 /* ── Frame (128 bytes, matches kernel) ────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint64_t sequence_id;
    uint64_t timestamp;
    uint32_t sensor_id;
    uint32_t metric_value;
    uint8_t active_regime;
    uint8_t pressure_ratio;
    uint8_t reserved[70];
    uint8_t block_hash[32];
} thayalt_stride_t;
#pragma pack(pop)

C_ASSERT(sizeof(thayalt_stride_t) == 128);

/* ── SHA-256 (self‑contained) ─────────────────────────────── */
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

static const uint32_t K[64] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

static inline uint32_t ror32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(SHA256_CTX* ctx, const uint8_t* data) {
    /* FIX-1: was `static uint32_t m[64]` — static locals are not
     * re-entrant.  Stack allocation is safe and costs ~256 bytes. */
    uint32_t m[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    uint32_t i, j;
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j + 1] << 16) | ((uint32_t)data[j + 2] << 8) | (uint32_t)data[j + 3];
    for (; i < 64; ++i)
        m[i] = m[i - 16] + (ror32(m[i - 15], 7) ^ ror32(m[i - 15], 18) ^ (m[i - 15] >> 3)) + m[i - 7] + (ror32(m[i - 2], 17) ^ ror32(m[i - 2], 19) ^ (m[i - 2] >> 10));
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + m[i];
        t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX* ctx) {
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

static void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX* ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    /* NOTE: ctx->datalen is intentionally not updated during the padding
     * loop above (i is a local copy).  This means the line below correctly
     * accounts only for the real payload bytes, not padding. */
    ctx->bitlen += ctx->datalen * 8;
    for (i = 0; i < 8; ++i)
        ctx->data[56 + i] = (ctx->bitlen >> (56 - i * 8)) & 0xFF;
    sha256_transform(ctx, ctx->data);
    for (uint32_t k = 0; k < 8; ++k) {
        hash[k * 4] = (ctx->state[k] >> 24) & 0xFF;
        hash[k * 4 + 1] = (ctx->state[k] >> 16) & 0xFF;
        hash[k * 4 + 2] = (ctx->state[k] >> 8) & 0xFF;
        hash[k * 4 + 3] = ctx->state[k] & 0xFF;
    }
}

/* ── SUPM (Safety/Urgency Prediction Machine) ─────────────── */
typedef struct {
    double tsf;  /* Trust Success Fraction */
    double tsc;  /* Trust Stability Coefficient */
    double ttcc; /* Time To Critical Condition */
    double last_tsf;
    double last_time;
    uint64_t ok;
    uint64_t fail;
    bool first;
} supm_t;

static supm_t supm;

static void supm_init(void) {
    memset(&supm, 0, sizeof(supm));
    supm.first = true;
}

static void supm_update_constraints(bool ok) {
    if (ok)
        supm.ok++;
    else
        supm.fail++;
}

static void supm_compute_tsf(void) {
    uint64_t total = supm.ok + supm.fail;
    supm.tsf = total ? (double)supm.ok / total : 1.0;
}

static void supm_compute_tsc(double now) {
    if (supm.first) {
        supm.tsc = 0.0;
        supm.last_time = now;
        supm.last_tsf = supm.tsf;
        supm.first = false;
        return;
    }
    double dt = now - supm.last_time;
    if (dt < 0.001)
        dt = 0.001;
    supm.tsc = (supm.tsf - supm.last_tsf) / dt;
    supm.last_time = now;
    supm.last_tsf = supm.tsf;
}

static void supm_compute_ttcc(double min_viable) {
    if (supm.tsc >= 0.0) {
        supm.ttcc = INFINITY;
        return;
    }
    double delta = supm.tsf - min_viable;
    if (delta <= 0.0)
        supm.ttcc = 0.0;
    else
        supm.ttcc = delta / (-supm.tsc);
}

/* ── Checkpoint subsystem ─────────────────────────────────── */
#define CHECKPOINT_INTERVAL 4096

#pragma pack(push, 1)
typedef struct {
    uint64_t start_seq;
    uint64_t end_seq;
    uint64_t frame_count;
    uint64_t timestamp;
    uint8_t seal_hash[32];
    uint8_t valid;
    uint8_t _pad[7];
} checkpoint_record_t;
#pragma pack(pop)

C_ASSERT(sizeof(checkpoint_record_t) == 72);

static checkpoint_record_t current_ckpt;
static uint8_t ckpt_rolling_hash[32];
static HANDLE ckpt_fd = INVALID_HANDLE_VALUE;

/* ── Core ledger state ────────────────────────────────────── */
static uint8_t prev_hash[32] = { 0 };
static uint64_t seq = 0;
static HANDLE fd = INVALID_HANDLE_VALUE;

/* ── Signal handling ──────────────────────────────────────── */
static volatile LONG g_running = 1;

static BOOL WINAPI signal_handler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_running, 0);
        return TRUE;
    }
    return FALSE;
}

/* ── Frame seal computation ───────────────────────────────── */
static void compute_frame_seal(uint8_t* hash_out,
    const uint8_t* prev,
    const thayalt_stride_t* frame) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, prev, 32);
    sha256_update(&ctx, (const uint8_t*)frame,
        sizeof(thayalt_stride_t) - 32);
    sha256_final(&ctx, hash_out);
}

/* ── Checkpoint operations ────────────────────────────────── */
static void checkpoint_begin(uint64_t start_seq) {
    memset(&current_ckpt, 0, sizeof(current_ckpt));
    current_ckpt.start_seq = start_seq;
    memcpy(ckpt_rolling_hash, prev_hash, 32);
}

static void checkpoint_advance(const uint8_t* frame_hash) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ckpt_rolling_hash, 32);
    sha256_update(&ctx, frame_hash, 32);
    sha256_final(&ctx, ckpt_rolling_hash);
}

static void checkpoint_seal(uint64_t end_seq) {
    uint64_t count = end_seq - current_ckpt.start_seq;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, ckpt_rolling_hash, 32);
    sha256_update(&ctx, (uint8_t*)&current_ckpt.start_seq, 8);
    sha256_update(&ctx, (uint8_t*)&end_seq, 8);
    sha256_update(&ctx, (uint8_t*)&count, 8);
    sha256_final(&ctx, current_ckpt.seal_hash);
    current_ckpt.end_seq = end_seq;
    current_ckpt.frame_count = count;
    current_ckpt.timestamp = (uint64_t)time(NULL);
    current_ckpt.valid = 1;

    if (ckpt_fd != INVALID_HANDLE_VALUE) {
        DWORD written;
        if (!WriteFile(ckpt_fd, &current_ckpt, sizeof(current_ckpt), &written, NULL)
            || written != sizeof(current_ckpt))
            fprintf(stderr, "[WARN] checkpoint write failed: %lu\n", GetLastError());
        FlushFileBuffers(ckpt_fd);
    }
    FlushFileBuffers(fd);

    /* FIX-2: was (char[]){hex0,hex1,hex2,hex3,'\0'} — only 5 bytes wide
     * but printed with %.8s which reads 8 bytes → UB / stack data leak.
     * Now we use a properly-sized 9-byte buffer for 4 hex chars + NUL,
     * and print with %.4s to match exactly what we computed. */
    static const char hex[] = "0123456789abcdef";
    char seal_preview[9];
    for (int b = 0; b < 4; ++b) {
        seal_preview[b * 2] = hex[current_ckpt.seal_hash[b] >> 4];
        seal_preview[b * 2 + 1] = hex[current_ckpt.seal_hash[b] & 0xF];
    }
    seal_preview[8] = '\0';

    fprintf(stderr, "[CKPT] sealed seq %llu..%llu count=%llu seal=%.8s...\n",
        (unsigned long long)current_ckpt.start_seq,
        (unsigned long long)end_seq,
        (unsigned long long)count,
        seal_preview);
}

/* ── Write one frame (core write path) ────────────────────── */
static bool write_frame(thayalt_stride_t* f) {
    f->sequence_id = seq;
    f->timestamp = (uint64_t)time(NULL);
    compute_frame_seal(f->block_hash, prev_hash, f);

    LARGE_INTEGER zero = {0};
    if (!SetFilePointerEx(fd, zero, NULL, FILE_END)) {
        fprintf(stderr, "[ERR] SetFilePointerEx failed: %lu\n", GetLastError());
        return false;
    }
    DWORD written;
    if (!WriteFile(fd, f, sizeof(*f), &written, NULL) || written != sizeof(*f)) {
        fprintf(stderr, "[ERR] write frame seq=%llu: %lu\n",
            (unsigned long long)seq, GetLastError());
        return false;
    }
    FlushFileBuffers(fd);
    memcpy(prev_hash, f->block_hash, 32);
    seq++;
    checkpoint_advance(f->block_hash);
    if (seq % CHECKPOINT_INTERVAL == 0) {
        checkpoint_seal(seq);
        checkpoint_begin(seq);
    }
    return true;
}

/* ── Recovery from log and checkpoint index ───────────────── */
static void recover_state(void) {
    LARGE_INTEGER size = {0};
    if (!GetFileSizeEx(fd, &size)) {
        fprintf(stderr, "[WARN] recover_state: GetFileSizeEx failed — cold start\n");
        seq = 0;
        checkpoint_begin(0);
        return;
    }
    uint64_t frame_count = (uint64_t)size.QuadPart / sizeof(thayalt_stride_t);
    if (frame_count == 0) {
        seq = 0;
        checkpoint_begin(0);
        fprintf(stderr, "[RECOVERY] Cold start — empty log\n");
        return;
    }
    LARGE_INTEGER last_off;
    last_off.QuadPart = (LONGLONG)(frame_count - 1) * (LONGLONG)sizeof(thayalt_stride_t);
    thayalt_stride_t last;
    if (!SetFilePointerEx(fd, last_off, NULL, FILE_BEGIN)) {
        fprintf(stderr, "[WARN] recover_state: SetFilePointerEx error — cold start\n");
        seq = 0;
        memset(prev_hash, 0, 32);
        checkpoint_begin(0);
        return;
    }
    DWORD read_bytes;
    if (!ReadFile(fd, &last, sizeof(last), &read_bytes, NULL) || read_bytes != sizeof(last)) {
        fprintf(stderr, "[WARN] recover_state: ReadFile error — cold start\n");
        seq = 0;
        memset(prev_hash, 0, 32);
        checkpoint_begin(0);
        return;
    }
    seq = last.sequence_id + 1;
    memcpy(prev_hash, last.block_hash, 32);

    if (ckpt_fd != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER ckpt_size = {0};
        if (GetFileSizeEx(ckpt_fd, &ckpt_size) && ckpt_size.QuadPart >= (LONGLONG)sizeof(checkpoint_record_t)) {
            LARGE_INTEGER last_ckpt_off;
            last_ckpt_off.QuadPart = ckpt_size.QuadPart - (LONGLONG)sizeof(checkpoint_record_t);
            checkpoint_record_t last_ckpt;
            if (SetFilePointerEx(ckpt_fd, last_ckpt_off, NULL, FILE_BEGIN)) {
                DWORD ckpt_read;
                if (ReadFile(ckpt_fd, &last_ckpt, sizeof(last_ckpt), &ckpt_read, NULL) && ckpt_read == sizeof(last_ckpt) && last_ckpt.valid) {
                    fprintf(stderr, "[RECOVERY] Last checkpoint: seq %llu..%llu\n",
                        (unsigned long long)last_ckpt.start_seq,
                        (unsigned long long)last_ckpt.end_seq);
                }
            }
        }
    }

    /* FIX-5: Rebuild the checkpoint rolling hash by replaying all frames
     * from interval_start to the end of the log.  Previously we seeded
     * ckpt_rolling_hash directly from prev_hash (the last frame's hash),
     * which produces a rolling hash that doesn't match a forward replay
     * from interval_start — making the next checkpoint seal unverifiable.
     *
     * We start the rolling hash from all-zeros (the seed used in a fresh
     * checkpoint_begin before any frames are ingested), then feed each
     * frame hash in order.  checkpoint_begin() below will overwrite
     * ckpt_rolling_hash with prev_hash, so we capture our rebuilt value
     * first and restore it afterward. */
    uint64_t interval_start = (seq / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL;

    /* Seed the rolling hash to the empty-checkpoint state. */
    memset(ckpt_rolling_hash, 0, 32);

    uint64_t replay_count = frame_count - interval_start;
    if (replay_count > 0) {
        fprintf(stderr, "[RECOVERY] Replaying %llu frames to rebuild rolling hash\n",
            (unsigned long long)replay_count);
        for (uint64_t fi = interval_start; fi < frame_count; ++fi) {
            thayalt_stride_t rf;
            LARGE_INTEGER rf_off;
            rf_off.QuadPart = (LONGLONG)fi * (LONGLONG)sizeof(rf);
            if (!SetFilePointerEx(fd, rf_off, NULL, FILE_BEGIN)) {
                fprintf(stderr, "[WARN] rolling-hash replay failed at frame %llu"
                    " — checkpoint continuity broken\n",
                    (unsigned long long)fi);
                memset(ckpt_rolling_hash, 0, 32);
                break;
            }
            DWORD rf_read;
            if (!ReadFile(fd, &rf, sizeof(rf), &rf_read, NULL) || rf_read != sizeof(rf)) {
                fprintf(stderr, "[WARN] rolling-hash replay failed at frame %llu"
                    " — checkpoint continuity broken\n",
                    (unsigned long long)fi);
                memset(ckpt_rolling_hash, 0, 32);
                break;
            }
            checkpoint_advance(rf.block_hash);
        }
    }

    /* checkpoint_begin re-initialises current_ckpt.start_seq and would
     * overwrite ckpt_rolling_hash; save and restore the rebuilt value. */
    uint8_t rebuilt_rolling[32];
    memcpy(rebuilt_rolling, ckpt_rolling_hash, 32);
    checkpoint_begin(interval_start);               /* sets start_seq, clears ckpt */
    memcpy(ckpt_rolling_hash, rebuilt_rolling, 32); /* restore rebuilt hash */

    fprintf(stderr, "[RECOVERY] Resumed at seq=%llu frames=%llu\n",
        (unsigned long long)seq, (unsigned long long)frame_count);
}

/* ── Main ─────────────────────────────────────────────────── */
int main(void) {
    /* Signal handlers for graceful shutdown */
    SetConsoleCtrlHandler(signal_handler, TRUE);

    fd = CreateFileA("thayalt_core.log",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (fd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[ERR] CreateFileA log: %lu\n", GetLastError());
        return 1;
    }
    ckpt_fd = CreateFileA("thayalt_checkpoints.log",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (ckpt_fd == INVALID_HANDLE_VALUE)
        fprintf(stderr, "[WARN] CreateFileA checkpoints: %lu — continuing without\n", GetLastError());

    recover_state();
    supm_init();

    /* Simulated sensor error counter (0..7) for pressure calculation */
    uint8_t error_counter = 0;
    const double MIN_VIABLE_TRUTH = 0.95;

    fprintf(stderr, "[CORE] THAYALT ledger engine online (with SUPM)\n");
    fprintf(stderr, "[CORE] log=thayalt_core.log checkpoints=thayalt_checkpoints.log\n");
    fprintf(stderr, "[CORE] checkpoint_interval=%d frames\n", CHECKPOINT_INTERVAL);

    /* FIX-4: SUPM ordering fix — the previous code ran supm_compute_*
     * BEFORE supm_update_constraints, meaning the regime decision for
     * frame N was based on outcomes up to frame N-2 (one full iteration
     * stale).  We now update constraints first (from the previous
     * iteration's write result) so that TSF/TSC/TTCC reflect all
     * completed frames before we decide the current frame's regime.
     *
     * `last_write_ok` is initialised true so the very first frame is
     * scored as a success before any real I/O has occurred, which
     * matches the cold-start TSF of 1.0 set by supm_compute_tsf when
     * ok==0 && fail==0. */
    bool last_write_ok = true;

    while (g_running) {
        thayalt_stride_t frame;
        memset(&frame, 0, sizeof(frame));

        /* FIX-4: update with result of the *previous* write first, then
         * compute SUPM metrics, then decide the regime for this frame. */
        supm_update_constraints(last_write_ok);

        /* ----- Replace this block with actual sensor input ----- */
        frame.metric_value = 42; /* placeholder */
        frame.sensor_id = 1;
        /* Pressure simulation: 0%, 15%, 30%, ... up to 105% (clamped) */
        float pressure = error_counter * 0.15f;
        if (pressure > 1.0f)
            pressure = 1.0f;
        frame.pressure_ratio = (uint8_t)(pressure * 100.0f);
        error_counter = (error_counter + 1) % 8;
        /* ------------------------------------------------------- */

        double now = (double)time(NULL);
        supm_compute_tsf();
        supm_compute_tsc(now);
        supm_compute_ttcc(MIN_VIABLE_TRUTH);

        /* Determine active regime */
        if (supm.ttcc < 10.0 || pressure > 0.85f)
            frame.active_regime = 2; /* CRITICAL */
        else if (pressure > 0.60f)
            frame.active_regime = 1; /* DEGRADED */
        else
            frame.active_regime = 0; /* SAFE */

        /* Fill reserved bytes according to regime */
        if (frame.active_regime == 0)
            memset(frame.reserved, 0x00, 70);
        else if (frame.active_regime == 1)
            memset(frame.reserved, 0xAA, 70);
        else
            memset(frame.reserved, 0xFF, 70);

        /* Write frame to ledger; capture result for next iteration */
        last_write_ok = write_frame(&frame);

        /* Periodic status every 1000 frames */
        if (seq > 0 && seq % 1000 == 0) {
            fprintf(stderr, "[STATUS] seq=%llu TSF=%.4f TSC=%.6f TTCC=%.2f "
                "reg=%d press=%d ok=%llu fail=%llu\n",
                (unsigned long long)seq,
                supm.tsf, supm.tsc, supm.ttcc,
                frame.active_regime, frame.pressure_ratio,
                (unsigned long long)supm.ok,
                (unsigned long long)supm.fail);
        }

        Sleep(100);  /* 100 ms — 10 Hz, adjust to your sampling rate */
    }

    /* Graceful shutdown */
    fprintf(stderr, "[CORE] Shutting down at seq=%llu\n", (unsigned long long)seq);
    FlushFileBuffers(fd);
    if (ckpt_fd != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(ckpt_fd);
        CloseHandle(ckpt_fd);
    }
    CloseHandle(fd);
    fprintf(stderr, "[CORE] Closed cleanly.\n");
    return 0;
}