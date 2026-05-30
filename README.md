# THAYALT — Sealed Ledger Engine with SUPM

THAYALT is a persistent append-only ledger engine that maintains cryptographic integrity through hash-chaining and checkpoint sealing. It integrates the Safety/Urgency Prediction Machine (SUPM) to classify operating regimes and make regime-aware processing decisions.

---

## Overview

THAYALT is designed to:

- Seal 128-byte frames into a hash-chained append-only ledger
- Checkpoint sealed ranges for fast recovery and verification
- Apply SUPM metrics to determine operational regimes
- Preserve immutability and enable deterministic replay

---

## Architecture

Sensor data or simulated input is received by the THAYALT core, which:

- validates and seals incoming frames
- chains frames using SHA-256
- writes ledger entries to `thayalt_core.log`
- indexes checkpointed ranges in `thayalt_checkpoints.log`
- evaluates SUPM to select SAFE, DEGRADED, or CRITICAL regimes

---

## Constitutional Invariants

THAYALT enforces the following properties:

1. Append-only: no frame is overwritten or removed once committed.
2. Hash-chained: each frame includes a cryptographic hash that links it to prior history.
3. Checkpointed: sealed ranges are recorded separately for fast recovery.
4. Recoverable: system state can always be reconstructed from the ledger.
5. Graceful shutdown: signal handlers flush pending data before exit.

---

## Frame Structure

Each frame is 128 bytes and includes:

```c
typedef struct {
    uint64_t sequence_id;      // Ledger sequence number
    uint64_t timestamp;        // UTC seconds at write time
    uint32_t sensor_id;        // Source identifier
    uint32_t metric_value;     // Sensor reading or computed value
    uint8_t  active_regime;    // 0=SAFE, 1=DEGRADED, 2=CRITICAL
    uint8_t  pressure_ratio;   // 0-100 (%)
    uint8_t  reserved[70];     // Regime-dependent padding
    uint8_t  block_hash[32];   // SHA256(prev_hash || frame_without_hash)
} thayalt_stride_t;
```

---

## SUPM — Safety/Urgency Prediction Machine

SUPM monitors system health and predicts failure risk using runtime metrics.

### Metrics

- TSF (Trust Success Fraction): `ok / (ok + fail)`
  - Cumulative success rate; 1.0 indicates perfect reliability.
- TSC (Trust Stability Coefficient): `dTSF / dt`
  - Rate of change of TSF; negative values indicate deterioration.
- TTCC (Time To Critical Condition): `(TSF - min_viable) / -TSC` when `TSC < 0`, otherwise infinity
  - Estimated time until TSF falls below the minimum threshold.

### Regime Decision

Regime selection uses SUPM metrics and pressure ratio:

- `TTCC < 10.0` or `pressure_ratio > 85`: `CRITICAL` — reserved fill `0xFF`
- `pressure_ratio > 60`: `DEGRADED` — reserved fill `0xAA`
- otherwise: `SAFE` — reserved fill `0x00`

---

## Checkpoint System

THAYALT creates checkpoints at regular intervals, typically every `4096` frames.

Each checkpoint record includes:

```c
typedef struct {
    uint64_t start_seq;      // First frame in range
    uint64_t end_seq;        // Last frame in range
    uint64_t frame_count;    // Total frames sealed
    uint64_t timestamp;      // Checkpoint time
    uint8_t  seal_hash[32];  // SHA256(rolling_hash || start || end || count)
    uint8_t  valid;          // Validity flag
    uint8_t  _pad[7];        // Alignment padding
} checkpoint_record_t;
```

The rolling hash accumulates over every frame in the checkpoint range, ensuring continuity and enabling verification of sealed ranges.

---

## Building

### Requirements

- `gcc` with C99 support
- `make` (optional)

### Build commands

Direct `gcc` build:

```sh
gcc -O2 -std=c99 -lm core/thayalt_core.c -o core/thayalt_core
```

Using the provided `Makefile`:

```sh
make          # builds core + observers
make run      # starts the core
make verify   # runs sentinel verification on the ledger
make audit    # runs auditor verification on the ledger
make clean    # removes binaries only
make clean-all # removes binaries and ledger files
```
```

-
--

## Running

```
bash
./core/thayalt_core
```

The eng
ine will:

1. Create/open `thayalt_core.log` and `thayalt
_checkpoints.log` in the current directory  
2. Recover s
tate from any previous run  
3. Enter the main loop:  
  
 - Simulate sensor readings (pressure, regime) – replac
e with real sensor input  
   - Update SUPM constraints b
ased on previous write result  
   - Compute TSF/ TSC/ TT
CC  
   - Determine active regime  
   - Write frame to l
edger at ~10 Hz  
   - Print status every 1000 frames  
4
. Exit gracefully on Cfrl,C, flushing all pending data  


---

## Observers

Two verification tools are included i
n `observers/`.

### `thayalt_sentinel`

Verifies hash ch
ain, sequence numbers, and structural validity (pressure 
ratio ≤ 100).  
Emits a **binary certificate** to stdou
t.

```
bash
./observers/thayalt_sentinel thayalt_core.lo
g
```

To save the certificate:

```bash
./observers/thay
alt_sentinel thayalt_core.log > cert.bin
```

Exit codes:
 `0` = valid, `2` = errors.

### `thayalt_auditor`

Enfor
ces a contract (speed limit, limiter signal) against the 
ledger.  
Requires the ledger file only (uses a mock sent
inel handshake).

```bash
./observers/thayalt_auditor tha
yalt_core.log
```
The auditor checks:
- Sequence continui
ty (no gaps or duplicates)  
- Speed limit compliance (`m
etric_value / 100`)  
- Limmter signal in `reserved[0] & 
1` (placeholder – adjust for your hardware)  
- Cross-c
hecks frame count and last sequence against a sentinel ce
rtificate (currently mocked)

---

## Architecture Highli
ghts

### Immutability Enforcement

- No in-place deletio
n or zeroing of frames  
- Storage management must be don
e via **archival*:  
  1. Copy sealed checkpoint ranges t
o cold storage  
  2. Verify archive against checkpoint s
eal  
  3. Only then remove from hot log (truncation/rota
tion)  

### Deterministic Replay

- Every frame is repro
ducible from the log  
- In-memory state (`seaz`, `prev_h
ash`, `ckpt_rolling_hash`) is an **optimisation**, not th
e source of truth  
- Full replay from byte 0 is always p
ossible  

### Signal Handling (POSIX)

- `sigaction` cap
tures `SIGINT` and `SIGTERM   
- Sets `g_running = 0` for
 graceful shutdown  
- Final `fsync()`before close  

---


## Output Example

```
[CORE] THAYALT ledger engine onl
ine (with SUPM)
[CORE] log=thayalt_core.log checkpoints=t
hayalt_checkpoints.log
[CORE] checkpoint_interval=4096 fr
ames
[RECOVERY] Resumed at seq=0 frames=0
[CKPT] sealed s
eq 0..4096 count=4096 seal=a1b2c3d4...
[STATUS] seq=1000 
TSF=1.0000 TSC=0.000000 TTCC=inf reg=0 press=0 ok=1000 fa
il=0
[STATUS] seq=2000 TSF=0.9950 TSC=-0.000001 TTCC=9.50
 reg=1 press=15 ok=1990 fail=10
[CORE] Shutting down at s
eq=5000
[CORE] Closed cleanly.
```

---

## Constants

| 
Constant | Value | Meaning |
|-----------|--------|------
-------------------------|
| `CHECKPOINT_INTERVAL` | 4096
 | Frames per checkpoint |
| `MIN_VIABLE_TRUTH` | 0.95 | 
TSF threshold for TTCC calculation |
| Frame sleep interv
al | 100 ms | ~10 Hz sampling rate (adjustable) |

---

#
# Threading & Concurrency

**Not thread-safe**. THAYALT i
s designed for single-thXYY\][ۋY][K]
eaded access is required, add a mutex around `write_frame
()` and ensure signal handlers use only async-safe functi
ons.

---

## Future Enhancements

1. **Archival interfac
e** – Move sealed checkpoints to cold storage  
2. **Ve
rification tool** – Load and verify checkpoint seals fr
om archive  
3. **Metrics export** – Expose SUPM metric
s via REST API or metrics sink  
4. **Sharding** – Mult
iple ledgers per regime or sensor cluster  
5. **Distribu
ted checkpoints** – Replicate checkpoint index across n
odes  

---

## License

**AGPL-3.0** – see [LICENSE](L
ICENSE).  
You may use, modify, and distribute this softw
are. If you run it as a service, you must publish your mo
difications.

---

## Repository Structure

```
thayalt-l
edger/
├── core/
≠── ── thayalt_core.c   
        # Main ledger engine
┎── observers/
≠─
 ── thayalt_sentinel.c       # Hash & sequence veri
fier
≠── ── thayalt_auditor.c        # Contract
 enforcer
┎0── constitution/                # (Opti
onal) PDFs
┎── Makefile                     # Build
 automation
┎── README.md                    # This
 file
┎── BOM.md                      # Bill of mat
erials
┎── SUPM.md                      # SUPM expl
anation
┎── LICENSE                      # AGPL-3.0

┎── .gitignore                   # Ignore binaries
, logs, etc.
```

---

## Author

THAYALT Project – [Yo
ur Name / Organization]  
Based on the **THAYALT Architec
tural Constitution** and **Embedded Ledger Kernel** speci
fications.
