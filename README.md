## Building

### Requirements

* GCC (C99 or later)
* Make (optional)

### Direct Build

```bash
gcc -O2 -std=c99 -lm core/thayalt_core.c -o core/thayalt_core
```

### Using the Makefile

```bash
make            # Build core and observers
make run        # Start the core
make verify     # Run Sentinel verification
make audit      # Run Auditor verification
make clean      # Remove binaries only
make clean-all  # Remove binaries and ledger files
```

---

## Running

```bash
./core/thayalt_core
```

The engine will:

1. Create or open `thayalt_core.log`
2. Create or open `thayalt_checkpoints.log`
3. Recover state from any previous run
4. Enter the main processing loop:

   * Acquire sensor input (simulated by default)
   * Update SUPM constraints
   * Compute TSF, TSC, and TTCC
   * Determine the active operating regime
   * Seal and append a frame to the ledger
   * Generate checkpoints at configured intervals
5. Exit gracefully on Ctrl+C or SIGTERM

---

## Observers

Two verification tools are included in `observers/`.

### thayalt_sentinel

Verifies:

* Hash chain continuity
* Sequence continuity
* Structural frame validity
* Checkpoint consistency

Run:

```bash
./observers/thayalt_sentinel thayalt_core.log
```

To save the verification certificate:

```bash
./observers/thayalt_sentinel thayalt_core.log > cert.bin
```

Exit codes:

| Code | Meaning                    |
| ---- | -------------------------- |
| 0    | Ledger valid               |
| 2    | Validation errors detected |

---

### thayalt_auditor

Applies semantic validation rules against a verified ledger.

Example checks:

* Speed limit compliance
* Limiter activation
* Sequence consistency
* Business rule violations
* Domain-specific constraints

Run:

```bash
./observers/thayalt_auditor thayalt_core.log
```

The Auditor assumes the Sentinel has already validated structural integrity.

---

## Architecture Highlights

### Immutability Enforcement

THAYALT never modifies committed frames.

Storage management must occur through archival:

1. Verify a sealed checkpoint range.
2. Export the verified range to cold storage.
3. Confirm archive integrity.
4. Rotate or truncate hot storage only after successful archival.

---

### Deterministic Replay

The ledger is the source of truth.

Internal variables such as:

```text
seq
prev_hash
ckpt_rolling_hash
```

exist solely as performance optimizations.

Any system state can be reconstructed by replaying the ledger from byte zero.

---

### Graceful Shutdown

The engine supports controlled termination.

On shutdown:

1. Signal handler sets the termination flag.
2. Pending writes complete.
3. Ledger files are flushed.
4. Checkpoint state is preserved.
5. File handles are closed.

This guarantees recovery continuity across restarts.

---

## Example Output

```text
[CORE] THAYALT ledger engine online (with SUPM)
[CORE] log=thayalt_core.log
[CORE] checkpoints=thayalt_checkpoints.log
[CORE] checkpoint_interval=4096 frames

[RECOVERY] Resumed at seq=0 frames=0

[CKPT] sealed seq 0..4096 count=4096 seal=a1b2c3d4...

[STATUS] seq=1000 TSF=1.0000 TSC=0.000000 TTCC=inf reg=0 press=0 ok=1000 fail=0

[STATUS] seq=2000 TSF=0.9950 TSC=-0.000001 TTCC=9.50 reg=1 press=15 ok=1990 fail=10

[CORE] Shutting down at seq=5000
[CORE] Closed cleanly.
```

---

## Constants

| Constant            | Value  | Description               |
| ------------------- | ------ | ------------------------- |
| CHECKPOINT_INTERVAL | 4096   | Frames per checkpoint     |
| MIN_VIABLE_TRUTH    | 0.95   | TSF threshold             |
| Sleep Interval      | 100 ms | Default sampling interval |

---

## Threading and Concurrency

Current implementation:

* Single-threaded
* Single-writer
* Deterministic execution

The core is intentionally conservative.

If multi-threaded ingestion is introduced, writes must be serialized and the ledger must preserve global ordering.

---

## Future Enhancements

1. Archive subsystem
2. Checkpoint verification utility
3. Metrics export endpoint
4. Multi-ledger sharding
5. Distributed checkpoint replication
6. Hardware-backed signing
7. Remote attestation support

---

## Repository Structure

```text
thayalt-ledger/
├── core/
│   └── thayalt_core.c
│
├── observers/
│   ├── thayalt_sentinel.c
│   └── thayalt_auditor.c
│
├── constitution/
│   └── architecture_documents.pdf
│
├── README.md
├── LICENSE
├── Makefile
├── BOM.md
├── SUPM.md
└── .gitignore
```

---

## License

AGPL-3.0

You may use, modify, and distribute this software.

If you deploy a modified version as a network-accessible service, the corresponding source code must also be made available under the AGPL.

---

## Author
**THAYALT Project**

Lead Architect: Ronald Makori

THAYALT develops deterministic ledger systems for telemetry, asset accountability, verification, and operational truth preservation.

The project is built around three constitutional components:

* THAYALT Core — persistent sealed ledger kernel
* THAYALT Sentinel — structural integrity verifier
* THAYALT Auditor — semantic and contractual verifier

Primary design goals:

* Deterministic replay
* Cryptographic continuity
* Offline-first operation
* Observer-based verification
* Hardware portability

Location: Mombasa, Kenya
email: ronald@thayaltsystems.com / rmakori065@gmail.com

