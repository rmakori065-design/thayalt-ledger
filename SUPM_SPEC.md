# SUPM – Safety/Urgency Prediction Machine

The SUPM regime runs inside the core to monitor the health of the logging process and predict when the system might fail to meet its minimum viable trust level.

## Definitions

- **TSF** (Trust Success Fraction) = `ok / (ok + fail)`  
  Fraction of successful writes since start.

- **TSC** (Trust Stability Coefficient) = `ΔTSF / Δt`  
  Rate of change of TSF. Negative TSC means trust is eroding.

- **TTCC** (Time to Critical Condition) = `(TSF - min_viable) / (-TSC)` if TSC < 0, else infinity.  
  Estimated seconds until TSF falls below `min_viable` (default 0.95).

- **Pressure Ratio** – simulated error count (0–100%).  
  In the core, `pressure = err_cnt * 0.15` where `err_cnt` cycles 0..7.

## Regime Assignment

| Condition                              | Regime      |
|----------------------------------------|-------------|
| TTCC < 10 seconds OR pressure > 0.85   | CRITICAL    |
| pressure > 0.60                        | DEGRADED    |
| otherwise                              | SAFE        |

## Regime Effect

The `reserved[70]` bytes in the frame are filled with:
- SAFE: all zeros
- DEGRADED: 0xAA pattern
- CRITICAL: 0xFF pattern

This provides a visual/automated way to detect regime changes without parsing TSF/TSC/TTCC.

## Why SUPM?

Physical systems degrade over time. SUPM gives early warning before the ledger becomes unreliable (e.g., failing flash, full storage, excessive noise).  
The observer can act on regime changes to trigger healing (e.g., switch to a backup node, request checkpoint).