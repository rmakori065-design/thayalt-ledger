# Bill of Materials (BOM) – THAYALT Core

The core runs on any C99-capable microcontroller or POSIX system.  
Minimum viable deployment costs under $10.

## Minimum Hardware

| Component               | Example               | Cost (approx) |
|------------------------|-----------------------|--------------|
| Microcontroller        | Arduino Uno (ATmega328P) | $5-10       |
| Power source           | USB cable + laptop/power bank | –         |
| Optional: RTC module   | DS3231                | $5           |

## Verified Boards

| Board                  | RAM    | Flash  | Status        |
|------------------------|--------|--------|---------------|
| Arduino Uno (ATmega328P) | 2KB  | 32KB   | ✓ Tested      |
| Arduino Mega (ATmega2560)| 8KB  | 256KB  | ✓ Compatible  |
| STM32F103 (Blue Pill)  | 20KB   | 64KB   | ✓ Compatible  |
| Raspberry Pi Pico      | 264KB  | 2MB    | ✓ Compatible  |
| ESP8266 / ESP32        | 80KB+  | 4MB+   | ✓ Compatible  |
| Any POSIX system (Linux, MSYS2) | – | – | ✓ Used for simulation |

## Upstream Observer Hardware

- Raspberry Pi Zero (or any Linux machine) – $5-10
- Storage: SD card or USB drive for the ledger file

The core sends 128‑byte frames over serial, I2C, RS‑485, or LoRa.  
The observer (separate program) runs upstream and verifies the ledger.