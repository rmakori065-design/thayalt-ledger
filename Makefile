# THAYALT Makefile – build core and observers, run, verify, audit

CC       = gcc
CFLAGS   = -O2 -std=c99 -Wall -Wextra -lm
LDFLAGS  = -lm

# Directories
CORE_DIR     = core
OBSERVERS_DIR = observers

# Targets
CORE_TARGET     = $(CORE_DIR)/thayalt_core
SENTINEL_TARGET = $(OBSERVERS_DIR)/thayalt_sentinel
AUDITOR_TARGET  = $(OBSERVERS_DIR)/thayalt_auditor
ALL_TARGETS     = $(CORE_TARGET) $(SENTINEL_TARGET) $(AUDITOR_TARGET)

# Source files
CORE_SRC     = $(CORE_DIR)/thayalt_core.c
SENTINEL_SRC = $(OBSERVERS_DIR)/thayalt_sentinel.c
AUDITOR_SRC  = $(OBSERVERS_DIR)/thayalt_auditor.c

# Default target: build everything
all: $(ALL_TARGETS)

$(CORE_DIR)/thayalt_core: $(CORE_SRC)
	@mkdir -p $(CORE_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(OBSERVERS_DIR)/thayalt_sentinel: $(SENTINEL_SRC)
	@mkdir -p $(OBSERVERS_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(OBSERVERS_DIR)/thayalt_auditor: $(AUDITOR_SRC)
	@mkdir -p $(OBSERVERS_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Run the core (foreground, Ctrl+C to stop)
run: $(CORE_TARGET)
	./$(CORE_TARGET)

# Run core and save stderr to a log file
rund: $(CORE_TARGET)
	./$(CORE_TARGET) 2>> core.log

# Verify the current ledger using sentinel
verify: $(SENTINEL_TARGET)
	@if [ ! -f thayalt_core.log ]; then \
		echo "No ledger found. Run 'make run' first to generate thayalt_core.log"; \
		exit 1; \
	fi
	./$(SENTINEL_TARGET) thayalt_core.log > sentinel_cert.bin
	@echo "Sentinel finished. Exit code $$? (0 = valid, 2 = errors)"
	@echo "Certificate written to sentinel_cert.bin (binary)"

# Audit the ledger using auditor
audit: $(AUDITOR_TARGET)
	@if [ ! -f thayalt_core.log ]; then \
		echo "No ledger found. Run 'make run' first."; \
		exit 1; \
	fi
	./$(AUDITOR_TARGET) thayalt_core.log

# Clean: remove binaries only
clean:
	rm -f $(CORE_TARGET) $(SENTINEL_TARGET) $(AUDITOR_TARGET)

# Clean everything, including logs and certificates
clean-all: clean
	rm -f thayalt_core.log thayalt_checkpoints.log core.log sentinel_cert.bin

# Help
help:
	@echo "THAYALT Makefile targets:"
	@echo "  make           – build core, sentinel, auditor"
	@echo "  make run       – start the core (Ctrl+C to stop)"
	@echo "  make rund      – start core, stderr logged to core.log"
	@echo "  make verify    – run sentinel on thayalt_core.log, produce certificate"
	@echo "  make audit     – run auditor on thayalt_core.log"
	@echo "  make clean     – remove binaries only"
	@echo "  make clean-all – remove binaries + ledger files + certificate"
	@echo "  make help      – show this help"

.PHONY: all run rund verify audit clean clean-all help