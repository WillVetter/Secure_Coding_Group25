# Makefile
# To run, from root:
# cd ./tests
# make

# To clean:
# make clean

SRC_DIR := ../src
BIN_DIR := bin

CC := gcc
CFLAGS := -std=c11 -pedantic-errors -Wall -Wextra -I$(SRC_DIR)
LDFLAGS := -lsodium
TARGET = $(BIN_DIR)/app

# Make a bin folder for the compilation files
$(shell mkdir -p $(BIN_DIR))

# Test names
TESTS := \
  test_account_create \
  test_account_record \
  test_account_status \
  test_handle_login \
  test_passwords

test_account_create_SRC := test_account_create.c $(SRC_DIR)/account.c $(SRC_DIR)/stubs.c
test_account_record_SRC := test_account_record.c $(SRC_DIR)/account.c $(SRC_DIR)/stubs.c
test_account_status_SRC := test_account_status.c $(SRC_DIR)/account.c $(SRC_DIR)/stubs.c
test_handle_login_SRC := test_handle_login.c $(SRC_DIR)/account.c $(SRC_DIR)/login.c $(SRC_DIR)/stubs.c
test_passwords_SRC := test_passwords.c $(SRC_DIR)/account.c $(SRC_DIR)/stubs.c

.PHONY: run_tests all clean $(TESTS)

run_tests: all

all: $(TESTS)

$(TESTS): %:
	@echo "[INFO]  Compiling $@ "
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $($@_SRC) $(LDFLAGS)
	@if [ $$? -eq 0 ]; then \
		echo "[INFO] Running $@..."; \
		$(BIN_DIR)/$@; \
	else \
		echo "[FAIL] Compilation failed for $@"; \
	fi

clean:
	rm -rf $(BIN_DIR) $(TARGET)
