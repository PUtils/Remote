CC = clang
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS = -lpthread

SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES))
DAEMON = $(BIN_DIR)/rtd
CLI = $(BIN_DIR)/rt

all: $(DAEMON) $(CLI)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(DAEMON): $(BUILD_DIR)/rtd.o $(BUILD_DIR)/auth.o $(BUILD_DIR)/session.o $(BUILD_DIR)/sandbox.o | $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS)

$(CLI): $(BUILD_DIR)/rt.o | $(BIN_DIR)
	$(CC) $^ -o $@

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

install: all
	install -m 755 $(DAEMON) /usr/local/bin/
	install -m 755 $(CLI) /usr/local/bin/

.PHONY: all clean install
