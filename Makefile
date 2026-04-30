CC = gcc
CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags`
LDFLAGS = `pkg-config fuse --libs`
UUID_LDFLAGS    := -luuid

TARGET = bin/sev-guest
SRC_DIR = src
OBJ_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/crypto/*.c $(SRC_DIR)/fuse/*.c $(SRC_DIR)/snp/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))

.PHONY: all clean

all: create_directories $(TARGET)

create_directories:
	mkdir -p $(OBJ_DIR) $(OBJ_DIR)/crypto $(OBJ_DIR)/fuse $(OBJ_DIR)/snp

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ -lssl -lcrypto $(LDFLAGS) $(UUID_LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)/* $(TARGET)
