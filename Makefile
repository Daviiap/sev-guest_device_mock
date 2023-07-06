CC = gcc
CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 `pkg-config fuse --cflags`
LDFLAGS = `pkg-config fuse --libs`

TARGET = bin/sev-guest
SRC_DIR = src
OBJ_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))

.PHONY: all clean

all: create_directories $(TARGET)

create_directories:
	mkdir -p bin

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ -lssl -lcrypto $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
