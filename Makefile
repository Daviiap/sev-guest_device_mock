TARGET = bin/sev-guest

.PHONY: all clean go_build

all: create_directories go_build

create_directories:
	mkdir -p bin

go_build:
	go build -o $(TARGET) main.go

clean:
	rm -rf $(TARGET)
