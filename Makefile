# Makefile for NetDigger

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Output executable
TARGET = netdigger

# Source files
SRC = sniffer.c

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# Clean build files
clean:
	rm -f $(TARGET) *.o

# Run (with sudo, because raw sockets require root)
run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all clean run

