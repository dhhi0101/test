CC=gcc
CFLAGS=-std=c11 -O2 -Wall -Wextra -pthread
TARGET=red1

all: $(TARGET)

$(TARGET): red1.c
	$(CC) $(CFLAGS) -o $(TARGET) red1.c

clean:
	rm -f $(TARGET)
