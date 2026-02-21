CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99 -D_GNU_SOURCE
LDFLAGS = -pthread

TARGET = iot-bruter
SRCS = main.c bruter.c scanner.c combos.c queue.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
