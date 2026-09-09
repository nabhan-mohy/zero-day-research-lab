"""Makefile for test target."""

CC ?= gcc
CFLAGS ?= -O2 -g
LDFLAGS ?= 

OBJS = parser.o
TARGET = parser

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
