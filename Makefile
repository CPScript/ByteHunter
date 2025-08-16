CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -fPIC -mavx2
INCLUDES = -I./include -I$(IDA_SDK)/include
LDFLAGS = -shared
TARGET = ByteHunter.dll
SRCDIR = src
SOURCES = $(shell find $(SRCDIR) -name '*.c')
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ -lida

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
