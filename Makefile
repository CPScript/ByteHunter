CC = gcc
CXX = g++
CFLAGS = -std=c11 -O2 -Wall -Wextra -fPIC
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -fPIC
INCLUDES = -I./include
LDFLAGS = -shared

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    TARGET = ByteHunter.so
    IDA_LIB_PATH = lib/x64_linux_gcc_64
endif
ifeq ($(UNAME_S),Darwin)
    TARGET = ByteHunter.dylib
    IDA_LIB_PATH = lib/x64_mac_clang_64
    LDFLAGS += -undefined dynamic_lookup
endif
ifdef OS  # Windows
    TARGET = ByteHunter.dll
    IDA_LIB_PATH = lib/x64_win_vc_64
    LDFLAGS += -Wl,--enable-stdcall-fixup
endif

IDA_SDK ?= ../SDK/9
INCLUDES += -I$(IDA_SDK)/include
LIBS = -L$(IDA_SDK)/$(IDA_LIB_PATH) -lida

AVX2_SUPPORT := $(shell echo | $(CC) -mavx2 -E - > /dev/null 2>&1 && echo yes || echo no)
ifeq ($(AVX2_SUPPORT),yes)
    CFLAGS += -mavx2 -D__AVX2__
    CXXFLAGS += -mavx2 -D__AVX2__
endif

SRCDIR = src
C_SOURCES = $(shell find $(SRCDIR) -name '*.c')
CXX_SOURCES = $(shell find $(SRCDIR) -name '*.cpp')
C_OBJECTS = $(C_SOURCES:.c=.o)
CXX_OBJECTS = $(CXX_SOURCES:.cpp=.o)
OBJECTS = $(C_OBJECTS) $(CXX_OBJECTS)

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	mkdir -p ~/.idapro/plugins
	cp $(TARGET) ~/.idapro/plugins/

debug: CFLAGS += -g -DDEBUG
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

test: $(TARGET)
	@echo "Plugin built successfully: $(TARGET)"
	@file $(TARGET)

help:
	@echo "ByteHunter Build System"
	@echo "======================="
	@echo "Targets:"
	@echo "  all     - Build the plugin (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install plugin to IDA Pro plugins directory"
	@echo "  debug   - Build with debug information"
	@echo "  test    - Build and show file information"
	@echo ""
	@echo "Variables:"
	@echo "  IDA_SDK - Path to IDA SDK (default: ../SDK/9)"
	@echo ""
	@echo "Example: make IDA_SDK=/path/to/ida/sdk"
