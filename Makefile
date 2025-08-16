CC = gcc
CXX = g++
CFLAGS = -std=c11 -O2 -Wall -Wextra -fPIC
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -fPIC
INCLUDES = -I./include
LDFLAGS = -shared

# Detect platform
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    TARGET = ByteHunter.so
    IDA_LIB_PATH = lib/x64_linux_gcc_64
    PLATFORM_LIBS = 
endif
ifeq ($(UNAME_S),Darwin)
    TARGET = ByteHunter.dylib
    IDA_LIB_PATH = lib/x64_mac_clang_64
    LDFLAGS += -undefined dynamic_lookup
    PLATFORM_LIBS = -framework ApplicationServices
endif
ifdef OS  # Windows
    TARGET = ByteHunter.dll
    IDA_LIB_PATH = lib/x64_win_vc_64
    LDFLAGS += -Wl,--enable-stdcall-fixup
    PLATFORM_LIBS = 
endif

# IDA SDK configuration
IDA_SDK ?= ../SDK/9
INCLUDES += -I$(IDA_SDK)/include
LIBS = -L$(IDA_SDK)/$(IDA_LIB_PATH) -lida $(PLATFORM_LIBS)

# Compiler definitions
CFLAGS += -D__NT__ -D__IDP__
CXXFLAGS += -D__NT__ -D__IDP__

# 64-bit support
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    CFLAGS += -D__EA64__
    CXXFLAGS += -D__EA64__
endif

# Enable AVX2 if supported
AVX2_SUPPORT := $(shell echo | $(CC) -mavx2 -E - > /dev/null 2>&1 && echo yes || echo no)
ifeq ($(AVX2_SUPPORT),yes)
    CFLAGS += -mavx2 -D__AVX2__
    CXXFLAGS += -mavx2 -D__AVX2__
    $(info AVX2 SIMD acceleration enabled)
endif

# Source files
SRCDIR = src
C_SOURCES = $(shell find $(SRCDIR) -name '*.c')
CXX_SOURCES = $(shell find $(SRCDIR) -name '*.cpp')
C_OBJECTS = $(C_SOURCES:.c=.o)
CXX_OBJECTS = $(CXX_SOURCES:.cpp=.o)
OBJECTS = $(C_OBJECTS) $(CXX_OBJECTS)

# Build information
$(info ByteHunter Build Configuration:)
$(info   Platform: $(UNAME_S))
$(info   Target: $(TARGET))
$(info   IDA SDK: $(IDA_SDK))
$(info   Architecture: $(ARCH))

.PHONY: all clean install debug test help

# Default target
all: $(TARGET)

# Link the plugin
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Build complete: $(TARGET)"

# Compile C source files
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Compile C++ source files
%.o: %.cpp
	@echo "Compiling $<..."
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(OBJECTS) $(TARGET)
	@echo "Clean complete"

# Install plugin to IDA Pro plugins directory
install: $(TARGET)
	@echo "Installing ByteHunter plugin..."
	@if [ "$(UNAME_S)" = "Darwin" ]; then \
		mkdir -p ~/Library/Application\ Support/Hex-Rays/IDA\ Pro/plugins; \
		cp $(TARGET) ~/Library/Application\ Support/Hex-Rays/IDA\ Pro/plugins/; \
	elif [ "$(UNAME_S)" = "Linux" ]; then \
		mkdir -p ~/.idapro/plugins; \
		cp $(TARGET) ~/.idapro/plugins/; \
	else \
		mkdir -p "%APPDATA%\\Hex-Rays\\IDA Pro\\plugins"; \
		cp $(TARGET) "%APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\"; \
	fi
	@echo "Installation complete"

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)
	@echo "Debug build complete"

# Test build
test: $(TARGET)
	@echo "Testing plugin build..."
	@file $(TARGET)
	@echo "Plugin size: $$(stat -c%s $(TARGET) 2>/dev/null || stat -f%z $(TARGET)) bytes"
	@echo "Test complete"

# Show help
help:
	@echo "ByteHunter Build System"
	@echo "======================="
	@echo "Targets:"
	@echo "  all     - Build the plugin (default)"
	@echo "  clean   - Remove build artifacts"
	@echo "  install - Install plugin to IDA Pro plugins directory"
	@echo "  debug   - Build with debug information"
	@echo "  test    - Build and show file information"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  IDA_SDK - Path to IDA SDK (default: ../SDK/9)"
	@echo "  CC      - C compiler (default: gcc)"
	@echo "  CXX     - C++ compiler (default: g++)"
	@echo ""
	@echo "Examples:"
	@echo "  make IDA_SDK=/path/to/ida/sdk"
	@echo "  make debug"
	@echo "  make clean && make install"

# Dependency tracking
-include $(OBJECTS:.o=.d)

# Generate dependency files
%.d: %.c
	@$(CC) $(CFLAGS) $(INCLUDES) -MM $< > $@

%.d: %.cpp
	@$(CXX) $(CXXFLAGS) $(INCLUDES) -MM $< > $@
