# ByteHunter

<div align="center">

![ByteHunter Logo](https://img.shields.io/badge/ByteHunter-v2.0.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-lightgrey)
![IDA Support](https://img.shields.io/badge/IDA%20Pro-8%20|%209-green)

*Reverse engineering tool for malware analysis, vulnerability research, and binary analysis*

</div>

---

## 🎯 Overview

ByteHunter is a IDA Pro plugin that changes binary signature generation and pattern matching. Built from the ground up in C with performance-critical optimizations, it provides advanced capabilities for reverse engineers, malware researchers, and security professionals.

### Key Features

- **🚀 Performance**: AVX2 SIMD-accelerated pattern matching for massive speed improvements
- **🎨 Multiple Output Formats**: Support for IDA, x64Dbg, C arrays, and hex byte formats
- **🧠 Intelligent Wildcarding**: Architecture-aware operand analysis and instruction optimization
- **🔍 Advanced Pattern Search**: Automatic format detection with robust parsing
- **📊 XREF Analysis**: Cross-reference signature generation with quality ranking
- **⚡ Memory Optimized**: Efficient memory management with dynamic allocation
- **🔧 Configurable**: Extensive customization options for different use cases

---

## 🛠 Installation

### Prerequisites

- **IDA Pro 8.0+ or 9.0+** (Professional or Freeware)
- **IDA SDK** corresponding to your IDA version
- **C/C++ Compiler**: GCC, Clang, or MSVC
- **CMake 3.12+** or Make

### Building from Source

#### Using CMake (Recommended)

```bash
git clone https://github.com/yourusername/ByteHunter.git
cd ByteHunter
mkdir build && cd build

# Configure for your IDA version
cmake -DIDA_SDK_PATH=/path/to/ida/sdk ..

# Build
cmake --build . --config Release

# Install
cmake --install . --prefix ~/.idapro/plugins
```

#### Using Makefile

```bash
git clone https://github.com/yourusername/ByteHunter.git
cd ByteHunter

# Build with custom SDK path
make IDA_SDK=/path/to/ida/sdk

# Install to IDA plugins directory
make install
```

#### Manual SDK Setup

1. **Download IDA SDK** from Hex-Rays website
2. **Extract to project directory**:
   ```
   ByteHunter/
   ├── SDK/
   │   ├── 8/          # IDA 8 SDK
   │   ├── 9/          # IDA 9 SDK
   │   └── 9beta/      # IDA 9 Beta SDK
   └── ...
   ```
3. **Build using your preferred method**

---

## 🚀 Usage

### Basic Operation

1. **Open target binary** in IDA Pro
2. **Navigate to desired location** in disassembly
3. **Press `Ctrl+Alt+B`** to open ByteHunter dialog
4. **Select action and format**, configure options
5. **Click OK** - signature copied to clipboard automatically

### Core Functions

#### 🎯 Unique Signature Generation

Generate minimal unique signatures for any code address:

```
Action: Unique signature
Location: Current cursor position
Result: E8 ? ? ? ? 48 89 C3 48 85 C0
```

**Use Cases:**
- Function identification across samples
- Code pattern matching
- Malware family detection
- Vulnerability signature creation

#### 🔗 XREF Signature Analysis  

Find and rank signatures from cross-references:

```
Action: XREF signatures
Target: Variable or function address
Result: Top 5 shortest signatures ranked by quality
```

**Benefits:**
- Discover alternative signature points
- Find more stable signatures
- Analyze calling patterns
- Reduce false positives

#### 📋 Selection Formatting

Convert selected bytes to various formats:

```
Action: Copy selection
Selection: Any byte range
Formats: IDA, x64Dbg, C Array, Hex Bytes
```

#### 🔍 Pattern Search

Search for patterns with automatic format detection:

```
Action: Pattern search
Input: Any signature format
Result: All matching locations
```

**Supported Formats:**
- `E8 ? ? ? ? 45` (IDA style)
- `E8 ?? ?? ?? ?? 45` (x64Dbg style)  
- `\xE8\x00\x00\x00\x00\x45 x????x` (C array + mask)
- `0xE8, 0x00, 0x00, 0x00, 0x00, 0x45 0b111110` (Hex + bitmask)

---

## 📖 Output Formats

### IDA Format
```
E8 ? ? ? ? 48 89 C3 48 85 C0 74 1A
```
- Single `?` for wildcards
- Space-separated hex bytes
- Direct paste into IDA

### x64Dbg Format
```  
E8 ?? ?? ?? ?? 48 89 C3 48 85 C0 74 1A
```
- Double `??` for wildcards
- Compatible with x64Dbg, Cheat Engine
- Standard debugger format

### C Array + Mask
```
\xE8\x00\x00\x00\x00\x48\x89\xC3\x48\x85\xC0\x74\x1A x????xxxxxxx
```
- C-style byte array
- String mask (`x` = match, `?` = wildcard)
- Perfect for custom tools
