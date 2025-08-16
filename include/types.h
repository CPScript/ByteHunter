#ifndef BYTEHUNTER_TYPES_H
#define BYTEHUNTER_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Signature formats supported by ByteHunter
typedef enum {
    SIG_FORMAT_IDA = 0,        // "E8 ? ? ? ? 45"
    SIG_FORMAT_X64DBG,         // "E8 ?? ?? ?? ?? 45" 
    SIG_FORMAT_C_ARRAY,        // "\xE8\x00\x00\x00\x00\x45" + "x????x"
    SIG_FORMAT_HEX_BYTES       // "0xE8, 0x00, 0x00, 0x00, 0x00, 0x45" + bitmask
} signature_format_t;

// Individual signature byte with wildcard flag
typedef struct {
    uint8_t value;
    bool is_wildcard;
} sig_byte_t;

// Dynamic signature container
typedef struct {
    sig_byte_t *bytes;
    size_t count;
    size_t capacity;
} signature_t;

// Search configuration
typedef struct {
    bool wildcard_operands;
    bool continue_outside_func;
    bool wildcard_optimized_instr;
    uint32_t operand_type_mask;
    size_t max_signature_length;
    size_t max_xref_length;
    size_t print_top_count;
} config_t;

// Processor architecture types
typedef enum {
    ARCH_X86 = 0,
    ARCH_X64,
    ARCH_ARM,
    ARCH_ARM64,
    ARCH_MIPS,
    ARCH_PPC,
    ARCH_UNKNOWN
} arch_type_t;

// Search result structure
typedef struct {
    ea_t address;
    signature_t signature;
    size_t score;  // Quality metric for signature ranking
} search_result_t;

// Error codes
typedef enum {
    BH_SUCCESS = 0,
    BH_ERROR_INVALID_ADDRESS,
    BH_ERROR_MEMORY_ALLOC,
    BH_ERROR_NOT_CODE,
    BH_ERROR_SIGNATURE_TOO_LONG,
    BH_ERROR_NO_UNIQUE_SIGNATURE,
    BH_ERROR_USER_CANCELLED,
    BH_ERROR_DECODE_FAILED
} bh_error_t;

#endif
