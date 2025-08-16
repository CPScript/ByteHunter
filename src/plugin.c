#include "../include/bytehunter.h"

// Global configuration
config_t g_config = {
    .wildcard_operands = true,
    .continue_outside_func = false,
    .wildcard_optimized_instr = true,
    .operand_type_mask = 0, // Will be set by processor_init
    .max_signature_length = BH_DEFAULT_MAX_SIG_LENGTH,
    .max_xref_length = BH_DEFAULT_MAX_XREF_LENGTH,
    .print_top_count = BH_DEFAULT_TOP_COUNT
};

arch_type_t g_arch = ARCH_UNKNOWN;

// Plugin context structure
struct bytehunter_plugin_ctx : public plugmod_t {
    virtual ~bytehunter_plugin_ctx() {
        bytehunter_cleanup();
    }
    
    virtual bool idaapi run(size_t arg) override {
        return bytehunter_run(arg);
    }
};

// Plugin initialization
static plugmod_t* idaapi init() {
    if (!bytehunter_init()) {
        return nullptr;
    }
    return new bytehunter_plugin_ctx;
}

// Plugin descriptor
plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    init,
    nullptr,  // term
    nullptr,  // run (handled by plugmod_t)
    BH_PLUGIN_NAME " v" BH_PLUGIN_VERSION " - " BH_PLUGIN_AUTHOR,
    "Advanced signature generation and pattern matching for reverse engineering",
    BH_PLUGIN_NAME,
    BH_PLUGIN_HOTKEY
};

// Initialize plugin subsystems
bool bytehunter_init(void) {
    msg("ByteHunter v" BH_PLUGIN_VERSION " initializing...\n");
    
    // Initialize processor-specific settings
    processor_init();
    
    // Check for SIMD support
    if (pattern_has_simd_support()) {
        msg("ByteHunter: AVX2 SIMD acceleration enabled\n");
    }
    
    msg("ByteHunter: Initialization complete\n");
    return true;
}

// Cleanup plugin resources
void bytehunter_cleanup(void) {
    // Cleanup would go here if we had persistent resources
}

// Main plugin execution
bool bytehunter_run(size_t arg) {
    return show_main_dialog();
}

//==============================================================================
// Additional format parsing

// Parse IDA-style signatures "E8 ? ? ? ?"
static bool parse_ida_format(const char *input, signature_t *sig) {
    if (!input || !sig) return false;
    
    const char *pos = input;
    while (*pos) {
        // Skip whitespace
        while (*pos == ' ' || *pos == '\t') pos++;
        if (!*pos) break;
        
        if (*pos == '?') {
            // Wildcard byte
            if (!sig_add_byte(sig, 0, true)) return false;
            pos++;
        } else if (isxdigit(*pos) && isxdigit(*(pos + 1))) {
            // Hex byte
            char hex_str[3] = {*pos, *(pos + 1), 0};
            uint8_t value = (uint8_t)strtol(hex_str, NULL, 16);
            if (!sig_add_byte(sig, value, false)) return false;
            pos += 2;
        } else {
            pos++; // Skip invalid characters
        }
    }
    
    return sig->count > 0;
}

// Parse x64Dbg-style signatures "E8 ?? ?? ?? ??"
static bool parse_x64dbg_format(const char *input, signature_t *sig) {
    if (!input || !sig) return false;
    
    const char *pos = input;
    while (*pos) {
        // Skip whitespace
        while (*pos == ' ' || *pos == '\t') pos++;
        if (!*pos) break;
        
        if (*pos == '?' && *(pos + 1) == '?') {
            // Wildcard byte
            if (!sig_add_byte(sig, 0, true)) return false;
            pos += 2;
        } else if (isxdigit(*pos) && isxdigit(*(pos + 1))) {
            // Hex byte
            char hex_str[3] = {*pos, *(pos + 1), 0};
            uint8_t value = (uint8_t)strtol(hex_str, NULL, 16);
            if (!sig_add_byte(sig, value, false)) return false;
            pos += 2;
        } else {
            pos++; // Skip invalid characters
        }
    }
    
    return sig->count > 0;
}

// Parse C array format "\xE8\x00\x00\x00\x00" with mask "x????x"
static bool parse_c_array_format(const char *input, signature_t *sig) {
    if (!input || !sig) return false;
    
    // Extract hex bytes
    const char *hex_pos = strstr(input, "\\x");
    if (!hex_pos) return false;
    
    std::vector<uint8_t> bytes;
    while (hex_pos && *hex_pos) {
        hex_pos += 2; // Skip "\x"
        if (isxdigit(*hex_pos) && isxdigit(*(hex_pos + 1))) {
            char hex_str[3] = {*hex_pos, *(hex_pos + 1), 0};
            bytes.push_back((uint8_t)strtol(hex_str, NULL, 16));
            hex_pos += 2;
            hex_pos = strstr(hex_pos, "\\x");
        } else {
            break;
        }
    }
    
    // Extract mask
    const char *mask_pos = input;
    while (*mask_pos && (*mask_pos == 'x' || *mask_pos == '?')) {
        mask_pos++;
    }
    
    // Find mask pattern
    const char *mask_start = NULL;
    for (const char *p = input; *p; p++) {
        if ((*p == 'x' || *p == '?') && 
            (p == input || (!isxdigit(*(p-1)) && *(p-1) != 'x'))) {
            mask_start = p;
            break;
        }
    }
    
    if (!mask_start || bytes.empty()) return false;
    
    // Apply mask to bytes
    for (size_t i = 0; i < bytes.size() && mask_start[i]; i++) {
        bool is_wildcard = (mask_start[i] == '?');
        if (!sig_add_byte(sig, bytes[i], is_wildcard)) return false;
    }
    
    return sig->count > 0;
}

// Parse hex bytes format "0xE8, 0x00, 0x00" with bitmask "0b11100"
static bool parse_hex_bytes_format(const char *input, signature_t *sig) {
    if (!input || !sig) return false;
    
    // Extract hex bytes
    std::vector<uint8_t> bytes;
    const char *pos = input;
    while ((pos = strstr(pos, "0x")) != NULL) {
        pos += 2;
        if (isxdigit(*pos) && isxdigit(*(pos + 1))) {
            char hex_str[3] = {*pos, *(pos + 1), 0};
            bytes.push_back((uint8_t)strtol(hex_str, NULL, 16));
            pos += 2;
        }
    }
    
    // Extract bitmask
    const char *mask_pos = strstr(input, "0b");
    if (!mask_pos || bytes.empty()) return false;
    
    mask_pos += 2;
    size_t mask_len = strspn(mask_pos, "01");
    
    // Apply bitmask (note: bitmask is typically reversed)
    for (size_t i = 0; i < bytes.size() && i < mask_len; i++) {
        size_t mask_idx = mask_len - 1 - i; // Reverse bit order
        bool is_wildcard = (mask_pos[mask_idx] == '0');
        if (!sig_add_byte(sig, bytes[i], is_wildcard)) return false;
    }
    
    return sig->count > 0;
}
