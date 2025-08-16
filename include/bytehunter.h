#ifndef BYTEHUNTER_H
#define BYTEHUNTER_H

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <ua.hpp>

#include "types.h"

// Plugin metadata
#define BH_PLUGIN_NAME    "ByteHunter"
#define BH_PLUGIN_VERSION "1.0.2"
#define BH_PLUGIN_AUTHOR  "CPScript"
#define BH_PLUGIN_HOTKEY  "Ctrl-Alt-B"

// Configuration constants
#define BH_DEFAULT_MAX_SIG_LENGTH    1000
#define BH_DEFAULT_MAX_XREF_LENGTH   250
#define BH_DEFAULT_TOP_COUNT         5
#define BH_MIN_SIGNATURE_LENGTH      4
#define BH_BUFFER_CHUNK_SIZE         4096

// Global configuration
extern config_t g_config;
extern arch_type_t g_arch;

// Core plugin functions
bool bytehunter_init(void);
void bytehunter_cleanup(void);
bool bytehunter_run(size_t arg);

// Processor functions
void processor_init(void);
arch_type_t detect_architecture(void);
bool get_operand_info(const insn_t *insn, uint8_t *offset, uint8_t *length);

// UI functions
bool show_main_dialog(void);
void configure_operand_types(void);
void configure_settings(void);
bool execute_action(int action, signature_format_t format);

// Output functions  
bool generate_and_display_signature(ea_t address, signature_format_t format);
bool generate_and_display_xref_signatures(ea_t address, signature_format_t format);
bool copy_selected_bytes(signature_format_t format);
bool show_pattern_search_dialog(void);
const char* get_error_string(bh_error_t error);

// Format functions
void format_ida_style(const signature_t *sig, char *buffer, size_t buffer_size);
void format_x64dbg_style(const signature_t *sig, char *buffer, size_t buffer_size);
void format_c_array_style(const signature_t *sig, char *buffer, size_t buffer_size);
void format_hex_bytes_style(const signature_t *sig, char *buffer, size_t buffer_size);

// Memory utilities
void* bh_malloc(size_t size);
void* bh_realloc(void *ptr, size_t size);
void bh_free(void *ptr);
uint8_t* read_segments_to_buffer(size_t *total_size);

// Clipboard utilities
bool set_clipboard_text(const char *text);

// Pattern parsing functions
bool parse_ida_format(const char *input, signature_t *sig);
bool parse_x64dbg_format(const char *input, signature_t *sig);
bool parse_c_array_format(const char *input, signature_t *sig);
bool parse_hex_bytes_format(const char *input, signature_t *sig);

// Signature helper functions
bool should_wildcard_operands(const insn_t *insn);
bool add_instruction_with_wildcards(signature_t *sig, const insn_t *insn, ea_t addr);
bool pattern_match_at_position(const uint8_t *data, const signature_t *pattern);

// Bit manipulation macro
#define BIT(x) (1ULL << (x))

#endif
