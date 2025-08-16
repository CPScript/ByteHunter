#include "../include/bytehunter.h"

// Display signature generation results
bool generate_and_display_signature(ea_t address, signature_format_t format) {
    if (address == BADADDR) {
        msg("ByteHunter: Invalid address\n");
        return false;
    }
    
    show_wait_box("Generating signature...");
    
    signature_t *sig = NULL;
    bh_error_t result = generate_unique_signature(address, &sig);
    
    hide_wait_box();
    
    if (result != BH_SUCCESS) {
        msg("ByteHunter: %s\n", get_error_string(result));
        return false;
    }
    
    char *formatted = sig_format(sig, format);
    if (formatted) {
        msg("ByteHunter: Signature for %a: %s\n", address, formatted);
        set_clipboard_text(formatted);
        msg("ByteHunter: Signature copied to clipboard\n");
        bh_free(formatted);
    }
    
    sig_destroy(sig);
    return true;
}

// Display XREF signature results
bool generate_and_display_xref_signatures(ea_t address, signature_format_t format) {
    show_wait_box("Finding cross-references and generating signatures...");
    
    search_result_t *results = NULL;
    size_t count = 0;
    bh_error_t error = generate_xref_signatures(address, &results, &count);
    
    hide_wait_box();
    
    if (error != BH_SUCCESS) {
        msg("ByteHunter: %s\n", get_error_string(error));
        return false;
    }
    
    if (count == 0) {
        msg("ByteHunter: No suitable XREF signatures found\n");
        return false;
    }
    
    size_t display_count = (count < g_config.print_top_count) ? count : g_config.print_top_count;
    msg("ByteHunter: Top %zu XREF signatures for %a:\n", display_count, address);
    
    char *first_sig = NULL;
    for (size_t i = 0; i < display_count; i++) {
        char *formatted = sig_format(&results[i].signature, format);
        if (formatted) {
            msg("  #%zu @ %a (%zu bytes): %s\n", 
                i + 1, results[i].address, results[i].signature.count, formatted);
            
            if (i == 0) {
                first_sig = formatted;
            } else {
                bh_free(formatted);
            }
        }
    }
    
    if (first_sig) {
        set_clipboard_text(first_sig);
        msg("ByteHunter: Best signature copied to clipboard\n");
        bh_free(first_sig);
    }
    
    // Cleanup
    for (size_t i = 0; i < count; i++) {
        sig_destroy(&results[i].signature);
    }
    bh_free(results);
    
    return true;
}

// Copy selected bytes with formatting
bool copy_selected_bytes(signature_format_t format) {
    ea_t start, end;
    if (!read_range_selection(get_current_viewer(), &start, &end)) {
        msg("ByteHunter: Please select a range first\n");
        return false;
    }
    
    signature_t *sig = NULL;
    bh_error_t result = generate_range_signature(start, end, &sig);
    
    if (result != BH_SUCCESS) {
        msg("ByteHunter: %s\n", get_error_string(result));
        return false;
    }
    
    char *formatted = sig_format(sig, format);
    if (formatted) {
        msg("ByteHunter: Selection %a-%a: %s\n", start, end, formatted);
        set_clipboard_text(formatted);
        msg("ByteHunter: Selection copied to clipboard\n");
        bh_free(formatted);
    }
    
    sig_destroy(sig);
    return true;
}

// Show pattern search dialog
bool show_pattern_search_dialog(void) {
    qstring pattern_input;
    if (!ask_str(&pattern_input, HIST_SRCH, "Enter pattern to search for:")) {
        return false;
    }
    
    show_wait_box("Searching for pattern...");
    
    pattern_ctx_t *ctx = pattern_compile(pattern_input.c_str());
    if (!ctx) {
        hide_wait_box();
        msg("ByteHunter: Invalid pattern format\n");
        return false;
    }
    
    ea_t *matches = NULL;
    size_t match_count = pattern_search(ctx, inf_get_min_ea(), inf_get_max_ea(), &matches);
    
    hide_wait_box();
    
    if (match_count == 0) {
        msg("ByteHunter: Pattern not found\n");
    } else {
        msg("ByteHunter: Found %zu matches for pattern:\n", match_count);
        for (size_t i = 0; i < match_count && i < 20; i++) { // Limit output
            msg("  Match #%zu: %a\n", i + 1, matches[i]);
        }
        if (match_count > 20) {
            msg("  ... and %zu more matches\n", match_count - 20);
        }
    }
    
    pattern_destroy(ctx);
    bh_free(matches);
    return true;
}

// Format signature strings for different output types
static void format_ida_style(const signature_t *sig, char *buffer, size_t buffer_size) {
    size_t pos = 0;
    for (size_t i = 0; i < sig->count && pos < buffer_size - 3; i++) {
        if (sig->bytes[i].is_wildcard) {
            buffer[pos++] = '?';
        } else {
            pos += snprintf(buffer + pos, buffer_size - pos, "%02X", sig->bytes[i].value);
        }
        if (i < sig->count - 1) buffer[pos++] = ' ';
    }
    buffer[pos] = '\0';
}

static void format_x64dbg_style(const signature_t *sig, char *buffer, size_t buffer_size) {
    size_t pos = 0;
    for (size_t i = 0; i < sig->count && pos < buffer_size - 4; i++) {
        if (sig->bytes[i].is_wildcard) {
            buffer[pos++] = '?';
            buffer[pos++] = '?';
        } else {
            pos += snprintf(buffer + pos, buffer_size - pos, "%02X", sig->bytes[i].value);
        }
        if (i < sig->count - 1) buffer[pos++] = ' ';
    }
    buffer[pos] = '\0';
}

static void format_c_array_style(const signature_t *sig, char *buffer, size_t buffer_size) {
    size_t pos = 0;
    
    // Generate byte array
    for (size_t i = 0; i < sig->count && pos < buffer_size - 8; i++) {
        pos += snprintf(buffer + pos, buffer_size - pos, "\\x%02X", 
                       sig->bytes[i].is_wildcard ? 0 : sig->bytes[i].value);
    }
    
    // Add mask
    pos += snprintf(buffer + pos, buffer_size - pos, " ");
    for (size_t i = 0; i < sig->count && pos < buffer_size - 2; i++) {
        buffer[pos++] = sig->bytes[i].is_wildcard ? '?' : 'x';
    }
    buffer[pos] = '\0';
}

static void format_hex_bytes_style(const signature_t *sig, char *buffer, size_t buffer_size) {
    size_t pos = 0;
    
    // Generate hex bytes
    for (size_t i = 0; i < sig->count && pos < buffer_size - 8; i++) {
        pos += snprintf(buffer + pos, buffer_size - pos, "0x%02X", 
                       sig->bytes[i].is_wildcard ? 0 : sig->bytes[i].value);
        if (i < sig->count - 1) {
            pos += snprintf(buffer + pos, buffer_size - pos, ", ");
        }
    }
    
    // Add bitmask
    pos += snprintf(buffer + pos, buffer_size - pos, " 0b");
    for (int i = sig->count - 1; i >= 0 && pos < buffer_size - 2; i--) {
        buffer[pos++] = sig->bytes[i].is_wildcard ? '0' : '1';
    }
    buffer[pos] = '\0';
}

// Get human-readable error strings
const char* get_error_string(bh_error_t error) {
    switch (error) {
        case BH_SUCCESS: return "Success";
        case BH_ERROR_INVALID_ADDRESS: return "Invalid address";
        case BH_ERROR_MEMORY_ALLOC: return "Memory allocation failed";
        case BH_ERROR_NOT_CODE: return "Address does not contain code";
        case BH_ERROR_SIGNATURE_TOO_LONG: return "Signature exceeds maximum length";
        case BH_ERROR_NO_UNIQUE_SIGNATURE: return "Could not generate unique signature";
        case BH_ERROR_USER_CANCELLED: return "Operation cancelled by user";
        case BH_ERROR_DECODE_FAILED: return "Failed to decode instruction";
        default: return "Unknown error";
    }
}
