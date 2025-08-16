#include "../../include/bytehunter.h"
#include "../../include/signature.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

signature_t* sig_create(size_t initial_capacity) {
    signature_t *sig = (signature_t*)calloc(1, sizeof(signature_t));
    if (!sig) return NULL;
    
    if (initial_capacity == 0) initial_capacity = 32;
    
    sig->bytes = (sig_byte_t*)malloc(sizeof(sig_byte_t) * initial_capacity);
    if (!sig->bytes) {
        free(sig);
        return NULL;
    }
    
    sig->capacity = initial_capacity;
    sig->count = 0;
    return sig;
}

void sig_destroy(signature_t *sig) {
    if (!sig) return;
    free(sig->bytes);
    free(sig);
}

bool sig_reserve(signature_t *sig, size_t capacity) {
    if (!sig || capacity <= sig->capacity) return true;
    
    sig_byte_t *new_bytes = (sig_byte_t*)realloc(sig->bytes, sizeof(sig_byte_t) * capacity);
    if (!new_bytes) return false;
    
    sig->bytes = new_bytes;
    sig->capacity = capacity;
    return true;
}

bool sig_add_byte(signature_t *sig, uint8_t value, bool is_wildcard) {
    if (!sig) return false;
    
    if (sig->count >= sig->capacity) {
        if (!sig_reserve(sig, sig->capacity * 2)) return false;
    }
    
    sig->bytes[sig->count].value = value;
    sig->bytes[sig->count].is_wildcard = is_wildcard;
    sig->count++;
    return true;
}

bool sig_add_bytes(signature_t *sig, ea_t address, size_t count, bool wildcards) {
    if (!sig) return false;
    
    for (size_t i = 0; i < count; i++) {
        uint8_t byte_val = get_byte(address + i);
        if (!sig_add_byte(sig, byte_val, wildcards)) return false;
    }
    return true;
}

void sig_trim_wildcards(signature_t *sig) {
    if (!sig || sig->count == 0) return;
    
    while (sig->count > 0 && sig->bytes[sig->count - 1].is_wildcard) {
        sig->count--;
    }
}

signature_t* sig_clone(const signature_t *sig) {
    if (!sig) return NULL;
    
    signature_t *clone = sig_create(sig->count);
    if (!clone) return NULL;
    
    for (size_t i = 0; i < sig->count; i++) {
        if (!sig_add_byte(clone, sig->bytes[i].value, sig->bytes[i].is_wildcard)) {
            sig_destroy(clone);
            return NULL;
        }
    }
    
    return clone;
}

// Check if instruction operands should be wildcarded
bool should_wildcard_operands(const insn_t *insn) {
    if (!insn || !g_config.wildcard_operands) return false;
    
    for (int i = 0; i < UA_MAXOP; i++) {
        const op_t *op = &insn->ops[i];
        if (op->type == o_void) break;
        
        if ((BIT(op->type) & g_config.operand_type_mask) != 0) {
            return true;
        }
    }
    return false;
}

// Add instruction with operand wildcarding
bool add_instruction_with_wildcards(signature_t *sig, const insn_t *insn, ea_t addr) {
    if (!sig || !insn) return false;
    
    uint8_t operand_offset = 0, operand_length = 0;
    bool has_operand = get_operand_info(insn, &operand_offset, &operand_length);
    
    if (has_operand && operand_length > 0) {
        // Add opcode bytes before operand
        if (!sig_add_bytes(sig, addr, operand_offset, false)) return false;
        
        // Add wildcarded operand
        if (!sig_add_bytes(sig, addr + operand_offset, operand_length, true)) return false;
        
        // Add remaining bytes after operand
        size_t remaining = insn->size - operand_offset - operand_length;
        if (remaining > 0) {
            if (!sig_add_bytes(sig, addr + operand_offset + operand_length, remaining, false)) {
                return false;
            }
        }
    } else {
        // No operand wildcarding needed
        if (!sig_add_bytes(sig, addr, insn->size, false)) return false;
    }
    
    return true;
}

// Generate unique signature for given address
bh_error_t generate_unique_signature(ea_t address, signature_t **result) {
    if (!result) return BH_ERROR_INVALID_ADDRESS;
    *result = NULL;
    
    if (address == BADADDR || !is_code(get_flags(address))) {
        return BH_ERROR_NOT_CODE;
    }
    
    signature_t *sig = sig_create(64);
    if (!sig) return BH_ERROR_MEMORY_ALLOC;
    
    func_t *current_func = get_func(address);
    ea_t current_addr = address;
    size_t total_length = 0;
    
    while (total_length < g_config.max_signature_length) {
        if (user_cancelled()) {
            sig_destroy(sig);
            return BH_ERROR_USER_CANCELLED;
        }
        
        insn_t insn;
        int insn_len = decode_insn(&insn, current_addr);
        if (insn_len <= 0) {
            if (sig->count == 0) {
                sig_destroy(sig);
                return BH_ERROR_DECODE_FAILED;
            }
            break;
        }
        
        // Add instruction bytes with operand wildcarding
        if (g_config.wildcard_operands && should_wildcard_operands(&insn)) {
            if (!add_instruction_with_wildcards(sig, &insn, current_addr)) {
                sig_destroy(sig);
                return BH_ERROR_MEMORY_ALLOC;
            }
        } else {
            if (!sig_add_bytes(sig, current_addr, insn_len, false)) {
                sig_destroy(sig);
                return BH_ERROR_MEMORY_ALLOC;
            }
        }
        
        // Check if signature is unique
        if (sig->count >= BH_MIN_SIGNATURE_LENGTH && sig_is_unique(sig)) {
            sig_trim_wildcards(sig);
            *result = sig;
            return BH_SUCCESS;
        }
        
        current_addr += insn_len;
        total_length += insn_len;
        
        // Stop if leaving function scope
        if (!g_config.continue_outside_func && current_func && 
            get_func(current_addr) != current_func) {
            break;
        }
    }
    
    sig_destroy(sig);
    return BH_ERROR_NO_UNIQUE_SIGNATURE;
}

bh_error_t generate_range_signature(ea_t start, ea_t end, signature_t **result) {
    if (!result || start == BADADDR || end == BADADDR || start >= end) {
        return BH_ERROR_INVALID_ADDRESS;
    }
    
    *result = NULL;
    
    signature_t *sig = sig_create(end - start);
    if (!sig) return BH_ERROR_MEMORY_ALLOC;
    
    // For data sections, just copy bytes without wildcards
    if (!is_code(get_flags(start))) {
        if (!sig_add_bytes(sig, start, end - start, false)) {
            sig_destroy(sig);
            return BH_ERROR_MEMORY_ALLOC;
        }
        *result = sig;
        return BH_SUCCESS;
    }
    
    // For code sections, process instruction by instruction
    ea_t current_addr = start;
    while (current_addr < end) {
        if (user_cancelled()) {
            sig_destroy(sig);
            return BH_ERROR_USER_CANCELLED;
        }
        
        insn_t insn;
        int insn_len = decode_insn(&insn, current_addr);
        if (insn_len <= 0) {
            // Add remaining bytes as-is if decode fails
            if (!sig_add_bytes(sig, current_addr, end - current_addr, false)) {
                sig_destroy(sig);
                return BH_ERROR_MEMORY_ALLOC;
            }
            break;
        }
        
        size_t bytes_to_add = (current_addr + insn_len > end) ? 
                              (end - current_addr) : insn_len;
        
        // Add instruction with optional operand wildcarding
        if (g_config.wildcard_operands && should_wildcard_operands(&insn)) {
            if (!add_instruction_with_wildcards(sig, &insn, current_addr)) {
                sig_destroy(sig);
                return BH_ERROR_MEMORY_ALLOC;
            }
        } else {
            if (!sig_add_bytes(sig, current_addr, bytes_to_add, false)) {
                sig_destroy(sig);
                return BH_ERROR_MEMORY_ALLOC;
            }
        }
        
        current_addr += insn_len;
    }
    
    sig_trim_wildcards(sig);
    *result = sig;
    return BH_SUCCESS;
}

static int compare_search_results(const void *a, const void *b) {
    const search_result_t *sa = (const search_result_t*)a;
    const search_result_t *sb = (const search_result_t*)b;
    return (int)sa->score - (int)sb->score;
}

bh_error_t generate_xref_signatures(ea_t address, search_result_t **results, size_t *count) {
    if (!results || !count) return BH_ERROR_INVALID_ADDRESS;
    
    *results = NULL;
    *count = 0;
    
    // Find all cross-references to the address
    xrefblk_t xref;
    size_t xref_count = 0;
    
    // Count total xrefs first
    for (bool ok = xref.first_to(address, XREF_FAR); ok; ok = xref.next_to()) {
        if (is_code(get_flags(xref.from))) {
            xref_count++;
        }
    }
    
    if (xref_count == 0) return BH_SUCCESS;
    
    // Allocate results array
    search_result_t *xref_results = (search_result_t*)bh_malloc(
        sizeof(search_result_t) * xref_count);
    if (!xref_results) return BH_ERROR_MEMORY_ALLOC;
    
    size_t valid_count = 0;
    size_t processed = 0;
    
    // Generate signatures for each xref
    for (bool ok = xref.first_to(address, XREF_FAR); ok; ok = xref.next_to()) {
        if (!is_code(get_flags(xref.from))) continue;
        
        if (user_cancelled()) {
            // Cleanup partial results
            for (size_t i = 0; i < valid_count; i++) {
                sig_destroy(&xref_results[i].signature);
            }
            bh_free(xref_results);
            return BH_ERROR_USER_CANCELLED;
        }
        
        // Update progress
        processed++;
        if (processed % 10 == 0) {
            replace_wait_box("Processing XREF %zu of %zu...", processed, xref_count);
        }
        
        signature_t *sig = NULL;
        bh_error_t result = generate_unique_signature(xref.from, &sig);
        
        if (result == BH_SUCCESS && sig) {
            xref_results[valid_count].address = xref.from;
            xref_results[valid_count].signature = *sig;
            xref_results[valid_count].score = sig->count; // Use signature length as score
            valid_count++;
            bh_free(sig); // Free the container but keep the signature data
        }
    }
    
    // Sort by signature length (shorter is better)
    qsort(xref_results, valid_count, sizeof(search_result_t), compare_search_results);
    
    *results = xref_results;
    *count = valid_count;
    return BH_SUCCESS;
}

// Format signature to specified output format
char* sig_format(const signature_t *sig, signature_format_t format) {
    if (!sig || sig->count == 0) return NULL;
    
    size_t buffer_size = sig->count * 16; // Conservative estimate
    char *buffer = (char*)malloc(buffer_size);
    if (!buffer) return NULL;
    
    buffer[0] = '\0';
    
    switch (format) {
        case SIG_FORMAT_IDA:
            format_ida_style(sig, buffer, buffer_size);
            break;
        case SIG_FORMAT_X64DBG:
            format_x64dbg_style(sig, buffer, buffer_size);
            break;
        case SIG_FORMAT_C_ARRAY:
            format_c_array_style(sig, buffer, buffer_size);
            break;
        case SIG_FORMAT_HEX_BYTES:
            format_hex_bytes_style(sig, buffer, buffer_size);
            break;
        default:
            free(buffer);
            return NULL;
    }
    
    return buffer;
}

size_t sig_find_occurrences(const signature_t *sig, ea_t **addresses) {
    if (!sig || sig->count == 0 || !addresses) return 0;
    
    *addresses = NULL;
    
    // Convert signature to IDA pattern string
    char *pattern_str = sig_format(sig, SIG_FORMAT_IDA);
    if (!pattern_str) return 0;
    
    // Use IDA's binary pattern search
    compiled_binpat_vec_t binpat;
    parse_binpat_str(&binpat, inf_get_min_ea(), pattern_str, 16);
    
    // Find all occurrences
    size_t capacity = 16;
    ea_t *results = (ea_t*)bh_malloc(sizeof(ea_t) * capacity);
    size_t count = 0;
    
    ea_t current_ea = inf_get_min_ea();
    while (current_ea != BADADDR) {
        current_ea = bin_search(current_ea, inf_get_max_ea(), binpat, 
                               BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);
        
        if (current_ea == BADADDR) break;
        
        // Resize if needed
        if (count >= capacity) {
            capacity *= 2;
            ea_t *new_results = (ea_t*)bh_realloc(results, sizeof(ea_t) * capacity);
            if (!new_results) {
                bh_free(results);
                bh_free(pattern_str);
                return 0;
            }
            results = new_results;
        }
        
        results[count++] = current_ea;
        current_ea += 1; // Move past current match
    }
    
    bh_free(pattern_str);
    *addresses = results;
    return count;
}

// Check if signature has unique matches in binary
bool sig_is_unique(const signature_t *sig) {
    if (!sig || sig->count == 0) return false;
    
    ea_t *matches = NULL;
    size_t match_count = sig_find_occurrences(sig, &matches);
    
    bool is_unique = (match_count == 1);
    bh_free(matches);
    return is_unique;
}
