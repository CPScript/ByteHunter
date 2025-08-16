#include "../include/bytehunter.h"
#include "../include/signature.h"
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

// Check if instruction operands should be wildcarded
static bool should_wildcard_operands(const insn_t *insn) {
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
static bool add_instruction_with_wildcards(signature_t *sig, const insn_t *insn, ea_t addr) {
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

// Check if signature has unique matches in binary
bool sig_is_unique(const signature_t *sig) {
    if (!sig || sig->count == 0) return false;
    
    ea_t *matches = NULL;
    size_t match_count = sig_find_occurrences(sig, &matches);
    
    bool is_unique = (match_count == 1);
    free(matches);
    return is_unique;
}
