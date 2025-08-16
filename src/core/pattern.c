#include "../../include/pattern.h"
#include "../../include/bytehunter.h"
#include <stdlib.h>
#include <string.h>

#ifdef __AVX2__
#include <immintrin.h>
#endif

typedef struct pattern_ctx {
    signature_t *signature;
    compiled_binpat_vec_t ida_pattern;
    bool use_simd;
} pattern_ctx_t;

// Check for SIMD support at runtime
bool pattern_has_simd_support(void) {
    #ifdef __AVX2__
    return true;
    #else
    return false;
    #endif
}

pattern_ctx_t* pattern_compile(const char *pattern_string) {
    if (!pattern_string) return NULL;
    
    pattern_ctx_t *ctx = (pattern_ctx_t*)calloc(1, sizeof(pattern_ctx_t));
    if (!ctx) return NULL;
    
    // Parse pattern string into signature
    if (!pattern_parse_string(pattern_string, &ctx->signature)) {
        free(ctx);
        return NULL;
    }
    
    // Compile for IDA's binary search if SIMD not available
    ctx->use_simd = pattern_has_simd_support();
    if (!ctx->use_simd) {
        char *ida_pattern_str = sig_format(ctx->signature, SIG_FORMAT_IDA);
        if (ida_pattern_str) {
            parse_binpat_str(&ctx->ida_pattern, inf_get_min_ea(), ida_pattern_str, 16);
            bh_free(ida_pattern_str);
        }
    }
    
    return ctx;
}

void pattern_destroy(pattern_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->signature) sig_destroy(ctx->signature);
    free(ctx);
}

// IDA-based pattern search fallback
static size_t pattern_search_ida(pattern_ctx_t *ctx, ea_t start, ea_t end, ea_t **results) {
    if (!ctx || !results) return 0;
    
    *results = NULL;
    size_t capacity = 16;
    ea_t *matches = (ea_t*)bh_malloc(sizeof(ea_t) * capacity);
    if (!matches) return 0;
    
    size_t count = 0;
    ea_t current_ea = start;
    
    while (current_ea < end) {
        current_ea = bin_search(current_ea, end, ctx->ida_pattern, 
                               BIN_SEARCH_NOCASE | BIN_SEARCH_FORWARD);
        
        if (current_ea == BADADDR) break;
        
        // Resize if needed
        if (count >= capacity) {
            capacity *= 2;
            ea_t *new_matches = (ea_t*)bh_realloc(matches, sizeof(ea_t) * capacity);
            if (!new_matches) {
                bh_free(matches);
                return 0;
            }
            matches = new_matches;
        }
        
        matches[count++] = current_ea;
        current_ea += 1;
    }
    
    *results = matches;
    return count;
}

// SIMD wrapper function
static size_t pattern_search_simd_wrapper(pattern_ctx_t *ctx, ea_t start, ea_t end, ea_t **results) {
    if (!ctx || !results) return 0;
    
    // Read memory range into buffer
    size_t range_size = end - start;
    uint8_t *buffer = (uint8_t*)bh_malloc(range_size);
    if (!buffer) return 0;
    
    if (get_bytes(buffer, range_size, start) != range_size) {
        bh_free(buffer);
        return 0;
    }
    
    // Perform SIMD search
    size_t *offsets = NULL;
    size_t count = pattern_search_simd(buffer, range_size, ctx->signature, &offsets);
    
    // Convert offsets to addresses
    ea_t *addresses = NULL;
    if (count > 0) {
        addresses = (ea_t*)bh_malloc(sizeof(ea_t) * count);
        if (addresses) {
            for (size_t i = 0; i < count; i++) {
                addresses[i] = start + offsets[i];
            }
        }
        bh_free(offsets);
    }
    
    bh_free(buffer);
    *results = addresses;
    return addresses ? count : 0;
}

size_t pattern_search(pattern_ctx_t *ctx, ea_t start, ea_t end, ea_t **results) {
    if (!ctx || !results) return 0;
    
    *results = NULL;
    
    if (ctx->use_simd) {
        return pattern_search_simd_wrapper(ctx, start, end, results);
    } else {
        return pattern_search_ida(ctx, start, end, results);
    }
}

// Check if pattern matches at specific position
bool pattern_match_at_position(const uint8_t *data, const signature_t *pattern) {
    if (!data || !pattern) return false;
    
    for (size_t i = 0; i < pattern->count; i++) {
        if (!pattern->bytes[i].is_wildcard && data[i] != pattern->bytes[i].value) {
            return false;
        }
    }
    return true;
}

#ifdef __AVX2__
// SIMD-optimized pattern search
size_t pattern_search_simd(const uint8_t *haystack, size_t haystack_len,
                          const signature_t *needle, size_t **offsets) {
    if (!haystack || !needle || !offsets || needle->count == 0) return 0;
    
    *offsets = NULL;
    size_t *matches = (size_t*)bh_malloc(sizeof(size_t) * 1024);
    if (!matches) return 0;
    
    size_t match_count = 0;
    size_t match_capacity = 1024;
    
    // Get first non-wildcard byte for quick scanning
    uint8_t first_byte = 0;
    size_t first_offset = 0;
    bool found_first = false;
    
    for (size_t i = 0; i < needle->count; i++) {
        if (!needle->bytes[i].is_wildcard) {
            first_byte = needle->bytes[i].value;
            first_offset = i;
            found_first = true;
            break;
        }
    }
    
    if (!found_first) {
        // Pattern is all wildcards
        bh_free(matches);
        return 0;
    }
    
    __m256i first_vec = _mm256_set1_epi8(first_byte);
    
    for (size_t pos = first_offset; pos + 32 <= haystack_len && pos <= haystack_len - needle->count; pos += 32) {
        // Load 32 bytes and compare with first byte
        __m256i data = _mm256_loadu_si256((__m256i*)(haystack + pos));
        __m256i cmp = _mm256_cmpeq_epi8(data, first_vec);
        uint32_t mask = _mm256_movemask_epi8(cmp);
        
        // Check each potential match
        while (mask) {
            int bit_pos = __builtin_ctz(mask);
            size_t candidate_pos = pos + bit_pos - first_offset;
            
            if (candidate_pos + needle->count <= haystack_len && 
                pattern_match_at_position(haystack + candidate_pos, needle)) {
                
                if (match_count >= match_capacity) {
                    match_capacity *= 2;
                    size_t *new_matches = (size_t*)bh_realloc(matches, sizeof(size_t) * match_capacity);
                    if (!new_matches) break;
                    matches = new_matches;
                }
                matches[match_count++] = candidate_pos;
            }
            
            mask &= mask - 1; // Clear lowest set bit
        }
    }
    
    // Handle remaining bytes with scalar search
    for (size_t pos = (haystack_len / 32) * 32; pos <= haystack_len - needle->count; pos++) {
        if (haystack[pos + first_offset] == first_byte && 
            pattern_match_at_position(haystack + pos, needle)) {
            
            if (match_count >= match_capacity) {
                match_capacity *= 2;
                size_t *new_matches = (size_t*)bh_realloc(matches, sizeof(size_t) * match_capacity);
                if (!new_matches) break;
                matches = new_matches;
            }
            matches[match_count++] = pos;
        }
    }
    
    *offsets = matches;
    return match_count;
}
#else
// Fallback scalar implementation
size_t pattern_search_simd(const uint8_t *haystack, size_t haystack_len,
                          const signature_t *needle, size_t **offsets) {
    if (!haystack || !needle || !offsets || needle->count == 0) return 0;
    
    *offsets = NULL;
    size_t *matches = (size_t*)bh_malloc(sizeof(size_t) * 1024);
    if (!matches) return 0;
    
    size_t match_count = 0;
    size_t match_capacity = 1024;
    
    for (size_t pos = 0; pos <= haystack_len - needle->count; pos++) {
        if (pattern_match_at_position(haystack + pos, needle)) {
            if (match_count >= match_capacity) {
                match_capacity *= 2;
                size_t *new_matches = (size_t*)bh_realloc(matches, sizeof(size_t) * match_capacity);
                if (!new_matches) break;
                matches = new_matches;
            }
            matches[match_count++] = pos;
        }
    }
    
    *offsets = matches;
    return match_count;
}
#endif

// Parse various signature string formats
bool pattern_parse_string(const char *input, signature_t **sig) {
    if (!input || !sig) return false;
    
    *sig = sig_create(0);
    if (!*sig) return false;
    
    // Detect and parse different formats
    if (parse_ida_format(input, *sig) ||
        parse_x64dbg_format(input, *sig) ||
        parse_c_array_format(input, *sig) ||
        parse_hex_bytes_format(input, *sig)) {
        return true;
    }
    
    sig_destroy(*sig);
    *sig = NULL;
    return false;
}
