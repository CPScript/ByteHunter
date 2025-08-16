#include "../include/pattern.h"
#include "../include/bytehunter.h"
#include <immintrin.h>  // For SIMD support

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
            free(ida_pattern_str);
        }
    }
    
    return ctx;
}

void pattern_destroy(pattern_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->signature) sig_destroy(ctx->signature);
    free(ctx);
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

// SIMD-optimized pattern search
size_t pattern_search_simd(const uint8_t *haystack, size_t haystack_len,
                          const signature_t *needle, size_t **offsets) {
    #ifdef __AVX2__
    if (!haystack || !needle || !offsets || needle->count == 0) return 0;
    
    *offsets = NULL;
    size_t *matches = (size_t*)malloc(sizeof(size_t) * 1024); // Initial capacity
    if (!matches) return 0;
    
    size_t match_count = 0;
    size_t match_capacity = 1024;
    
    // Get first non-wildcard byte for quick scanning
    uint8_t first_byte = 0;
    size_t first_offset = 0;
    for (size_t i = 0; i < needle->count; i++) {
        if (!needle->bytes[i].is_wildcard) {
            first_byte = needle->bytes[i].value;
            first_offset = i;
            break;
        }
    }
    
    __m256i first_vec = _mm256_set1_epi8(first_byte);
    
    for (size_t pos = first_offset; pos <= haystack_len - needle->count; pos += 32) {
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
                    size_t *new_matches = (size_t*)realloc(matches, sizeof(size_t) * match_capacity);
                    if (!new_matches) break;
                    matches = new_matches;
                }
                matches[match_count++] = candidate_pos;
            }
            
            mask &= mask - 1; // Clear lowest set bit
        }
    }
    
    *offsets = matches;
    return match_count;
    #else
    return 0; // Fallback to non-SIMD version
    #endif
}

// Check if pattern matches at specific position
static bool pattern_match_at_position(const uint8_t *data, const signature_t *pattern) {
    for (size_t i = 0; i < pattern->count; i++) {
        if (!pattern->bytes[i].is_wildcard && data[i] != pattern->bytes[i].value) {
            return false;
        }
    }
    return true;
}

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
