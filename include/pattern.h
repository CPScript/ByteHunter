#ifndef BYTEHUNTER_PATTERN_H
#define BYTEHUNTER_PATTERN_H

#include "types.h"

// Pattern compilation and search
typedef struct pattern_ctx pattern_ctx_t;

pattern_ctx_t* pattern_compile(const char *pattern_string);
void pattern_destroy(pattern_ctx_t *ctx);
size_t pattern_search(pattern_ctx_t *ctx, ea_t start, ea_t end, ea_t **results);
bool pattern_parse_string(const char *input, signature_t **sig);

// High-performance search using SIMD when available
bool pattern_has_simd_support(void);
size_t pattern_search_simd(const uint8_t *haystack, size_t haystack_len,
                          const signature_t *needle, size_t **offsets);

#endif
