#ifndef BYTEHUNTER_SIGNATURE_H
#define BYTEHUNTER_SIGNATURE_H

#include "types.h"

// Signature lifecycle management
signature_t* sig_create(size_t initial_capacity);
void sig_destroy(signature_t *sig);
bool sig_reserve(signature_t *sig, size_t capacity);
bool sig_add_byte(signature_t *sig, uint8_t value, bool is_wildcard);
bool sig_add_bytes(signature_t *sig, ea_t address, size_t count, bool wildcards);
void sig_trim_wildcards(signature_t *sig);
signature_t* sig_clone(const signature_t *sig);

// Signature generation
bh_error_t generate_unique_signature(ea_t address, signature_t **result);
bh_error_t generate_range_signature(ea_t start, ea_t end, signature_t **result);
bh_error_t generate_xref_signatures(ea_t address, search_result_t **results, size_t *count);

// Signature formatting and output
char* sig_format(const signature_t *sig, signature_format_t format);
bool sig_is_unique(const signature_t *sig);
size_t sig_find_occurrences(const signature_t *sig, ea_t **addresses);

#endif
