#include "../../include/bytehunter.h"
#include <stdlib.h>

// Safe memory allocation with error handling
void* bh_malloc(size_t size) {
    if (size == 0) return NULL;
    
    void *ptr = malloc(size);
    if (!ptr) {
        msg("ByteHunter: Memory allocation failed for %zu bytes\n", size);
    }
    return ptr;
}

void* bh_realloc(void *ptr, size_t size) {
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        msg("ByteHunter: Memory reallocation failed for %zu bytes\n", size);
    }
    return new_ptr;
}

void bh_free(void *ptr) {
    free(ptr);
}

// Read segments into buffer for high-performance searching
uint8_t* read_segments_to_buffer(size_t *total_size) {
    if (!total_size) return NULL;
    
    *total_size = 0;
    size_t buffer_capacity = BH_BUFFER_CHUNK_SIZE;
    uint8_t *buffer = (uint8_t*)bh_malloc(buffer_capacity);
    if (!buffer) return NULL;
    
    int seg_count = get_segm_qty();
    for (int i = 0; i < seg_count; i++) {
        segment_t *seg = getnseg(i);
        if (!seg) continue;
        
        size_t seg_size = seg->end_ea - seg->start_ea;
        
        // Resize buffer if needed
        while (*total_size + seg_size > buffer_capacity) {
            buffer_capacity *= 2;
            uint8_t *new_buffer = (uint8_t*)bh_realloc(buffer, buffer_capacity);
            if (!new_buffer) {
                bh_free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
        
        // Read segment data
        if (get_bytes(buffer + *total_size, seg_size, seg->start_ea) != seg_size) {
            bh_free(buffer);
            return NULL;
        }
        
        *total_size += seg_size;
    }
    
    return buffer;
}
