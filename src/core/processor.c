#include "../include/bytehunter.h"

// Initialize processor-specific settings
void processor_init(void) {
    g_arch = detect_architecture();
    
    // Set default operand wildcarding based on architecture
    switch (g_arch) {
        case ARCH_X86:
        case ARCH_X64:
            g_config.operand_type_mask = 
                BIT(o_mem) | BIT(o_phrase) | BIT(o_displ) | BIT(o_far) | 
                BIT(o_near) | BIT(o_imm) | BIT(o_trreg) | BIT(o_dbreg) | 
                BIT(o_crreg) | BIT(o_fpreg) | BIT(o_mmxreg) | BIT(o_xmmreg) | 
                BIT(o_ymmreg) | BIT(o_zmmreg) | BIT(o_kreg);
            break;
            
        case ARCH_ARM:
        case ARCH_ARM64:
            g_config.operand_type_mask = 
                BIT(o_mem) | BIT(o_phrase) | BIT(o_displ) | BIT(o_far) | 
                BIT(o_near) | BIT(o_imm);
            break;
            
        default:
            g_config.operand_type_mask = 
                BIT(o_mem) | BIT(o_phrase) | BIT(o_displ) | BIT(o_far) | 
                BIT(o_near) | BIT(o_imm);
            break;
    }
}

// Detect current processor architecture
static arch_type_t detect_architecture(void) {
    switch (get_ph()->id) {
        case PLFM_386:
            return ARCH_X86;
        case PLFM_ARM:
            return ARCH_ARM;
        case PLFM_PPC:
            return ARCH_PPC;
        case PLFM_MIPS:
            return ARCH_MIPS;
        default:
            return ARCH_UNKNOWN;
    }
}

// Get operand information for wildcarding
bool get_operand_info(const insn_t *insn, uint8_t *offset, uint8_t *length) {
    if (!insn || !offset || !length) return false;
    
    for (int i = 0; i < UA_MAXOP; i++) {
        const op_t *op = &insn->ops[i];
        if (op->type == o_void) continue;
        
        if ((BIT(op->type) & g_config.operand_type_mask) == 0) continue;
        
        *offset = op->offb;
        
        // Calculate operand length based on architecture
        switch (g_arch) {
            case ARCH_ARM:
            case ARCH_ARM64:
                *length = (insn->size == 4) ? 3 : 7;
                break;
                
            case ARCH_X86:
            case ARCH_X64:
                if (op->offb == 0 && !g_config.wildcard_optimized_instr) {
                    continue; // Skip optimized instructions
                }
                *length = insn->size - op->offb;
                break;
                
            default:
                *length = insn->size - op->offb;
                break;
        }
        
        return true;
    }
    
    return false;
}
