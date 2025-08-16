#include "../../include/bytehunter.h"

// Main plugin dialog
bool show_main_dialog(void) {
    const char dialog_format[] =
        "STARTITEM 0\n"
        BH_PLUGIN_NAME " v" BH_PLUGIN_VERSION "\n"
        "Signature Generation and Pattern Matching\n\n"
        
        "Action:\n"
        "<#Generate unique signature for current address#Unique signature:R>\n"
        "<#Find shortest XREF signatures#XREF signatures:R>\n"
        "<#Copy selected bytes with formatting#Copy selection:R>\n"
        "<#Search for pattern in binary#Pattern search:R>>\n\n"
        
        "Output Format:\n"
        "<#IDA style: E8 ? ? ? ?#IDA Format:R>\n"
        "<#x64Dbg style: E8 ?? ?? ?? ??#x64Dbg Format:R>\n"
        "<#C array with mask#C Array + Mask:R>\n"
        "<#Hex bytes with bitmask#Hex + Bitmask:R>>\n\n"
        
        "Options:\n"
        "<#Wildcard instruction operands#Wildcard operands:C>\n"
        "<#Continue beyond function boundaries#Continue outside function:C>\n"
        "<#Wildcard optimized instructions#Wildcard optimized:C>>\n"
        
        "<#Configure operand types...#Operand Types:B:0:0:>\n"
        "<#Advanced settings...#Settings:B:1:1:>\n";

    static int action = 0;
    static int format = 0;
    static int options = (1 << 0); // Default: wildcard operands enabled
    
    if (ask_form(dialog_format, &action, &format, &options, 
                 configure_operand_types, configure_settings)) {
        
        // Update global configuration
        g_config.wildcard_operands = (options & (1 << 0)) != 0;
        g_config.continue_outside_func = (options & (1 << 1)) != 0;
        g_config.wildcard_optimized_instr = (options & (1 << 2)) != 0;
        
        return execute_action(action, (signature_format_t)format);
    }
    
    return false;
}

// Configure operand type wildcarding
void configure_operand_types(void) {
    const char format[] =
        "STARTITEM 0\n"
        "Operand Type Configuration\n"
        "Select operand types to wildcard:\n\n"
        
        "<#General registers (eax, ebx, etc.)#General Register:C>\n"
        "<#Memory references [address]#Direct Memory:C>\n"
        "<#Base+Index addressing [reg+reg]#Base+Index:C>\n"
        "<#Base+Index+Displacement [reg+reg+disp]#Base+Index+Disp:C>\n"
        "<#Immediate values#Immediate:C>\n"
        "<#Far addresses (segment:offset)#Far Address:C>\n"
        "<#Near addresses (offset only)#Near Address:C>\n"
        
        // Architecture-specific options
        #ifdef __EA64__
        "<#Extended registers (r8-r15)#Extended Registers:C>\n"
        "<#XMM/YMM/ZMM registers#Vector Registers:C>\n"
        #endif
        
        ">\n";
    
    uint32_t mask = g_config.operand_type_mask >> 1; // Skip o_void
    if (ask_form(format, &mask)) {
        g_config.operand_type_mask = mask << 1;
    }
}

// Configure advanced settings
void configure_settings(void) {
    const char format[] =
        "STARTITEM 0\n"
        "Settings\n\n"
        
        "<#Maximum bytes for single signature#Max signature length:u:4:1000::\n>"
        "<#Maximum bytes for XREF signatures#Max XREF length:u:4:250::\n>"
        "<#Number of top results to show#Show top results:u:1:10::\n>";
    
    size_t max_sig = g_config.max_signature_length;
    size_t max_xref = g_config.max_xref_length;
    size_t top_count = g_config.print_top_count;
    
    if (ask_form(format, &max_sig, &max_xref, &top_count)) {
        g_config.max_signature_length = max_sig;
        g_config.max_xref_length = max_xref;
        g_config.print_top_count = top_count;
    }
}

// Execute selected action
bool execute_action(int action, signature_format_t format) {
    switch (action) {
        case 0: // Unique signature
            return generate_and_display_signature(get_screen_ea(), format);
            
        case 1: // XREF signatures
            return generate_and_display_xref_signatures(get_screen_ea(), format);
            
        case 2: // Copy selection
            return copy_selected_bytes(format);
            
        case 3: // Pattern search
            return show_pattern_search_dialog();
            
        default:
            return false;
    }
}
