#ifndef BYTEHUNTER_H
#define BYTEHUNTER_H

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <search.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <ua.hpp>

#include "types.h"

// Plugin metadata
#define BH_PLUGIN_NAME    "ByteHunter"
#define BH_PLUGIN_VERSION "2.0.0"
#define BH_PLUGIN_AUTHOR  "Advanced Reverse Engineering Tools"
#define BH_PLUGIN_HOTKEY  "Ctrl-Alt-B"

// Configuration constants
#define BH_DEFAULT_MAX_SIG_LENGTH    1000
#define BH_DEFAULT_MAX_XREF_LENGTH   250
#define BH_DEFAULT_TOP_COUNT         5
#define BH_MIN_SIGNATURE_LENGTH      4
#define BH_BUFFER_CHUNK_SIZE         4096

// Global configuration
extern config_t g_config;
extern arch_type_t g_arch;

// Core plugin functions
bool bytehunter_init(void);
void bytehunter_cleanup(void);
bool bytehunter_run(size_t arg);

#endif
