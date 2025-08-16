#ifdef _WIN32
#include <windows.h>

bool set_clipboard_text(const char *text) {
    if (!text) return false;
    
    size_t len = strlen(text);
    if (len == 0) return false;
    
    if (!OpenClipboard(NULL) || !EmptyClipboard()) return false;
    
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, len + 1);
    if (!hMem) {
        CloseClipboard();
        return false;
    }
    
    char *pMem = (char*)GlobalLock(hMem);
    if (pMem) {
        memcpy(pMem, text, len);
        GlobalUnlock(hMem);
        SetClipboardData(CF_TEXT, hMem);
    }
    
    CloseClipboard();
    return (pMem != NULL);
}

#else
// Linux/macOS clipboard implementation would go here
bool set_clipboard_text(const char *text) {
    // Placeholder for cross-platform clipboard support
    return false;
}
#endif
