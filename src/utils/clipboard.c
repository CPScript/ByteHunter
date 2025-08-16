#include "../../include/bytehunter.h"
#include <string.h>

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

#elif defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>

bool set_clipboard_text(const char *text) {
    if (!text) return false;
    
    PasteboardRef clipboard;
    if (PasteboardCreate(kPasteboardClipboard, &clipboard) != noErr) {
        return false;
    }
    
    PasteboardClear(clipboard);
    
    CFStringRef cf_text = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
    if (!cf_text) {
        CFRelease(clipboard);
        return false;
    }
    
    OSStatus result = PasteboardPutItemFlavor(clipboard, (PasteboardItemID)1,
                                             CFSTR("public.utf8-plain-text"),
                                             CFStringCreateExternalRepresentation(NULL, cf_text, kCFStringEncodingUTF8, 0),
                                             0);
    
    CFRelease(cf_text);
    CFRelease(clipboard);
    return (result == noErr);
}

#elif defined(__linux__)
#include <unistd.h>
#include <sys/wait.h>

bool set_clipboard_text(const char *text) {
    if (!text) return false;
    
    // Try xclip first
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        int pipefd[2];
        if (pipe(pipefd) == -1) {
            _exit(1);
        }
        
        pid_t xclip_pid = fork();
        if (xclip_pid == 0) {
            // Grandchild process - run xclip
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
            execlp("xclip", "xclip", "-selection", "clipboard", NULL);
            _exit(1);
        } else if (xclip_pid > 0) {
            // Child process - write text to pipe
            close(pipefd[0]);
            write(pipefd[1], text, strlen(text));
            close(pipefd[1]);
            waitpid(xclip_pid, NULL, 0);
            _exit(0);
        } else {
            _exit(1);
        }
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    
    return false;
}

#else
// Generic fallback - no clipboard support
bool set_clipboard_text(const char *text) {
    // Print to console as fallback
    if (text) {
        msg("ByteHunter: Clipboard not supported, result: %s\n", text);
    }
    return false;
}
#endif
