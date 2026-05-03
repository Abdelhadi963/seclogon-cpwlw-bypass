#pragma once
#include <windows.h>
#include <stdio.h>

#ifndef DEBUG_BUILD
#define DEBUG_BUILD 0
#endif

#if DEBUG_BUILD

static void _dbg_print(const char *level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("%s ", level);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

static void _dbg_hexdump(const char *label, const BYTE *data, DWORD len) {
    printf("\n[~] HEXDUMP : %s : %lu bytes\n", label, len);
    printf("  --------------------------------------------\n");
    for (DWORD i = 0; i < len && i < 256; i += 16) {
        char hex[52] = {0}, asc[20] = {0};
        char *hp = hex, *ap = asc;
        for (DWORD j = 0; j < 16 && (i+j) < len; j++) {
            BYTE b = data[i+j];
            wsprintfA(hp, "%02X ", b); hp += 3;
            *ap++ = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
        }
        *ap = 0;
        printf("  %04lX  %-48s %s\n", i, hex, asc);
    }
    printf("  --------------------------------------------\n");
}

#define DBG_INFO(fmt, ...)          _dbg_print("[*]", fmt, ##__VA_ARGS__)
#define DBG_OK(fmt, ...)            _dbg_print("[+]", fmt, ##__VA_ARGS__)
#define DBG_WARN(fmt, ...)          _dbg_print("[!]", fmt, ##__VA_ARGS__)
#define DBG_ERR(fmt, ...)           _dbg_print("[-]", fmt, ##__VA_ARGS__)
#define DBG_TRACE(fmt, ...)         _dbg_print("[~]", fmt, ##__VA_ARGS__)
#define DBG_HEX(label, val)         printf("[*] %s : 0x%llX\n", (label), (unsigned long long)(val))
#define DBG_SEPARATOR()             printf("  --------------------------------------------\n")
#define DBG_HEXDUMP(label, data, len) _dbg_hexdump((label), (const BYTE*)(data), (DWORD)(len))

#else

#define DBG_INFO(fmt, ...)
#define DBG_OK(fmt, ...)
#define DBG_WARN(fmt, ...)
#define DBG_ERR(fmt, ...)
#define DBG_TRACE(fmt, ...)
#define DBG_HEX(label, val)
#define DBG_SEPARATOR()
#define DBG_HEXDUMP(label, data, len)

#endif
