#ifndef HOOK_H
#define HOOK_H

#include <windows.h>
#include "debug.h"

// -----------------------------------------------------------------------------
// SECL_REQUEST.dwProcessId inline hook
//
// Root cause:
//   CreateProcessWithLogonCommonW calls GetCurrentProcessId() to populate
//   SECL_REQUEST.dwProcessId at offset +0xD8 before sending to seclogon.
//   seclogon then calls OpenProcess(0x4C0, FALSE, dwProcessId) while
//   impersonating the RPC caller. If the calling process is SYSTEM-owned,
//   a medium-integrity impersonation token cannot open it -> ERROR_ACCESS_DENIED.
//
// Fix:
//   Hook the call site of c_SeclCreateProcessWithLogonW inside
//   CreateProcessWithLogonCommonW. The stub patches [rcx+0xD8] to a
//   user-owned PID before the RPC call fires.
//
// Call site pattern (verified Win11 26200, stable since Vista):
//   48 8D 94 24 40 02 00 00   LEA RDX,[RSP+240h]  <- SECL_RESPONSE ptr
//   48 8D 8C 24 30 01 00 00   LEA RCX,[RSP+130h]  <- SECL_REQUEST ptr
//   E8 xx xx xx xx            call c_SeclCreateProcessWithLogonW
//
// Stub (27 bytes, allocated near advapi32 for E9 rel32 reach):
//   B8 xx xx xx xx       MOV EAX, spoofPid         <- patched at install
//   89 81 D8 00 00 00    MOV [RCX+0D8h], EAX       <- patch dwProcessId
//   FF 15 02 00 00 00    CALL [RIP+2]               <- preserves stack balance
//   EB 08                JMP over addr qword
//   xx xx xx xx xx xx xx xx  real c_Secl addr
// -----------------------------------------------------------------------------

#define CALLSITE_OFFSET  0x768
#define SECL_PID_OFFSET  0xD8
#define PATCH_SIZE       5
#define STUB_SIZE        39
#define STUB_PID_OFF     0x01   // spoofPid DWORD
#define STUB_RET_OFF     0x17   // CommonW+769 retaddr qword
#define STUB_ADDR_OFF    0x1F   // c_Secl addr qword

typedef struct {
    BYTE   *pCallSite;
    BYTE    origBytes[PATCH_SIZE];
    LPVOID  pRealFunc;
    BOOL    installed;
    DWORD   spoofPid;
} HookCtx;

static HookCtx g_hook = {0};
static BYTE   *g_stub  = NULL;

// stub layout (39 bytes) - verified working in WinDbg:
//
//   [00] B8 xx xx xx xx        MOV EAX, spoofPid        (5)
//   [05] 89 81 D8 00 00 00     MOV [RCX+D8h], EAX       (6)  patch SECL_REQUEST.dwProcessId
//   [0B] FF 35 06 00 00 00     PUSH [RIP+6]              (6)  RIP=0x11 -> pushes [0x17] = CommonW+769
//   [11] FF 25 08 00 00 00     JMP  [RIP+8]              (6)  RIP=0x17 -> jumps to  [0x1F] = c_Secl
//   [17] retaddr qword         CommonW+769 = pCallSite+5 (8)  patched at install
//   [1F] c_Secl  qword         c_SeclCreateProcess...    (8)  patched at install
//
// why PUSH then JMP instead of CALL:
//   our E9 JMP to the stub does NOT push a return address (unlike the original E8).
//   so CommonW+769 is never on the stack. we manually PUSH it before jumping to
//   c_Secl so its RET pops CommonW+769 and returns there cleanly.
static const BYTE g_stubTemplate[STUB_SIZE] = {
    0xB8, 0x00, 0x00, 0x00, 0x00,                          // [00] MOV EAX, spoofPid
    0x89, 0x81, 0xD8, 0x00, 0x00, 0x00,                    // [05] MOV [RCX+D8h], EAX
    0xFF, 0x35, 0x06, 0x00, 0x00, 0x00,                    // [0B] PUSH [RIP+6] -> retaddr
    0xFF, 0x25, 0x08, 0x00, 0x00, 0x00,                    // [11] JMP  [RIP+8] -> c_Secl
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        // [17] retaddr qword (CommonW+769)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00         // [1F] c_Secl  qword
};

// allocate executable memory within +-2GB of pNear for E9 rel32 reach
static LPVOID _AllocNear(LPVOID pNear, SIZE_T size) {
    SYSTEM_INFO si = {0};
    GetSystemInfo(&si);
    BYTE *base = (BYTE*)pNear;
    BYTE *lo = (base - 0x70000000 > (BYTE*)si.lpMinimumApplicationAddress)
               ? base - 0x70000000 : (BYTE*)si.lpMinimumApplicationAddress;
    BYTE *hi = (base + 0x70000000 < (BYTE*)si.lpMaximumApplicationAddress)
               ? base + 0x70000000 : (BYTE*)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi = {0};
    for (BYTE *addr = lo; addr < hi; ) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
            LPVOID p = VirtualAlloc(addr, size, MEM_COMMIT|MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            if (p) return p;
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    return VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}

// resolve CreateProcessWithLogonCommonW
// CreateProcessWithLogonW is a tiny wrapper that ends with:
//   xor ecx, ecx   (33 C9)
//   call CommonW   (E8 xx xx xx xx)
// scan for the 33 C9 E8 sequence to find CommonW reliably
static BYTE *_FindCommonW(HMODULE hAdv) {
    BYTE *pLogonW = (BYTE*)GetProcAddress(hAdv, "CreateProcessWithLogonW");
    if (!pLogonW) return NULL;

    for (int i = 0; i < 0x100; i++) {
        if (pLogonW[i]==0x33 && pLogonW[i+1]==0xC9 && pLogonW[i+2]==0xE8) {
            INT32  rel  = *(INT32*)(pLogonW + i + 3);
            BYTE  *dest = pLogonW + i + 7 + rel;
            DBG_INFO("CreateProcessWithLogonW @ %p", pLogonW);
            DBG_OK("pattern [33 C9 E8] at +0x%X -> CommonW @ %p", i, dest);
            return dest;
        }
    }
    return NULL;
}

// scan CommonW for the LEA RDX/RCX pattern preceding the c_Secl call
static const BYTE g_callSitePattern[] = {
    0x48, 0x8D, 0x94, 0x24, 0x40, 0x02, 0x00, 0x00,  // LEA RDX,[RSP+240h]
    0x48, 0x8D, 0x8C, 0x24, 0x30, 0x01, 0x00, 0x00   // LEA RCX,[RSP+130h]
};

static DWORD _ScanCallSite(BYTE *pBase) {
    for (DWORD i = 0; i < 0x2000 - 21; i++) {
        if (memcmp(pBase + i, g_callSitePattern, 16) != 0) continue;
        DWORD callOff = i + 16;
        if (pBase[callOff] == 0xE8) {
            DBG_OK("call site pattern matched at +0x%lX -> E8 at +0x%lX", i, callOff);
            return callOff;
        }
    }
    DBG_WARN("pattern scan failed, using hardcoded +0x%X", CALLSITE_OFFSET);
    return CALLSITE_OFFSET;
}

static BOOL HookInstall(DWORD spoofPid) {
    if (g_hook.installed) return TRUE;

    HMODULE hAdv = GetModuleHandleA("advapi32.dll");
    if (!hAdv) { DBG_ERR("advapi32 not loaded"); return FALSE; }

    BYTE *pCommonW = _FindCommonW(hAdv);
    if (!pCommonW) { DBG_ERR("CommonW not found"); return FALSE; }

    DWORD  csOff    = _ScanCallSite(pCommonW);
    BYTE  *pCallSite = pCommonW + csOff;

    if (pCallSite[0] != 0xE8) {
        DBG_ERR("E8 not at +0x%lX (got 0x%02X)", csOff, pCallSite[0]);
        return FALSE;
    }

    // resolve real c_SeclCreateProcessWithLogonW
    INT32  rel32   = *(INT32*)(pCallSite + 1);
    LPVOID pRealFn = (LPVOID)(pCallSite + 5 + rel32);

    // verify it's inside advapi32
    HMODULE hCheck = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCSTR)pRealFn, &hCheck);
    if (hCheck != hAdv) {
        DBG_ERR("c_Secl @ %p not inside advapi32", pRealFn);
        return FALSE;
    }

    DBG_INFO("c_Secl @ %p  callsite @ %p  offset +0x%lX", pRealFn, pCallSite, csOff);

    // alloc stub near call site
    g_stub = (BYTE*)_AllocNear(pCallSite, STUB_SIZE + 16);
    if (!g_stub) { DBG_ERR("stub alloc failed"); return FALSE; }

    // build stub
    memcpy(g_stub, g_stubTemplate, STUB_SIZE);
    *(DWORD  *)(g_stub + STUB_PID_OFF)  = spoofPid;
    *(UINT64 *)(g_stub + STUB_RET_OFF)  = (UINT64)(pCallSite + 5); // CommonW+769
    *(UINT64 *)(g_stub + STUB_ADDR_OFF) = (UINT64)pRealFn;
    FlushInstructionCache(GetCurrentProcess(), g_stub, STUB_SIZE);

    DBG_INFO("stub @ %p  spoofPid=0x%lX -> real=%p", g_stub, spoofPid, pRealFn);

    // check E9 rel32 reach
    INT64 delta = (INT64)g_stub - (INT64)(pCallSite + 5);
    if (delta < -0x7FFFFFFF || delta > 0x7FFFFFFF) {
        DBG_ERR("stub out of E9 range");
        VirtualFree(g_stub, 0, MEM_RELEASE); g_stub = NULL;
        return FALSE;
    }

    // save + patch
    memcpy(g_hook.origBytes, pCallSite, PATCH_SIZE);
    DWORD oldProt = 0;
    VirtualProtect(pCallSite, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProt);
    pCallSite[0] = 0xE9;
    *(INT32*)(pCallSite + 1) = (INT32)delta;
    VirtualProtect(pCallSite, PATCH_SIZE, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), pCallSite, PATCH_SIZE);

    g_hook.pCallSite = pCallSite;
    g_hook.pRealFunc = pRealFn;
    g_hook.spoofPid  = spoofPid;
    g_hook.installed = TRUE;
    DBG_OK("hook installed  spoofPid=%lu (0x%lX)", spoofPid, spoofPid);
    return TRUE;
}

static void HookRemove(void) {
    if (!g_hook.installed) return;

    // restore original E8 bytes at call site
    DWORD oldProt = 0;
    VirtualProtect(g_hook.pCallSite, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(g_hook.pCallSite, g_hook.origBytes, PATCH_SIZE);
    VirtualProtect(g_hook.pCallSite, PATCH_SIZE, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), g_hook.pCallSite, PATCH_SIZE);

    // stub page intentionally NOT freed here.
    // CALL [RIP+2] inside the stub pushed a return address back into the stub.
    // the call stack is still unwinding through that address when we get here.
    // freeing now causes an access violation. OS reclaims the page on exit.

    g_hook.installed = FALSE;
    DBG_OK("hook removed");
}

#endif // HOOK_H
