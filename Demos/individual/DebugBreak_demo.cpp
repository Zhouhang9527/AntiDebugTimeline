#include <Windows.h>
#include <cstdio>

int main() {
    printf("Checking for debugger using DebugBreak() exception handling...\n");

    __try {
        DebugBreak();
    }
    __except (
        GetExceptionCode() == EXCEPTION_BREAKPOINT
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH
        ) {
        printf("[-] No debugger detected (exception caught by SEH).\n");
        return 0;
    }

    printf("[+] Debugger detected (debugger consumed the breakpoint)!\n");
    return 1;
}
