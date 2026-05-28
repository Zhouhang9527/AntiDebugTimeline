#include <Windows.h>
#include <cstdio>
#include <intrin.h>

int main() {
    printf("=== Timing Anti-Debug Demo ===\n\n");

    printf("[1] RDTSC check:\n");
    unsigned __int64 t1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    unsigned __int64 t2 = __rdtsc();
    unsigned __int64 delta_rdtsc = t2 - t1;
    printf("    Cycles: %llu\n", delta_rdtsc);
    if (delta_rdtsc > 10000000) {
        printf("    [+] RDTSC: Debugger detected (delta too large)!\n");
    } else {
        printf("    [-] RDTSC: Normal execution speed.\n");
    }

    printf("\n[2] QueryPerformanceCounter check:\n");
    LARGE_INTEGER freq, qpc1, qpc2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&qpc1);
    dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    QueryPerformanceCounter(&qpc2);
    double elapsed_us = (double)(qpc2.QuadPart - qpc1.QuadPart) / freq.QuadPart * 1000000.0;
    printf("    Elapsed: %.2f us\n", elapsed_us);
    if (elapsed_us > 10000.0) {
        printf("    [+] QPC: Debugger detected (elapsed too large)!\n");
    } else {
        printf("    [-] QPC: Normal execution speed.\n");
    }

    printf("\n[3] GetTickCount check:\n");
    DWORD tick1 = GetTickCount();
    dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    DWORD tick2 = GetTickCount();
    DWORD delta_tick = tick2 - tick1;
    printf("    Delta: %u ms\n", delta_tick);
    if (delta_tick > 100) {
        printf("    [+] GetTickCount: Debugger detected!\n");
    } else {
        printf("    [-] GetTickCount: Normal execution speed.\n");
    }

    return 0;
}
