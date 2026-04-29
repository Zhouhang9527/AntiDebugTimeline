#include <Windows.h>
#include <cstdio>

int main() {
	int pid;
	pid = GetCurrentProcessId();
	printf("[Sample] PID = %d\n", pid);
	while (TRUE) {
		BOOL flag = IsDebuggerPresent();
		printf("[Sample] IsdebuggerPresent = %d\n",flag);
		Sleep(1000);
	}
	return 0;
}

