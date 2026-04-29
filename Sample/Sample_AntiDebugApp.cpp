#include <Windows.h>
#include <cstdio>

int main() {
	int pid;
	pid = GetCurrentProcessId();
	BOOL remote = FALSE;
	printf("[Sample] PID = %d\n", pid);
	while (TRUE) {
		BOOL flag = IsDebuggerPresent();
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
		printf("[Sample] CheckRemoteDebuggerPresent = %d\n", remote);
		printf("[Sample] IsdebuggerPresent = %d\n", flag);
		Sleep(1000);
	}
	return 0;
}

