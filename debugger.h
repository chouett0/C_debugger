#include <stdio.h>
#include <iostream>
#include <tlhelp32.h>
#include <windows.h>
#include <tchar.h>
#include <wchar.h>

BOOL DebugActive = FALSE;
int ProcessId = 0;
char *ThreadList[];

void get_debug_event();
HANDLE openProcess(DWORD pid);
HANDLE oepn_thread(int ThreadId);

int load(char *path) {

	// デバッグ特権取得開始

	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tp, 0, 0, 0);
	CloseHandle(hToken);

	// デバッグ特権取得処理終了

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	HANDLE h_process = NULL;
	int pid;

	si.dwFlags = 0x1;
	si.wShowWindow = 0x0;
	si.cb = sizeof(si);

	BOOL hCreate = CreateProcess(NULL, "UsaTest2Win.exe", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	if (hCreate == TRUE) {
		printf("[*] we have successfully launched the process\n");
		printf("[*] PID: %d\n", pi.dwProcessId);

		pid = pi.dwProcessId;


	}
	else {
		printf("[!] Cann't open process...\n");
		printf("[!] Error: %d\n", pi.dwProcessId);

		return -1;

	}

	h_process = open_process(pid);
	ProcessId = pid;

	return 0;

}

HANDLE open_process(DWORD pid) {
	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	return h_process;

}

HANDLE open_thread(DWORD ThreadId) {
	HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, NULL, ThreadId);

	if (h_thread != 0) {
		return h_thread;

	} else {
		printf("[!] Could not obtain a vaiid thread handle...\n");
		return FALSE;

	}
}

char enumerate_threads(DWORD TreadId) {
	THREADENTRY32 te = {0};
	int snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessId);

}

void attach(int pid) {
	HANDLE h_process = openProcess(pid);

	if (DebugActiveProcess(pid) == TRUE) {
		DebugActive = TRUE;
		ProcessId = pid;

	}
	else {
		printf("[!] unable to attach the process...\n");

	}

}

void run() {
	while (DebugActive == TRUE) {
		get_debug_event();

	}
}

void get_debug_event() {
	DEBUG_EVENT de;

	if (WaitForDebugEvent(&de, INFINITE) == TRUE) {
		getchar();
		getchar();
		DebugActive = FALSE;
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);

	}
}

BOOL detach(int pid) {
	if (DebugActiveProcessStop(pid)) {
		printf("[*] Finished debugging. Exiting...\n");
		return TRUE;

	}
	else {
		printf("[!] detach Error...\n");
		return FALSE;

	}
}
