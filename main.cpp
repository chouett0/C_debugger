#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>

using namespace std;

struct Debugger {

	// 変数初期化
	HANDLE h_process_ = 0;
	int pid_ = NULL;
	BOOL debugger_active = FALSE;
	HANDLE h_thread_ = NULL;
	CONTEXT context_;
	PVOID exception_address = NULL;
	map<PVOID, PVOID>software_breakpoint;
	BOOL first_breakpoint = TRUE;
	map<PVOID, PVOID>hardware_breakpoint;

	Debugger() {
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

	}

	void load(LPSTR path) {
		// プロセスの生成方法
		int create_flags = CREATE_NEW_CONSOLE;

		// 構造体のインスタンス化
		STARTUPINFO startupinfo = { 0 };
		PROCESS_INFORMATION processinformation = { 0 };

		// デバッグ対象を別ウィンドウで表示させるためのオプション
		startupinfo.dwFlags = 0x1;
		startupinfo.wShowWindow = 0x0;

		// STARTUPINFO構造体のサイズを初期化
		startupinfo.cb = sizeof(startupinfo);

		BOOL success_create = CreateProcessA(NULL, path, NULL, NULL, NULL, create_flags, NULL, NULL, (LPSTARTUPINFOA)&startupinfo, &processinformation);
		if (success_create == TRUE) {
			printf("[*] We have successfully lanched the process,\n");
			printf("[*] PID: %d\n", processinformation.dwProcessId);

			pid_ = processinformation.dwProcessId;
			h_process_ = open_process(pid_);
			debugger_active = TRUE;


		}
		else {
			printf("[!] Error: 0x%08x\n", GetLastError);

		}
	}

	void Attach(int pid) {
		h_process_ = open_process(pid);

		// プロセスへのアタッチ処理
		if (DebugActiveProcess(pid)) {
			debugger_active = TRUE;
			pid_ = pid;
			cout << "Attach Successfully." << endl;

		}
		else {
			printf("[!] Unable to attach to the process...\n");

		}

	}

	HANDLE open_process(int pid) {
		HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		return h_process;

	}

	HANDLE open_thread(DWORD thread_id) {
		HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, NULL, thread_id);

		if (h_thread != NULL) {
			return h_thread;

		}
		else {
			printf("[!] Could not obtain a valid thrad handle...\n ");
			return FALSE;

		}
	}

	void run() {
		while (debugger_active == TRUE) {
			get_debug_event();

		}
	}

	void get_debug_event() {
		DEBUG_EVENT debug_event;
		DWORD continue_status = DBG_CONTINUE;

		if (WaitForDebugEvent(&debug_event, INFINITE)) {
			h_thread_ = open_thread(debug_event.dwThreadId);
			context_ = get_thread_context(NULL, h_thread_);
			printf("Event Code: %d Thread ID: %d\n", debug_event.dwDebugEventCode, debug_event.dwThreadId);

			if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
				DWORD exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
				exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

				if (exception == EXCEPTION_ACCESS_VIOLATION) {
					printf("Access Violation Detected.\n");

				}
				else if (exception == EXCEPTION_BREAKPOINT) {
					continue_status = exception_handler_breakpoint();

				}
				else if (exception == EXCEPTION_GUARD_PAGE) {
					printf("Guard Page Access Detected.\n");

				}
				else if (exception == EXCEPTION_SINGLE_STEP) {
					printf("Single Steppting.\n");

				}

			}

			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);

		}
		else {
			printf("[!] Can't Wait Debug Event...\n");
			debugger_active = FALSE;

		}
	}

	int exception_handler_breakpoint() {
		printf("[*] Inside the breakpoint handler.\n");
		printf("Exception Address: 0x%08x\n", exception_address);
		return DBG_CONTINUE;

	}

	int detach() {
		if (DebugActiveProcessStop(pid_)) {
			printf("[*] Finished debugging. Exiting...\n");
			return TRUE;

		}
		else {
			printf("[!] There was an error.\n");
			return FALSE;

		}
	}

	vector<DWORD> enumerate_threads() {
		THREADENTRY32 thread_entry;
		vector<DWORD> thread_list;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid_);

		if (snapshot != NULL) {
			thread_entry.dwSize = sizeof(thread_entry);
			BOOL success = Thread32First(snapshot, &thread_entry);

			while (success) {
				if (thread_entry.th32OwnerProcessID == pid_) {
					thread_list.push_back(thread_entry.th32ThreadID);

				}

				success = Thread32Next(snapshot, &thread_entry);

			}

			CloseHandle(snapshot);
			return thread_list;

		}
		else {
			vector<DWORD> emp;
			return emp;

		}
	}

	CONTEXT get_thread_context(DWORD thread_id = NULL, HANDLE h_thread = NULL) {
		CONTEXT context;
		context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

		if (h_thread == NULL) {
			h_thread = open_thread(thread_id);

		}

		if (GetThreadContext(h_thread, &context)) {
			CloseHandle(h_thread);
			return context;

		}
		else {
			printf("[!] Can not Get ThreadContext...\n");

		}

	}

	PVOID read_process_memory(PVOID address, int length) {
		//		PLPVOID data = "";
		char read_buf[1];
		DWORD count = 0;

		if (!ReadProcessMemory(h_process_, address, read_buf, length, &count)) {
			return FALSE;
		}
		else {
			//			data += read_buf;
			return read_buf;

		}

	}

	BOOL write_process_memomry(PVOID address, LPVOID data) {
		DWORD count = 0;
		int length = sizeof(data);

		if (!WriteProcessMemory(h_process_, address, data, length, &count)) {
			return FALSE;

		}
		else {
			return TRUE;

		}

	}

	BOOL bp_set_sw(PVOID address) {
		printf("[*] Setting breakpoint at: 0x%08x\n", address);

		try {
			PVOID original_byte = read_process_memory(address, 1);
			if (original_byte == FALSE) {
				printf("Can not read process memory...\n");

			}

			if (!write_process_memomry(address, "\xCC")) {
				printf("Can not write process memory...\n");

			}


			software_breakpoint[address] = original_byte;

		}
		catch (exception e) {
			cout << &e << endl;
			return FALSE;

		}

		return TRUE;

	}

	BOOL bp_set_hw(PVOID address, int length, int condition) {
		if (!(length == 1 || length == 2 || length == 4)) {
			return FALSE;

		}
		else {
			length -= 1;

		}

		if (!(condition == 0x03 || condition == 0x00 || condition == 0x01)) {
			return FALSE;

		}
	}

	PVOID func_resolve(LPSTR dll, LPSTR function) {
		HMODULE handle = GetModuleHandleA(dll);
		PVOID address = GetProcAddress(handle, function);
		CloseHandle(handle);

		return address;

	}

};

int main(int argc, char *argv) {
	Debugger debugger;

	cout << "PATH:0 PID:1" << endl;
	int select = 2;
	cin >> select;

	if (select == 0) {
		debugger.load("UsaTest2Win.exe");
		debugger.Attach(debugger.pid_);

	}
	else if (select == 1) {
		int pid;
		cin >> pid;
		debugger.Attach(pid);

	}
	else {
		cout << "PATH:0 PID:1" << endl;
		return 1;

	}

//	debugger.run();
/*
	vector<DWORD> list = debugger.enumerate_threads();
	for (DWORD thread: list) {
		CONTEXT thread_context = debugger.get_thread_context(thread);

		printf("[*] Dumping registers for thread Id: 0x%08x\n", thread);
		printf("[**] EIP: 0x%08x\n", thread_context.Eip);
		printf("[**] ESP: 0x%08x\n", thread_context.Esp);
		printf("[**] EBP: 0x%08x\n", thread_context.Ebp);
		printf("[**] EAX: 0x%08x\n", thread_context.Eax);
		printf("[**] EBX: 0x%08x\n", thread_context.Ebx);
		printf("[**] ECX: 0x%08x\n", thread_context.Ecx);
		printf("[**] EDX: 0x%08x\n", thread_context.Edx);
		printf("[*] END DUMP\n");
	
	}
*/

	PVOID printf_address = debugger.func_resolve("user32.dll", "MessageBox");
	printf("[*] Address of printf: 0x%08x\n", printf_address);
	debugger.bp_set_sw(printf_address);

	debugger.run();

	debugger.detach();

	getchar();
	getchar();

	return 0;

}
