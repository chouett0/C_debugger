#include <windows.h>
#include <stdio.h>
#include <iostream>

using namespace std;

struct Debugger {

	// 変数初期化
	HANDLE h_process_ = 0;
	int pid_ = NULL;
	BOOL debugger_active = FALSE;

	Debugger() { /* デストラクター */ }

	void Load(char *path) {
		// プロセスの生成方法
		int creation_flags = CREATE_NEW_CONSOLE;

		// 構造体をインスタンス化
		PROCESS_INFORMATION process_information = { 0 };
		STARTUPINFO startupinfo = { 0 };

		// 起動されたプロセスを別ウィンドウとして表示させるためのオプション
		startupinfo.dwFlags = 0x1;
		startupinfo.wShowWindow = 0x0;

		startupinfo.cb = sizeof(startupinfo);

		if (CreateProcess(path, NULL, NULL, NULL, NULL, creation_flags, NULL, NULL, &startupinfo, &process_information)) {
			printf("[*] We have successfully lanched the process!\n");
			printf("PID: %d\n", process_information.dwProcessId);

			pid_ = process_information.dwProcessId;
			h_process_ = OpenProcesses(process_information.dwProcessId);
			debugger_active = TRUE;

		} else {
			printf("[!] Error: 0x%08x\n", GetLastError);
		
		}
	}

	void Attach(int pid) {
		h_process_ = OpenProcesses(pid);

		// プロセスへのアタッチ処理
		if (DebugActiveProcess(pid)) {
			debugger_active = TRUE;
			pid_ = pid;

		} else {
			printf("[!] Unable to attach to the process...\n");
		
		}

	}

	HANDLE OpenProcesses(int pid) {
		HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		return h_process;
	
	}

	void Run() {
		while (debugger_active == TRUE) {
			GetDebugEvent();

		}
	}

	void GetDebugEvent() {
		DEBUG_EVENT debug_event;
		DWORD continue_status = DBG_CONTINUE;

		if (WaitForDebugEvent(&debug_event, INFINITE)) {
			getchar();
			getchar();
			debugger_active = FALSE;
			ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);

		} else {
			printf("[!] Can't Wait Debug Event...\n");
			debugger_active = FALSE;

		}
	}

	int detach() {
		if (DebugActiveProcessStop(pid_)) {
			printf("[*] Finished debugging. Exiting...\n");
			return TRUE;

		} else {
			printf("[!] There was an error.\n");
			return FALSE;
		
		}
	}

};

int main(int argc, char *argv) {
	Debugger debugger;

	cout << "PATH:0 PID:1" << endl;
	int select = 2;
	cin >> select;

	if (select == 0) {
		debugger.Load("UsaTest2Win.exe");

	} else if (select == 1) {
		int pid;
		cin >> pid;
		debugger.Attach(pid);
	
	} else {
		cout << "PATH:0 PID:1" << endl;
	
	}

//	debugger.Run();
	debugger.detach();

	return 0;

}
