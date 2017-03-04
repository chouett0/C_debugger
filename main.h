#include <stdio.h>
#include <iostream>
#include <tlhelp32.h>
#include "debugger.h"

int main(int argc, char *argv) {
	printf("[*]  Select 0:PATH or 1:Input\n");
	int Select;
	std::cin >> Select;
	
	if (Select == 0) {
	load("UsaTest2Win.exe");

	} else if (Select == 1){
		printf("PID: ");
		std::cin >> ProcessId;

	}
	else {
		printf("[!] Select 0:PATH or 1:Input\n");
		return 0;

	}

	attach(ProcessId);
	run();

	if (ProcessId >= 0) {
		detach(ProcessId);

	}

	getchar();

	return 0;

}
