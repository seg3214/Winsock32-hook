/*
 * Copyright (c) 2023-2026 seg3214 (https://github.com)
 * Licensed under the AGPL-3.0 license.
 *
 * DISCLAIMER: This tool is for educational purposes only.
 * The author is not responsible for account bans or system damage.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
//#define DEBUG_PRINT_RING_BUFFER
//#define DEBUG_PRINT_RING_BUFFER2
#define DEBUG_PRINT_RECV_BUFFER
#define DEBUG_PRINT_SEND_BUFFER
#include<Windows.h>
#include<stdint.h>
#include<stdio.h>
#include<winsock2.h>
#include<assert.h>

#include "ring_buffer.h"
#pragma warning(default : 4820)//padding

#define MAX_packet_payload_size 4096


struct stPayload
{
	int32_t size;
	uint8_t message[MAX_packet_payload_size];
};

struct patch_data
{
	uint8_t* target_function;//the absolute address of the function to be patched
	int32_t patch_size;//how many bytes are patched at target function
	uint32_t jump_size;//how many bytes is jump instruction
	uint8_t* cave;//the absolute address of the trampoline and controller code location 
	uint8_t backup[20];//to hold target function bytes MAX size 20 bytes

	uint8_t* callback_function;//the absolute address of callback function
	uint8_t* controller_function;//the absolute address of the controller function to be copied into the cave
	int32_t controller_size;//how many bytes are in the controller function
	uint32_t target_original_return_address;
	uint32_t target_returned_value;
	uint32_t target_stack_pointer;

	
};

//typedef int32_t(WINAPI *thk_recv)(SOCKET s, char *buf, int32_t bufsize, int32_t flags);
//typedef int32_t(WINAPI *thk_send)(SOCKET s, char *buf, int32_t bufsize, int32_t flags);

int console_allocated = 0;
int SHUTTINGDOWN = 0;
uintptr_t write_ptr = 0;
struct stPayload* RecievedData = nullptr;
struct patch_data patch_recv;
struct patch_data patch_send;

static __declspec(naked) void WINAPI controller_recv()
{
	__asm
	{
		mov patch_recv.target_stack_pointer, esp
		mov eax, [esp + 0]
		mov patch_recv.target_original_return_address, eax
		mov eax, label_target_returns
		mov[esp + 0], eax
		jmp[patch_recv.cave]

		label_target_returns :
			mov patch_recv.target_returned_value, eax
			mov esp, patch_recv.target_stack_pointer
			push eax
			pop eax
			xchg eax, [esp]
			push eax
			mov eax, label_callback_f_returns
			mov dword ptr[esp + 0], eax
			jmp[patch_recv.callback_function]

		label_callback_f_returns :
			mov eax, patch_recv.target_returned_value
			jmp patch_recv.target_original_return_address

		label_target_resume :
			nop
			nop
			nop
			nop
	}
}
static __declspec(naked) void WINAPI controller_send()
{

	__asm
	{
		mov eax, [esp + 0]
		mov patch_send.target_original_return_address, eax
		mov eax, label_callback_f_returns
		mov[esp + 0], eax

		mov patch_send.target_stack_pointer, esp
		jmp[patch_send.callback_function]

		label_callback_f_returns :
			mov esp, patch_send.target_stack_pointer
			mov eax, patch_send.target_original_return_address
			mov[esp + 0], eax
			jmp[patch_send.cave]

		label_target_resume :
			nop
			nop
			nop
			nop
	}
}

//result contains return value of the winsock recv function
static void WINAPI callback_recv(int32_t result,SOCKET s, char* buf, int32_t bufsize, int32_t flags)
{
	if (!prologue()) return;
	const int sz = sizeof(struct stPayload);
	if (result > 0)
	{
		struct stPayload* p = (struct stPayload*)write_ptr;
#if defined DEBUG_PRINT_RING_BUFFER
		static int c = 0;
		c++;
		printf("%d.  writing RecievedData=%p len=%zu\n", c, write_ptr, result);
#endif
		p->size = result;
		memcpy(p->message, buf, p->size);
#if defined DEBUG_PRINT_RING_BUFFER2
		printf("RING result=%04zu bufsize=%04zu p->payload=", p->size,bufsize);
		for (int32_t i = 0; i < p->size; i++) {
			printf("%02hhx ", p->message[i]);
		}
		printf("\n");
#endif

		write_ptr += sz;
		if (write_ptr >= (uintptr_t)secondaryView) {
#if defined DEBUG_PRINT_RING_BUFFER
			printf("%d. oopsie  RecievedData=%p ", c, write_ptr);
#endif
			write_ptr = (uintptr_t)RingBuffer_pointer;
#if defined DEBUG_PRINT_RING_BUFFER
			printf(" adjusted=%p\n", write_ptr);
#endif
		}


#if defined DEBUG_PRINT_RECV_BUFFER
		printf("RECV result=%04zu bufsize=%04zu payload=",  result, bufsize);
		for (int32_t i = 0; i < result; i++) {
			printf("%02hhx ", buf[i]);
		}
		printf("\n");
#endif
	}
	else if (result == 0)
		printf("Connection closed\n");
	else
	{
		int r = WSAGetLastError();
		if (r != WSAEWOULDBLOCK) 
		printf("recv failed: %d\n", r);
	}
}
static void WINAPI callback_send(SOCKET s, char* buf, int32_t bufsize, int32_t flags)
{
	if (!prologue()) return;
#if defined DEBUG_PRINT_SEND_BUFFER
	printf("SEND bufsize=%04zu payload=",  bufsize);
	for (int32_t i = 0; i < bufsize; i++) {
		printf("%02hhx ", buf[i]);
	}
	printf("\n");
#endif
}

int prologue()
{
	if (SHUTTINGDOWN)
	{
		return 0;
	}
	return 1;
}
static void hook_function(struct patch_data* pd)
{
	int cavesize = pd->patch_size + pd->jump_size + 50;

	memcpy(&pd->backup, pd->target_function, pd->patch_size);

	pd->cave = VirtualAlloc(0, cavesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("target_function@ 0x%p patch_size=%d\n", pd->target_function, pd->patch_size);
	printf("cave@ 0x%p cavesize=%d\n", pd->cave, cavesize);

	//put stolen bytes
	memcpy(pd->cave, &pd->backup, pd->patch_size);

	uint8_t* jmp_back_at = (uint8_t*)((uint32_t)pd->cave + pd->patch_size);
	jmp_back_at[0] = 0xE9;

	//get the relative address of the target function to continue
	uint32_t continue_target_relative = ((uint32_t)pd->target_function + pd->patch_size) - ((uint32_t)jmp_back_at) - pd->jump_size;
	memcpy(jmp_back_at + 1, &continue_target_relative, 4);
	printf("continue_target_relative 0x%X\n", continue_target_relative);

	// fixing target function prologue
	DWORD oProc;
	VirtualProtect(pd->target_function, pd->patch_size, PAGE_EXECUTE_READWRITE, &oProc);
	memset(pd->target_function, 0x90, pd->patch_size);
	pd->target_function[0] = 0xE9;
	uint32_t controller_function_relative = ((uint32_t)pd->controller_function) - ((uint32_t)pd->target_function) - pd->jump_size;
	memcpy(pd->target_function + 1, &controller_function_relative, 4);

	VirtualProtect(pd->target_function, pd->patch_size, oProc, &oProc);
	//

}

static uint32_t get_controller_size(uint8_t* controller_func)
{
	for (int i = 0; i < 500; i++)
	{
		if (controller_func[i] == 0x90 && controller_func[i + 1] == 0x90 && controller_func[i + 2] == 0x90 && controller_func[i + 3] == 0x90)
		{
			return  i;
		}
	}
	assert(0 && "cant find the end of controller_func");
	return 0;
}

static void patch_back(struct patch_data* pd) {
	DWORD oProc;
	VirtualProtect(pd->target_function, pd->patch_size, PAGE_EXECUTE_READWRITE, &oProc);
	memcpy(pd->target_function, &pd->backup, pd->patch_size);
	VirtualProtect(pd->target_function, pd->patch_size, oProc, &oProc);
}
void shut_down()
{
	patch_back(&patch_recv);
	VirtualFree(patch_recv.cave, 0, MEM_RELEASE);
	patch_back(&patch_send);
	VirtualFree(patch_send.cave, 0, MEM_RELEASE);
}
 static DWORD WINAPI HackThread(HMODULE hModule) 
 {

	 HMODULE hWs3 = GetModuleHandleA("Ws2_32.dll");
	 if (hWs3 != nullptr) {
		 patch_recv.patch_size = 5;
		 patch_recv.jump_size = 5;
		 patch_send = patch_recv;
		 patch_recv.target_function = (uint8_t*)GetProcAddress(hWs3, "recv");
		 patch_recv.callback_function = (uint8_t*)&callback_recv;
		 patch_recv.controller_function=(uint8_t*)&controller_recv;
		 patch_recv.controller_size= get_controller_size(patch_recv.controller_function);
		 hook_function(&patch_recv);

		 patch_send.target_function = (uint8_t*)GetProcAddress(hWs3, "send");
		 patch_send.callback_function = (uint8_t*)&callback_send;
		 patch_send.controller_function = (uint8_t*)&controller_send;
		 patch_send.controller_size = get_controller_size(patch_send.controller_function);
		 hook_function(&patch_send);
	 }
	 else {
		 goto Exit;
	 }

	RecievedData = (struct stPayload*)CreateRingBuffer();
	if (RecievedData == nullptr) {
		printf("CreateRingBuffer failed\n");
		goto Exit;
	}
	write_ptr = (uintptr_t)RecievedData;
	
	while (!(GetAsyncKeyState(VK_F10) & 0x01)) {
		Sleep(1);

	}
	SHUTTINGDOWN = 1;
	Sleep(500);
	shut_down();

	goto Exit;

Exit:
	
	printf(">>>Unloading Winsock32_hook\n");
	FreeRingBuffer();
	
	if (console_allocated) 
	{
		PostMessage(GetConsoleWindow(), WM_QUIT, 0, 0);
		FreeConsole();
	}
	FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpr) {
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		FILE* pConsole;
		if (GetConsoleWindow() == NULL) {
			if (AllocConsole()) {
				freopen_s(&pConsole, "CONOUT$", "w", stdout);
				SetConsoleTitle("Console");
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
				console_allocated = 1;
			}
		}
		else {
			freopen_s(&pConsole, "CONOUT$", "w", stdout);
		}
			printf(">>>Loading Winsock32_hook\n");
			HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr);
			if (hThread != nullptr) {
				CloseHandle(hThread);
			}
			return TRUE;

	case DLL_PROCESS_DETACH:
		break;
	}
}