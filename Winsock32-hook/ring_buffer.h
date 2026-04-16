#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma comment(lib, "onecore.lib")
#if !defined(nullptr)
#define nullptr ((void*)0)
#endif

void* CreateRingBuffer();
void FreeRingBuffer();
int testRingBuffer();

extern void* RingBuffer_pointer;
extern void* secondaryView;