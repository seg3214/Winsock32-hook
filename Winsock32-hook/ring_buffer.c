/*
 * Portions of this code are derived and modified from Microsoft Learn
 * Sample Code (VirtualAlloc2 documentation).
 *
 * Original Source: https://microsoft.com
 * Original Copyright (c) Microsoft Corporation.
 * Modifications Copyright (c) 2023-2026 seg3214 (https://github.com)
 * Modifications: Integrated logic into a C - based ring buffer class and
 * added error handling for specific buffer alignment.
 *
 * This combined work is licensed under the MIT License for the original portions
 * and AGPL-3.0 for the modifications and overall project.
 * 
 * For full license texts, see the LICENSE and THIRD-PARTY-NOTICES 
 * files in the project root.
 */



#include "ring_buffer.h"

static int initialized = 0;
void* RingBuffer_pointer = nullptr;
void* secondaryView = nullptr;


const unsigned int bufferSize = 0x10000;

//
// This function creates a ring buffer by allocating a pagefile-backed section
// and mapping two views of that section next to each other. This way if the
// last record in the buffer wraps it can still be accessed in a linear fashion
// using its base VA.
//
void* CreateRingBuffer()
{
    if (initialized)
    {
        printf("CreateRingBuffer() ERROR cant handle more than 1 ring buffer\n");
        return nullptr;
    }
    BOOL result;
    HANDLE section = nullptr;
    SYSTEM_INFO sysInfo;
    void* placeholder1 = nullptr;
    void* placeholder2 = nullptr;
    void* view1 = nullptr;
    void* view2 = nullptr;

    GetSystemInfo(&sysInfo);

    if ((bufferSize % sysInfo.dwAllocationGranularity) != 0) {
        return nullptr;
    }

    //
    // Reserve a placeholder region where the buffer will be mapped.
    //

    placeholder1 = (PCHAR)VirtualAlloc2(
        nullptr,
        nullptr,
        2 * bufferSize,
        MEM_RESERVE | MEM_RESERVE_PLACEHOLDER,
        PAGE_NOACCESS,
        nullptr, 0
    );

    if (placeholder1 == nullptr) {
        printf("VirtualAlloc2 failed, error %#x\n", GetLastError());
        goto Exit;
    }

    //
    // Split the placeholder region into two regions of equal size.
    //

    result = VirtualFree(
        placeholder1,
        bufferSize,
        MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER
    );

    if (result == FALSE) {
        printf("VirtualFreeEx failed, error %#x\n", GetLastError());
        goto Exit;
    }

    placeholder2 = (void*)((ULONG_PTR)placeholder1 + bufferSize);

    //
    // Create a pagefile-backed section for the buffer.
    //

    section = CreateFileMapping(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        bufferSize, nullptr
    );

    if (section == nullptr) {
        printf("CreateFileMapping failed, error %#x\n", GetLastError());
        goto Exit;
    }

    //
    // Map the section into the first placeholder region.
    //

    view1 = MapViewOfFile3(
        section,
        nullptr,
        placeholder1,
        0,
        bufferSize,
        MEM_REPLACE_PLACEHOLDER,
        PAGE_READWRITE,
        nullptr, 0
    );

    if (view1 == nullptr) {
        printf("MapViewOfFile3 failed, error %#x\n", GetLastError());
        goto Exit;
    }

    //
    // Ownership transferred, don't free this now.
    //

    placeholder1 = nullptr;

    //
    // Map the section into the second placeholder region.
    //

    view2 = MapViewOfFile3(
        section,
        nullptr,
        placeholder2,
        0,
        bufferSize,
        MEM_REPLACE_PLACEHOLDER,
        PAGE_READWRITE,
        nullptr, 0
    );

    if (view2 == nullptr) {
        printf("MapViewOfFile3 failed, error %#x\n", GetLastError());
        goto Exit;
    }

    //
    // Success, return both mapped views to the caller.
    //

    RingBuffer_pointer = view1;

    secondaryView = view2;

    placeholder2 = nullptr;
    view1 = nullptr;
    view2 = nullptr;

    initialized = 1;
Exit:

    if (section != nullptr) {
        CloseHandle(section);
    }

    if (placeholder1 != nullptr) {
        VirtualFree(placeholder1, 0, MEM_RELEASE);
    }

    if (placeholder2 != nullptr) {
        VirtualFree(placeholder2, 0, MEM_RELEASE);
    }

    if (view1 != nullptr) {
        UnmapViewOfFileEx(view1, 0);
    }

    if (view2 != nullptr) {
        UnmapViewOfFileEx(view2, 0);
    }

    return RingBuffer_pointer;
}

void FreeRingBuffer()
{
    if (!initialized) return;
    UnmapViewOfFile(RingBuffer_pointer);
    UnmapViewOfFile(secondaryView);

    RingBuffer_pointer = nullptr;

    secondaryView = nullptr;

    initialized = 0;
}

// 1 if works
int testRingBuffer()
{
    if (initialized)
    {
        printf("cant test already created buffer\n");
        return 0;
    }
    char* ringBuffer;
    void* secondaryView = nullptr;

    int works = 0;

    ringBuffer = (char*)CreateRingBuffer();

    if (ringBuffer == nullptr) {
        printf("CreateRingBuffer failed\n");
        return 0;
    }

    //
    // Make sure the buffer wraps properly.
    //

    ringBuffer[0] = 'a';

    if (ringBuffer[bufferSize] == 'a') {
        printf("The buffer wraps as expected\n");
        works = 1;
    }

    UnmapViewOfFile(ringBuffer);
    UnmapViewOfFile(secondaryView);
    if (works)
        return 1;
    else
        return 0;
}
