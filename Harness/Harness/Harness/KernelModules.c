// Copyright (c) 2021, SafeBreach & Guardicore
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// AUTHORS: Peleg Hadar (@peleghd), Ophir Harpaz (@OphirHarpaz)

#include "Globals.h"
#include "KernelModules.h"

NTSTATUS InitKernelModules(PKERNEL_MODULES pKernelModules)
{
    /* Based on https://github.com/thomhastings/mimikatz-en/blob/master/driver/modules.c */

    NTSTATUS status = STATUS_SUCCESS;
    ULONG modulesSize = 0;
    ULONG numberOfModules = 0;
    PVOID getRequiredBufferSize = NULL;
    AUX_MODULE_EXTENDED_INFO* modules = NULL;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Failed in AuxKlibInitialize, 0x%x\n", status);
        goto exit;
    }

    /* Get the size of the struct for requested information */
    status = AuxKlibQueryModuleInformation(
        &modulesSize,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        getRequiredBufferSize
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Failed to get kernel modules information\n");
        goto exit;
    }

    /* Create a new buffer for the modules */
    numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
    modules = (AUX_MODULE_EXTENDED_INFO*)ExAllocatePool2(
        POOL_FLAG_PAGED,
        modulesSize,
        POOL_TAG
    );
    if (modules == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Failed to allocate modules buffer\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }
    RtlZeroMemory(modules, modulesSize);

    /* Now get the actual information... */
    status = AuxKlibQueryModuleInformation(
        &modulesSize,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Failed to query module information, status: 0x%x\n", status);
        ExFreePoolWithTag(pKernelModules->modules, POOL_TAG);
        goto exit;
    }

    pKernelModules->modules = modules;
    pKernelModules->numberOfModules = numberOfModules;

exit:
    return status;
}

VOID DeinitKernelModules(PKERNEL_MODULES pKernelModules)
{
    ExFreePoolWithTag(pKernelModules->modules, POOL_TAG);
}

ULONG GetKernelModulesCount(PKERNEL_MODULES pKernelModules)
{
    return pKernelModules->numberOfModules;
}

PCSZ GetKernelModuleNameByIndex(PKERNEL_MODULES pKernelModules, ULONG i)
{
    if (i >= pKernelModules->numberOfModules)
    {
        return NULL;
    }
    return (PCSZ)(pKernelModules->modules[i].FullPathName);
}

PVOID GetKernelModuleBaseAddressByIndex(PKERNEL_MODULES pKernelModules, ULONG i)
{
    if (i >= pKernelModules->numberOfModules)
    {
        return NULL;
    }
    return pKernelModules->modules[i].BasicInfo.ImageBase;
}

NTSTATUS GetModuleAddress(PUNICODE_STRING targetModuleName, PVOID* targetBaseAddr)
{
    NTSTATUS status = STATUS_SUCCESS;
    KERNEL_MODULES kernelModules;
    ULONG numberOfModules;
    UNICODE_STRING currentUnicode = { 0 };
    ANSI_STRING currentAnsi = { 0 };
    LONG stringCompareRes = 0;
    BOOLEAN caseInsensitive = TRUE;
    BOOLEAN allocateDestinationString = TRUE;


    status = InitKernelModules(&kernelModules);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Couldn't InitKernelModules\n");
    if (!NT_SUCCESS(status))
    {
        goto exit;
    }

    status = STATUS_NOT_FOUND;
    numberOfModules = GetKernelModulesCount(&kernelModules);
    for (ULONG i = 0; i < numberOfModules; i++)
    {
        RtlInitAnsiString(&currentAnsi, GetKernelModuleNameByIndex(&kernelModules, i));
        status = RtlAnsiStringToUnicodeString(&currentUnicode, &currentAnsi, allocateDestinationString);
        if (!NT_SUCCESS(status))
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Could not convert an Ansi string to a Unicode one\n");
            goto deinit;
        }

        stringCompareRes = RtlCompareUnicodeString(&currentUnicode, targetModuleName, caseInsensitive);
        if (stringCompareRes)
            continue;

        *targetBaseAddr = GetKernelModuleBaseAddressByIndex(&kernelModules, i);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Found Module %wZ address at %p\n", targetModuleName, *targetBaseAddr);
        status = STATUS_SUCCESS;
        break;
    }

deinit:
    DeinitKernelModules(&kernelModules);
exit:
    return status;
}

PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    ASSERT(ModuleBase && pFunctionName);
    PVOID pFunctionAddress = NULL;

    ULONG size = 0;
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
        RtlImageDirectoryEntryToData(ModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &size);

    ULONG_PTR addr = (ULONG_PTR)(PUCHAR)((UINT64)exports - (UINT64)ModuleBase);

    PULONG functions = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfFunctions);
    PSHORT ordinals = (PSHORT)((ULONG_PTR)ModuleBase + exports->AddressOfNameOrdinals);
    PULONG names = (PULONG)((ULONG_PTR)ModuleBase + exports->AddressOfNames);
    ULONG  max_name = exports->NumberOfNames;
    ULONG  max_func = exports->NumberOfFunctions;

    ULONG i;

    for (i = 0; i < max_name; i++)
    {
        ULONG ord = ordinals[i];
        if (i >= max_name || ord >= max_func) {
            return NULL;
        }
        if (functions[ord] < addr || functions[ord] >= addr + size)
        {
            if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
            {
                pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
                break;
            }
        }
    }
    return pFunctionAddress;
}