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

#define NOP_BUFFER_SIZE 0x100

#include "PatchLogic.h"

extern PVOID remoteChannelBuf;
extern PVOID fakeMdlArray;
extern PVOID RndisDevContext;
extern PVOID vmswitchBaseAddress;

extern PVOID channel;

// VMSwitch (21354.1000) - Function Offsets (Global)
const UINT64 vmswitch_RndisDevHostHandleControlMessageOffset = 0x1A9D4;

char nopBuf[NOP_BUFFER_SIZE] = { 0 };

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS WriteToRXMemory(PVOID dst, PVOID src, size_t size)
{
    PVOID pPatchMdl = NULL;
    NTSTATUS status = STATUS_INVALID_ADDRESS;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] Calling IoAllocateMdl...!\n");
    pPatchMdl = IoAllocateMdl(dst, (ULONG)size, FALSE, FALSE, NULL);
    if (pPatchMdl == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] IoAllocateMdl was failed!\n");
        return status;
    }

    __try
    {
        MmProbeAndLockPages(pPatchMdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(pPatchMdl);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] MmProbeAndLockPages failed!\n");
        return STATUS_INVALID_ADDRESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] Calling MmMapLockedPagesSpecifyCache!\n");

    PLONG64 RwMapping = MmMapLockedPagesSpecifyCache(
        pPatchMdl,
        KernelMode,
        MmNonCached,
        NULL,
        FALSE,
        NormalPagePriority
    );

    if (RwMapping == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] MmMapLockedPagesSpecifyCache Failed!\n");
        MmUnlockPages(pPatchMdl);
        IoFreeMdl(pPatchMdl);

        return STATUS_INTERNAL_ERROR;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] Calling MmProtectMdlSystemAddress ...!\n");
    status = MmProtectMdlSystemAddress(pPatchMdl, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] MmProtectMdlSystemAddress was failed!\n");
        MmUnmapLockedPages(RwMapping, pPatchMdl);
        MmUnlockPages(pPatchMdl);
        IoFreeMdl(pPatchMdl);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: [PATCHING] Patching...!\n");
    memcpy((char*)RwMapping, src, size);

    MmUnmapLockedPages(RwMapping, pPatchMdl);
    MmUnlockPages(pPatchMdl);
    IoFreeMdl(pPatchMdl);


    return STATUS_SUCCESS;
}

NTSTATUS PatchLogic()
{
    extern PVOID vmbkmclrBaseAddress;
    NTSTATUS status = STATUS_SUCCESS;
 
    // VMSwitch (21354.1000) - Function Offsets
    const UINT64 vmswitch_VmsVmNicMorphOffset = 0x1A6608;
    const UINT64 vmswitch_VmsVmNicPvtRndisDeviceSetRequestOffset = 0x17100;
    const UINT64 vmswitch_RndisDevHostHandleSetExMessageOffset = 0x1B5430;
    const UINT64 vmswitch_RndisDevDeviceCompleteSetExOffset = 0x1B7568;
    const UINT64 vmswitch_RndisDevHostHandleSetMessageOffset = 0x463A0;
    const UINT64 vmswitch_VmsVmNicPvtRndisDeviceResetRequestOffset = 0x1AACE0;
    const UINT64 vmswitch_RndisDevHostHandleQueryMessageOffset = 0x18530;
    const UINT64 vmswitch_VmsVmNicPvtVersion1HandleRndisSendMessageOffset = 0x366D0;

    // VMSwitch (21354.1000) - Offsets within Functions
    const UINT64 VmsVmNicMorph_postVmbChannelEnableOffset = 0xB28;
    const UINT64 RndisDevHostHandleControlMessage_postIsReceiveBuffersReadyBranchOffset = 0x6A;
    const UINT64 RndisDevHostHandleControlMessage_postAcquireOperationOffset = 0x7E;
    const UINT64 VmsVmNicPvtRndisDeviceSetRequest_callsiteCompleteSetOffset = 0xCD;
    const UINT64 VmsVmNicPvtRndisDeviceSetRequest_callsiteCompleteSetExOffset = 0x114;
    const UINT64 RndisDevDeviceCompleteSetEx_callsiteCompleteSetExOffset = 0xF8;
    const UINT64 RndisDevHostHandleSetMessage_callsiteCompleteSetOffset = 0x109;
    const UINT64 RndisDevHostHandleQueryMessage_callsiteSendQueryCompleteMessageOffset = 0x30A;
    const UINT64 VmsVmNicPvtVersion1HandleRndisSendMessageOffset_callsiteVmbPacketCompleteOffset = 0x471FC;

    // vmbkmclr (21354.1) - Function Offsets
    const UINT64 vmbkmclr_VmbChannelPacketCompleteOffset = 0x2AD0;
    const UINT64 vmbkmclr_VmbChannelPacketDeferUntilPolledOffset = 0x10620;

    char retNopBuf[5] = "\xC3\x90\x90\x90";
    char movChannelShellcode[30] = "\x90\x90\x90\x48\x8B\x4E\x10\x48\x89\x71\x08\x48\xB8\x11\x11\x11\x11\x11\x11\x11\x11\x48\x89\x08\x31\xC0\xEB\x19\x90";
    
    memset(nopBuf, '\x90', NOP_BUFFER_SIZE);

    
    // VmsVmNicMorph+0xB28 (0x1A7130) ==> Patch 29 bytes
  /*
    call r10
       0:  48 8b 4e 10             mov    rcx,QWORD PTR [rsi+0x10]
4:  48 89 71 08             mov    QWORD PTR [rcx+0x8],rsi
8:  48 b8 11 11 11 11 11    movabs rax,0x1111111111111111
f:  11 11 11
12: 48 89 08                mov    QWORD PTR [rax],rcx
15: 31 c0                   xor    eax,eax
17: eb 1c                   jmp    0x35
19: 90                      nop
1a: 90                      nop
1b: 90                      nop
1c: 90                      nop

  */

    /* When VmsVmNicMorph is called, it puts the channel pointer
     * in remoteChannelBuf[0] */
    remoteChannelBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8, 'FBCR');
        
    memcpy((char*)movChannelShellcode + 13, &remoteChannelBuf, 0x8);
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_VmsVmNicMorphOffset + \
                                    VmsVmNicMorph_postVmbChannelEnableOffset), &movChannelShellcode, 29);


    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                                    RndisDevHostHandleControlMessage_postIsReceiveBuffersReadyBranchOffset), &nopBuf, 6);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                                    RndisDevHostHandleControlMessage_postAcquireOperationOffset), &nopBuf, 2);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_VmsVmNicPvtRndisDeviceSetRequestOffset + \
                                    VmsVmNicPvtRndisDeviceSetRequest_callsiteCompleteSetOffset), &nopBuf, 5);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleSetExMessageOffset + \
                                    VmsVmNicPvtRndisDeviceSetRequest_callsiteCompleteSetExOffset), &nopBuf, 5);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevDeviceCompleteSetExOffset + \
                                    RndisDevDeviceCompleteSetEx_callsiteCompleteSetExOffset), &nopBuf, 5);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleSetMessageOffset + \
                                    RndisDevHostHandleSetMessage_callsiteCompleteSetOffset), &nopBuf, 5);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_VmsVmNicPvtRndisDeviceResetRequestOffset), &nopBuf, 5);


    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleQueryMessageOffset + \
                                    RndisDevHostHandleQueryMessage_callsiteSendQueryCompleteMessageOffset), &nopBuf, 5);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_VmsVmNicPvtVersion1HandleRndisSendMessageOffset + \
                                    VmsVmNicPvtVersion1HandleRndisSendMessageOffset_callsiteVmbPacketCompleteOffset), &nopBuf, 7);

    // VmbChannelPacketComplete ==> Patch 4 Bytes (Ret, NOP X 3)
    WriteToRXMemory((PVOID)((char*)vmbkmclrBaseAddress + vmbkmclr_VmbChannelPacketCompleteOffset), &retNopBuf, 4);

    // VmbChannelPacketDeferUntilPolled / VmbChannelPacketFail ==> Patch 3 Bytes (Ret, NOP X 2)
    WriteToRXMemory((PVOID)((char*)vmbkmclrBaseAddress + vmbkmclr_VmbChannelPacketDeferUntilPolledOffset), &retNopBuf, 3);

    return status;
}


NTSTATUS RetreiveChannelPointer()
{
    PVOID dummyBuf = NULL;

    dummyBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x8, 'TBU5');
    fakeMdlArray = ExAllocatePool2(POOL_FLAG_NON_PAGED, FAKE_ARRAY_SIZE, 'TBU6');
   
   /* At this point, the global remoteChannelBuf should already populate the channel pointer */
    channel = (PVOID) * (UINT64*)remoteChannelBuf;
    if (channel == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Channel is NULL, Aborting!\n");
        return STATUS_SUCCESS;
    }
    RndisDevContext = (PVOID)(*(UINT64*)((char*)channel + 0x8));
    (((UINT64*)channel)[6]) = (UINT64)dummyBuf; // channel+0x30 - dummy buffer not in use (allegedly)
    (((UINT32*)channel)[8]) = (UINT32)0x10; // In HandleRndis, goto ProcessingComplete.

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Found Channel: %p!\n", channel);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Found RndisDevContext: %p!\n", RndisDevContext);

    return STATUS_SUCCESS;
}

#pragma pack(push, 1)

typedef struct {
    char filler1[0x120];
    UINT64 isReady;
    char filler2[0xb8];
    UINT32 secondIsReady;
    char filler3[0x3C];
    UINT32 thirdIsReady;
} ConfigInnerStruct;


typedef struct {
    ConfigInnerStruct* configInnerStruct;
    PVOID pfPacketComplete;
    char filler2[0x98];
    UINT32 bufferSize;
} RndisDevConfig;


typedef struct {
    char buf[0xF5BB0];
    RndisDevConfig rndisDevConfig;
} RndisDevConfigWrapper;

typedef struct {
    RndisDevConfigWrapper* rndisDevConfigWrapper;
} ConfigWrapper;

typedef struct {
    char buf1[0x8];
    ConfigWrapper* configWrapper;
    char buf2[0x18];
    PMDL dummyPMDL;
} ChannelInnerStruct;

typedef struct {
    char buf[0x8F8];
    ChannelInnerStruct *pointerInChannel;
} ChannelStruct;

typedef struct {
    char filler1[0x750];
    UINT32 flag;
    UINT32 filler2;
    UINT32 secondFlag;
    UINT32 filler3;
    PVOID pool;
} VMS_OBJ_NIC;

typedef struct {
    char filler1[0x254];
    UINT32 nvspVersion;
    UINT32 ndisVersion;
    char filler2[0x4C];
    VMS_OBJ_NIC *vmsObjNic;
} RndisDevContextStruct;

#pragma pack(pop)


NTSTATUS InitOpaqueStructs()
{
    extern PVOID rndisDevConfig;

    // VMSwitch (21354.1000) - Function Offsets
    const UINT64 vmswitch_RndisDevHostDispatchControlMessageOffset = 0x1A760;
    const UINT64 vmswitch_RndisDevHostReleaseOperationOffset = 0x1AEB4;
    const UINT64 vmswitch_RndisDevHostAcquireOperationOffset = 0x1ACB0;
    const UINT64 vmswitch_RndisDevHostCompleteControlMessageOffset = 0x1A6E0;
    const UINT64 vmswitch_RndisDevHostHandlePacketMessagesOffset = 0x19D60;
    const UINT64 vmswitch_VmsExtFilterSetFilterModuleOptionsOffset = 0x55F60;
    const UINT64 vmswitch_RndisDevHostControlMessageWorkerRoutine = 0x1A9A0;

    // VMSwitch (21354.1000) Globals
    const UINT64 vmswitch_VmsDriverObjectOffset = 0x218890;

    // VMSwitch (21354.1000) - Offsets within Functions
    const UINT64 RndisDevHostDispatchControlMessage_postPushEntrySList = 0x17F;
    const UINT64 RndisDevHostDispatchControlMessage_postLastCfg = 0x4F9EF;
    const UINT64 RndisDevHostHandleControlMessage_postAcquireOperation = 0x7E;
    const UINT64 RndisDevHostHandleControlMessage_callsiteAcquireOperation = 0x77;
    const UINT64 RndisDevHostHandleControlMessage_callsiteReleaseOperation = 0xA2;
    const UINT64 RndisDevHostHandleControlMessage_postPopEntrySListAndJnz = 0xD8;
    const UINT64 RndisDevHostHandlePacketMessages_callsiteLastCfgToSendPackets = 0x1EF;

    NTSTATUS status = STATUS_SUCCESS;
    UINT64 qwordVar = 0;
    PVOID pVmsExtFilterSetFilterModuleOptions = NULL;

    // (1) Create placeholders to not crash in VmsVmNicPvtKmclProcessingCompleteInternal
    
    ((ChannelStruct*)channel)->pointerInChannel->dummyPMDL = fakeMdlArray;

    rndisDevConfig = &((ChannelStruct*)channel)->pointerInChannel->configWrapper->rndisDevConfigWrapper->rndisDevConfig;

    // RndisDevHostDispatchControlMessage + 0x17F (0x1A8DF)
    /*
    0:  4c 8b 87 90 00 00 00    mov    r8,QWORD PTR [rdi+0x90]
    7:  48 b9 11 11 11 11 11    movabs rcx,0x1111111111111111
    e:  11 11 11
    11: 48 ba 22 22 22 22 22    movabs rdx,0x2222222222222222
    18: 22 22 22
    1b: 48 be 33 33 33 33 33    movabs rsi,0x3333333333333333
    22: 33 33 33
    25: ff d6                   call   rsi
                                [NOPS x ...]
    */
    char callWorkerRoutineDirectlyShellcode[75] = "\x90\x90\x90\x4C\x8B\x87\x90\x00\x00\x00\x48\xB9\x11\x11\x11\x11\x11\x11\x11\x11\x48\xBA\x22\x22\x22\x22\x22\x22\x22\x22\x48\xBE\x33\x33\x33\x33\x33\x33\x33\x33\xFF\xD6\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";

    // VmsDriverObject (@rcx)
    qwordVar = (UINT64)((char*)vmswitchBaseAddress + vmswitch_VmsDriverObjectOffset);
    memcpy((char*)callWorkerRoutineDirectlyShellcode + 12, &qwordVar, 0x8);

    // ConfigStruct (Context)
    memcpy((char*)callWorkerRoutineDirectlyShellcode + 22, &rndisDevConfig, 0x8);

    qwordVar = (UINT64)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostControlMessageWorkerRoutine);
    memcpy((char*)callWorkerRoutineDirectlyShellcode + 32, &qwordVar, 0x8);

    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostDispatchControlMessageOffset + \
        RndisDevHostDispatchControlMessage_postPushEntrySList), &callWorkerRoutineDirectlyShellcode, 74);

    char tmpBuf11[2] = "\xD5";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                                    RndisDevHostDispatchControlMessage_postLastCfg), &tmpBuf11, 1);

    /* // RndisDevHostHandleControlMessage + 0x9C ==> Change JNZ to JMP (Bypass Pop from Queue)
    char tmpBuf5[2] = "\xEB";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + 0x1AA70), &tmpBuf5, 1);
    */

    char tmpBuf6[3] = "\x90\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                            RndisDevHostHandleControlMessage_postAcquireOperation), &tmpBuf6, 2);

    char tmpBuf8[6] = "\x90\x90\x90\x90\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                            RndisDevHostHandleControlMessage_callsiteAcquireOperation), &tmpBuf8, 5);

    char tmpBuf9[6] = "\x90\x90\x90\x90\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                                RndisDevHostHandleControlMessage_callsiteReleaseOperation), &tmpBuf9, 5);


    // xor eax, eax; ret;
    char tmpBuf10[6] = "\x31\xC0\xC3\x90\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostReleaseOperationOffset), &tmpBuf10, 5);
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostAcquireOperationOffset), &tmpBuf10, 5);


    // RndisDevHostHandleControlMessage
    char tmpBuf7[5] = "\x49\x89\xC5\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandleControlMessageOffset + \
                                    RndisDevHostHandleControlMessage_postPopEntrySListAndJnz), &tmpBuf7, 4);


    // Patch Out RndisDevHostCompleteControlMessage (0x1A6E0) with xor eax, eax; ret; nop nop;
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostCompleteControlMessageOffset), &tmpBuf10, 5);

    // Patch Out call to SendPackets from HandlePacketMessages + 0x1EF
    char tmpBuf13[7] = "\x90\x90\x90\x90\x90\x90";
    WriteToRXMemory((PVOID)((char*)vmswitchBaseAddress + vmswitch_RndisDevHostHandlePacketMessagesOffset + \
                                    RndisDevHostHandlePacketMessages_callsiteLastCfgToSendPackets), &tmpBuf13, 6);

    // Overwrite VmbPacketComplete
    pVmsExtFilterSetFilterModuleOptions = (PVOID)((char*)vmswitchBaseAddress + vmswitch_VmsExtFilterSetFilterModuleOptionsOffset);
    ((RndisDevConfig*) rndisDevConfig)->pfPacketComplete = pVmsExtFilterSetFilterModuleOptions;

    // RecvBuf Size, Set by RndisDevHostSetBuffers (RndisDevHostSetBuffers + 0x1D5)
    ((RndisDevConfig*) rndisDevConfig)->bufferSize = 0x1000;
    
    // Change Recv Buffers to be "Ready" for RndisDevHostInternalIsReceiveBuffersReady
    ((RndisDevConfig*) rndisDevConfig)->configInnerStruct->isReady = 0x1;
    ((RndisDevConfig*) rndisDevConfig)->configInnerStruct->secondIsReady = 0x0;
    ((RndisDevConfig*) rndisDevConfig)->configInnerStruct->thirdIsReady = 0x0;


    // Set NVSP version on RNDISDeviceContext to version 6.1
    ((RndisDevContextStruct*)RndisDevContext)->nvspVersion = 0x60001;

    // Set NDIS to 6.1
    ((RndisDevContextStruct*)RndisDevContext)->ndisVersion = 0x60001;
    ((RndisDevContextStruct*)RndisDevContext)->vmsObjNic->flag = 0x1;

    // VmsMpCommonPvtHandleMulticastOids + 0x6B
    ((RndisDevContextStruct*)RndisDevContext)->vmsObjNic->secondFlag = 0x1;

    PVOID fakePool = ExAllocatePool2(POOL_FLAG_NON_PAGED, 0x4000, 'TBU9');
    if (fakePool) {
        ((RndisDevContextStruct*)RndisDevContext)->vmsObjNic->pool = fakePool; // See example on VmsMpNicPvtPinMacAddress + 0x3E
    }

    *(UINT32*)((char*)fakePool + 0x10B0) = 0x3;
    return status;
}
