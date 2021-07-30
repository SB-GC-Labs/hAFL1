#include "Driver.h"
#include "Globals.h"
#include "KernelModules.h"
#include "CrashMonitoring.h"
#include "PatchLogic.h"

#define IOCTL_SEND_PACKET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_INIT_OPAQUE_STRUCTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RETREIVE_CHANNEL_POINTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3, METHOD_BUFFERED, FILE_WRITE_ACCESS)

EVT_WDF_DRIVER_UNLOAD DriverUnload;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL IoctlHandler;
PCWSTR vmbkmclrModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\vmbkmclr.sys";
PCWSTR vmswitchModulePath = (PCWSTR)L"\\SystemRoot\\System32\\drivers\\vmswitch.sys";
PVOID vmbkmclrBaseAddress;
PVOID vmswitchBaseAddress;
PFN_VMB_PACKET_ALLOCATE pVmbPacketAllocate = NULL;
pVmsVmNicPvtVersion1HandleRndisSendMessage VmsVmNicPvtVersion1HandleRndisSendMessage = NULL;
PVOID channel;

PDEVICE_OBJECT deviceObject = NULL;
PVOID remoteChannelBuf = NULL;
PVOID fakeMdlArray = NULL;
PVOID rndisDevConfig = NULL;
PVOID RndisDevContext = NULL;
KBUGCHECK_CALLBACK_RECORD    BugcheckCallbackRecord;
KBUGCHECK_CALLBACK_ROUTINE BugcheckCallback;

DECLARE_CONST_UNICODE_STRING(dosDeviceName, DOS_DEVICE_NAME);
DECLARE_CONST_UNICODE_STRING(ntDeviceName, NT_DEVICE_NAME);


NTSTATUS SendPacketWrapper(PVOID packetRequestBuf, ULONG packetRequestBufSize)
/* Prepare an RNDIS packet and its corresponding control buffer, then call SendPacket */
{
    NTSTATUS status = STATUS_SUCCESS;

    PVOID pPacketBuf = NULL;
    PVOID pNvspControlBuf = NULL;
    ULONG userPacketBufSize = packetRequestBufSize;

    // Prepare the actual RNDIS packet
    pPacketBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, userPacketBufSize, HARNESS_POOL_TAG);
    if (pPacketBuf == NULL) {
        goto cleanup;
    }
    RtlCopyMemory(pPacketBuf, packetRequestBuf, userPacketBufSize);

    // Initialize a control buffer suitable for the RNDIS packet
    pNvspControlBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, NVSP_RNDIS_SEND_PACKET_SIZE, HARNESS_POOL_TAG);
    if (pNvspControlBuf == NULL) {
        goto cleanup;
    }
    memset(pNvspControlBuf, 0, NVSP_RNDIS_SEND_PACKET_SIZE);
    ((UINT*)pNvspControlBuf)[0] = 0x0000006B;        // NVSP_RNDIS_SEND_PACKET
    ((UINT*)pNvspControlBuf)[1] = 0x00000001;        // Channel type (control)
    ((UINT*)pNvspControlBuf)[2] = 0xFFFFFFFF;        // send_buf_section_index
    ((UINT*)pNvspControlBuf)[3] = (UINT)0;           // send_buf_section_size

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Calling SendPacket\n");
    status = SendPacket(pNvspControlBuf, pPacketBuf, userPacketBufSize);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: SendPacket Failed: %x\n", status);
        goto cleanup;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: SendPacket Success\n");

    status = STATUS_SUCCESS;

cleanup:
    if (pNvspControlBuf) {
        ExFreePoolWithTag(pNvspControlBuf, HARNESS_POOL_TAG);
        pNvspControlBuf = NULL;
    }
    if (pPacketBuf) {
        ExFreePoolWithTag(pPacketBuf, HARNESS_POOL_TAG);
        pPacketBuf = NULL;
    }
    return status;
}

NTSTATUS SendPacket(PVOID pNvspControlBuf, PVOID dataBuf, ULONG dataBufLen) 
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pMdl = NULL;
    VMBPACKET packet = NULL;
    PVOID dummyPtr = NULL;
    UINT64 qwordVar = 0;
    PVOID pDummyBuf = NULL;
    PMDL* dummyPmdl = NULL;
    
    if (pNvspControlBuf == NULL) {
        status = STATUS_INVALID_PARAMETER;
    }

    pMdl = IoAllocateMdl(dataBuf, dataBufLen, FALSE, FALSE, NULL);
    if (pMdl == NULL) {
        status = STATUS_BUFFER_TOO_SMALL;
        return status;
    }
    MmBuildMdlForNonPagedPool(pMdl);
    
    /* fakMdlArray may have already been allocated previously */
    if (fakeMdlArray == NULL) {
        fakeMdlArray = ExAllocatePool2(POOL_FLAG_NON_PAGED, FAKE_ARRAY_SIZE, HARNESS_POOL_TAG);
        if (fakeMdlArray == NULL) {
            goto cleanup;
        }
    }
    (*(UINT64*)fakeMdlArray) = (UINT64)pMdl;

    dummyPtr = channel;
    
    // Usage: vmbkmclr!VmbChannelGetPointer
    dummyPtr = (UINT64*)((char*)channel + 0x8F8);
    dummyPtr = *(UINT64**)dummyPtr;
    dummyPtr = (UINT64*)((char*)dummyPtr + 0x28);
    dummyPmdl = (PMDL*)dummyPtr;
    *dummyPmdl = (PMDL)fakeMdlArray;

    dummyPtr = channel;
    dummyPtr = (UINT64*)((char*)channel + 0x8F8);
    dummyPtr = *(UINT64**)dummyPtr;
    dummyPtr = (UINT64*)((char*)dummyPtr + 0x8);
    dummyPtr = *(UINT64**)dummyPtr;
    
    // VmsVmNicPvtKmclProcessPacket + 0x15E (Changed from 0x24C to 0x244)
    dummyPtr = (UINT32*)((char*)dummyPtr + 0x244);
    *(UINT32*)dummyPtr = 0x2;

    // Filling packet fields for vmbkmclr!VmbChannelPacketGetClientContext
    packet = pVmbPacketAllocate((VMBCHANNEL)channel);
    pDummyBuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PACKET_BUF_SIZE, HARNESS_POOL_TAG);
    
    dummyPtr = (UINT64*)((char*)packet + 0x30);
    qwordVar = (UINT64)pMdl;
    memcpy(dummyPtr, &qwordVar, 0x8);

    (*(UINT32*)((char*)packet + 0x40)) = (UINT32)0;
    dummyPtr = (UINT64*)((char*)packet + 0xA0);
    qwordVar = (UINT64)pDummyBuf;
    memcpy(dummyPtr, &qwordVar, 0x8);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Calling VmsVmNicPvtVersion1HandleRndisSendMessage\n");
    (((UINT32*)channel)[8]) = (UINT32)0x10; // In HandleRndis + 0x1B4, goto ProcessingComplete.

    /* This is the fuzzing point! */
    VmsVmNicPvtVersion1HandleRndisSendMessage((VMBCHANNEL)channel, pNvspControlBuf, pMdl, packet);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Returned From VmsVmNicPvtVersion1HandleRndisSendMessage\n");

cleanup:
    if (pDummyBuf) {
        ExFreePoolWithTag(pDummyBuf, HARNESS_POOL_TAG);
        pDummyBuf = NULL;
    }

    if (fakeMdlArray) {
        ExFreePoolWithTag(fakeMdlArray, HARNESS_POOL_TAG);
        fakeMdlArray = NULL;
    }

    return status;
}

NTSTATUS LocateTargetFunctions()
/* Locate functions VmbPacketAllocate and VmsVmNicPvtVersion1HandleRndisSendMessage 
 * in vmbkmclr and vmswitch, respectively
 */
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING vmbkmclrModuleName;
    UNICODE_STRING vmswitchModuleName;
    CHAR vmbPacketAllocate[] = "VmbPacketAllocate";

    /* Locate vmbkmclr and vmswitch modules in memory */
    RtlInitUnicodeString(&vmbkmclrModuleName, vmbkmclrModulePath);
    status = GetModuleAddress(&vmbkmclrModuleName, &vmbkmclrBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: vmbkmclr Address was not found\n");
        return status;
    }

    RtlInitUnicodeString(&vmswitchModuleName, vmswitchModulePath);
    status = GetModuleAddress(&vmswitchModuleName, &vmswitchBaseAddress);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: vmswitch Address was not found\n");
        return status;
    }

    /* Fetch the functions from the modules above */
    pVmbPacketAllocate = (PFN_VMB_PACKET_ALLOCATE)KernelGetProcAddress(vmbkmclrBaseAddress, (PCHAR)&vmbPacketAllocate);
    VmsVmNicPvtVersion1HandleRndisSendMessage = (pVmsVmNicPvtVersion1HandleRndisSendMessage)((char*)vmswitchBaseAddress + VMSWITCH_OFFSET_HANDLE_RNDIS_MESSAGE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: VmbPacketAllocate Address: %p\n", pVmbPacketAllocate);

    return status;
}

VOID IoctlHandler(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength, size_t InputBufferLength, ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(Queue);

    NTSTATUS status;
    PVOID requestBuf = NULL;
    ULONG requestBufSize = 0;

    switch (IoControlCode) {
    case IOCTL_RETREIVE_CHANNEL_POINTER:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: IoctlHandler, 0x%x - IOCTL_RETREIVE_CHANNEL_POINTER!\n", IoControlCode);
        RetreiveChannelPointer();
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return; 
    case IOCTL_INIT_OPAQUE_STRUCTS:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: IoctlHandler, 0x%x - IOCTL_INIT_OPAQUE_STRUCTS!\n", IoControlCode);
        InitOpaqueStructs();
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    case IOCTL_SEND_PACKET:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: IoctlHandler, 0x%x - IOCTL_SEND_PACKET!\n", IoControlCode);
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &requestBuf, (size_t*)&requestBufSize);
        if (!NT_SUCCESS(status)) {
            return;
        }
        WdfRequestComplete(Request, STATUS_SUCCESS);
        SendPacketWrapper(requestBuf, requestBufSize);
        return;
    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: IoctlHandler, Unknown IOCTL 0x%x, returning!\n", IoControlCode);
        return;
    }
}

VOID DriverUnload(WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Driver unloading\n");
    KeDeregisterBugCheckCallback(&BugcheckCallbackRecord);
    ModuleTeardown();
}

NTSTATUS DeviceAdd(WDFDRIVER Driver, PWDFDEVICE_INIT DeviceInit)
/* https://github.com/microsoft/Windows-driver-samples/blob/master/gpio/samples/simdevice/simdevice.c */
{
    UNREFERENCED_PARAMETER(Driver);

    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES FdoAttributes;
    WDFDEVICE Device;
    WDF_IO_QUEUE_CONFIG ioQueueConfig;
    WDFQUEUE hQueue;

    WDF_OBJECT_ATTRIBUTES_INIT(&FdoAttributes);

    status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceInitAssignName Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceInitAssignName succeed\n");

    status = WdfDeviceInitAssignSDDLString(DeviceInit, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_R_RES_R);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceInitAssignSDDLString Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceInitAssignSDDLString succeed\n");

    status = WdfDeviceCreate(&DeviceInit, &FdoAttributes, &Device);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceCreate Failed: %x\n", status);
        goto EvtDeviceAddEnd;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceCreate succeed\n");

    deviceObject = WdfDeviceWdmGetDeviceObject(Device);
    if (deviceObject == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceWdmGetDeviceObject Failed\n");
        goto EvtDeviceAddEnd;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceWdmGetDeviceObject Succeed\n");

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);

    ioQueueConfig.EvtIoDeviceControl = IoctlHandler;

    status = WdfIoQueueCreate(Device, &ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, &hQueue);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfIoQueueCreate Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfIoQueueCreate succeed\n");

    status = WdfDeviceCreateSymbolicLink(Device, &dosDeviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceCreateSymbolicLink Failed: %x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDeviceCreateSymbolicLink succeed\n");

EvtDeviceAddEnd:
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{   
    NTSTATUS status = STATUS_SUCCESS;
    WDF_DRIVER_CONFIG config;

    /* Register the driver and its callbacks */
    WDF_DRIVER_CONFIG_INIT(&config, DeviceAdd);
    config.EvtDriverUnload = DriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDriverCreate failed: 0x%x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: WdfDriverCreate succeeded\n");

    /* Locate functions necessary for fuzzing */
    status = LocateTargetFunctions();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: LocateTargetFunctions failed: 0x%x\n", status);
        return status;
    }
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: LocateTargetFunctions succeeded\n");

    /* Patch vmswitch to exclude vmbus logic that fails us */
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Starting with Patching Logic...\n");
    PatchLogic();
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_LEVEL, "Harness: Done Patching!\n");

    /* Register BugCheck callbacks for detailed crash reports */
    KeInitializeCallbackRecord(&BugcheckCallbackRecord);
    KeRegisterBugCheckCallback(&BugcheckCallbackRecord, BugcheckCallback, NULL, 0, (PUCHAR)"BugcheckCallback");
    
    ModuleInitialize();

    return status;
}