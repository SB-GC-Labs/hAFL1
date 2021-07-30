#include <stdio.h>
#include <Windows.h>

#define HARNESS L"\\\\.\\Harness"
#define IOCTL_VMSWITCH_TRIGGER_MORPH 0x22344c // Consider 0x22144C (Regular flow shows it in WinDbg)
#define IOCTL_INIT_OPAQUE_STRUCTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_RETREIVE_CHANNEL_POINTER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x3, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_FIRST 0x3EC04C
#define IOCTL_SECOND 0x3EC074
#define STATUS_FAILED 1
#define STATUS_SUCCESS 0
#define INPUT_BUFFER_LENGTH 0x68c
#define VMBUS_DATA_BUF_SIZE 0x100
#define MORPH_BUF_HANDLE_OFFSET 0x638
#define REQUIRED_ARGC_VALUE 5


int CreateHarnessHandle(PHANDLE phHarness)
{

    // Concatenate szGuid
    *phHarness = CreateFileW(
        HARNESS,          // drive to open
        GENERIC_WRITE,                // no access to the drive
        0,
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        0,                // file attributes
        NULL);         // do not copy file attributes
    if (INVALID_HANDLE_VALUE == *phHarness) {
        printf("[!] Harness Handle opening was failed: 0x%x\n", GetLastError());
        return STATUS_FAILED;
    }
    return STATUS_SUCCESS;
}

int TriggerRetreiveChannel(HANDLE hHarness)
{
    BOOL bResult = TRUE;
    DWORD dwBytesReturned = 0;

    bResult = DeviceIoControl(
        hHarness,                       // device to be queried
        IOCTL_RETREIVE_CHANNEL_POINTER, // operation to perform
        NULL, 0,                       // no input buffer
        NULL, 0,            // output buffer
        &dwBytesReturned,                         // # bytes returned
        (LPOVERLAPPED)NULL
    );

    if (!bResult) {
        printf("[!] IOCTL_RETREIVE_CHANNEL_POINTER DeviceIoControl Failed: 0%x\n", GetLastError());
        return STATUS_FAILED;
    }

    return STATUS_SUCCESS;

}

int TriggerInitOpaqueStructs(HANDLE hHarness)
{
    BOOL bResult = TRUE;
    DWORD dwBytesReturned = 0;

    bResult = DeviceIoControl(
        hHarness,                       // device to be queried
        IOCTL_INIT_OPAQUE_STRUCTS, // operation to perform
        NULL, 0,                       // no input buffer
        NULL, 0,            // output buffer
        &dwBytesReturned,                         // # bytes returned
        (LPOVERLAPPED)NULL
    );

    if (!bResult) {
        printf("[!] IOCTL_INIT_OPAQUE_STRUCTS DeviceIoControl Failed: 0%x\n", GetLastError());
        return STATUS_FAILED;
    }

    return STATUS_SUCCESS;
}

int AssembleVMSwitchGuid(wchar_t* szVmGuid, wchar_t* szVNicGuid, wchar_t *outGuid)
{
   wsprintf(outGuid, L"\\\\.\\VmSwitch\\%ws--%ws", szVmGuid, szVNicGuid);
   return STATUS_SUCCESS;
}

int AssembleVMBusGuid(wchar_t* szVmGuid, wchar_t* outGuid)
{
    wsprintf(outGuid, L"\\\\.\\VMBus\\vdev\\{%ws}", szVmGuid);
    return STATUS_SUCCESS;
}

void print_usage(wchar_t *argv[])
{
    printf("Usage: %ws [VM_GUID] [VNIC_GUID] [VM_NAME] [MORPH_BUFFER_PATH]\n", argv[0]);
}

int TriggerVMSwitchMorphFunction(HANDLE hVmSwitch, LPCWSTR szBufferFilePath, DWORD dwBufferSize, HANDLE hVmBusHandle)
{
    HANDLE hBufferFile = INVALID_HANDLE_VALUE;
    PVOID pDataBuf = NULL;
    UINT32 status = STATUS_SUCCESS;
    BOOL bResult = TRUE;
    DWORD dwBytesReturned = 0;
    CHAR outBuf[4] = { 0 };

    // Allocating a Buffer, Then reading the Buffer File
    hBufferFile = CreateFileW(
       szBufferFilePath,          // drive to open
        GENERIC_READ,                // no access to the drive
        0,
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        0,                // file attributes
        NULL);         // do not copy file attributes

    if (INVALID_HANDLE_VALUE == hBufferFile)
    {
        printf("[!] Failed to open input file: 0%x\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }

    pDataBuf = VirtualAlloc(NULL, INPUT_BUFFER_LENGTH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == pDataBuf)
    {
        printf("[!] VirtualAlloc was failed: 0x%lx\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }
    memset(pDataBuf, 0, INPUT_BUFFER_LENGTH);

    bResult = ReadFile(
        hBufferFile,
        pDataBuf,
        INPUT_BUFFER_LENGTH,
        &dwBytesReturned,
        NULL
    );

    if (dwBytesReturned != INPUT_BUFFER_LENGTH)
    {
        printf("ERROR! Didn't read the expected number of bytes...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }


    ((UINT32*)pDataBuf)[MORPH_BUF_HANDLE_OFFSET / sizeof(UINT32)] = (UINT32)hVmBusHandle;
    bResult = DeviceIoControl(
        hVmSwitch,                       // device to be queried
        IOCTL_VMSWITCH_TRIGGER_MORPH, // operation to perform
        pDataBuf,
        INPUT_BUFFER_LENGTH,                       // no input buffer
        outBuf, 4,            // output buffer
        &dwBytesReturned,                         // # bytes returned
        (LPOVERLAPPED)NULL
    );
    if (!bResult) {
        printf("ERROR! Sending IOCTL to VMSwitch was failed, Error: 0x%x\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }

cleanup:
    if (NULL != pDataBuf)
        VirtualFree(pDataBuf, 0, MEM_RELEASE);
    if (INVALID_HANDLE_VALUE != hBufferFile)
        CloseHandle(hBufferFile);
    return status;
}
int InitializeVMBus(HANDLE hVmBusHandle, LPCWSTR szVmName)
{
    HANDLE hBufferFile = INVALID_HANDLE_VALUE;
    UINT32 status = STATUS_SUCCESS;
    PVOID pVmBusDataBuf = NULL;
    CHAR outBuf[0xC] = { 0 };
    BOOL bResult = TRUE;
    DWORD dwBytesReturned = 0;

    pVmBusDataBuf = VirtualAlloc(NULL, VMBUS_DATA_BUF_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (NULL == pVmBusDataBuf)
    {
        printf("[!] VirtualAlloc failed: 0x%x\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }
    memset(pVmBusDataBuf, 0, VMBUS_DATA_BUF_SIZE);

    ((UINT64*)pVmBusDataBuf)[0] = (UINT64)0x50000;
    wcscpy((wchar_t*)((char*)pVmBusDataBuf + 0x8), szVmName);

    // Won't check the result, as it's suppose to fail
    bResult = DeviceIoControl(
        hVmBusHandle,                       // device to be queried
        IOCTL_FIRST, // operation to perform
        pVmBusDataBuf,
        VMBUS_DATA_BUF_SIZE,                       // no input buffer
        NULL, 0,            // output buffer
        &dwBytesReturned,                         // # bytes returned
        (LPOVERLAPPED)NULL
    );

    // Won't check the result, as it's suppose to fail
    bResult = DeviceIoControl(
        hVmBusHandle,                       // device to be queried
        IOCTL_SECOND, // operation to perform
        NULL, 0,                       // no input buffer
        outBuf, 0xC,            // output buffer
        &dwBytesReturned,                         // # bytes returned
        (LPOVERLAPPED)NULL
    );
    


cleanup:
    if (INVALID_HANDLE_VALUE != hBufferFile)
        CloseHandle(hBufferFile);
    if (NULL != pVmBusDataBuf)
        VirtualFree(pVmBusDataBuf, 0, MEM_RELEASE);
    return status;
}
int CreateVmbusHandle(PHANDLE phVmbusHandle, LPCWSTR szGuid)
{

    // Concatenate szGuid
    *phVmbusHandle = CreateFileW(
        szGuid,          // drive to open
        GENERIC_ALL,                // no access to the drive
        0,
        NULL,             // default security attributes
        OPEN_EXISTING,    // disposition
        0,                // file attributes
        NULL);         // do not copy file attributes
    if (INVALID_HANDLE_VALUE == *phVmbusHandle) {
        printf("[!] Vmbus Handle opening was failed: 0x%x\n", GetLastError());
        return STATUS_FAILED;
    }    
    return STATUS_SUCCESS;
}
int CreateVmswitchHandle(PHANDLE phVmSwitch, LPCWSTR szGuid)
{
    typedef DWORD(*pVmsIfNicCreateSynthetic)(PVOID* a1, LPCWSTR a2);
    HANDLE hDll = INVALID_HANDLE_VALUE;
    pVmsIfNicCreateSynthetic VmsIfNicCreateSynthetic = NULL;
    UINT32 status = 0;

    hDll = LoadLibrary(L"c:\\windows\\system32\\vmsif.dll");
    if (NULL == hDll) {
        printf("LoadLibrary was failed: 0x%x\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }

    VmsIfNicCreateSynthetic = (pVmsIfNicCreateSynthetic)GetProcAddress(hDll, "VmsIfNicCreateSynthetic");
    if (NULL == VmsIfNicCreateSynthetic) {
        printf("GetProcAddress was failed: 0x%x\n", GetLastError());
        status = STATUS_FAILED;
        goto cleanup;
    }

    // Concatenate szGuid
    // L"\\\\.\\VmSwitch\\8C157683-BFE6-4C84-BC99-238842C425DE--7CEDB39D-8F04-40FC-AACB-76FEBEC7A5C2"
    status = VmsIfNicCreateSynthetic(phVmSwitch, szGuid);
    if (status < 0) {
        printf("[!] VmsIfNicCreateSynthetic was failed: 0x%x\n", GetLastError());
        goto cleanup;
    }

    status = STATUS_SUCCESS;

cleanup:
    if (INVALID_HANDLE_VALUE != hDll)
        CloseHandle(hDll);

    VmsIfNicCreateSynthetic = NULL;

    return status;
}
int wmain(int argc, wchar_t* argv[]) {
    BOOL bResult = FALSE;
    DWORD dwBytesReturned = 0;
    HANDLE hVmbusHandle = INVALID_HANDLE_VALUE;
    HANDLE hVmSwitch = NULL;
    HANDLE hHarness = INVALID_HANDLE_VALUE;
    PCHAR InputBuffer = NULL;
    wchar_t szVmSwitchGuid[128] = { 0 };
    wchar_t szVmBusGuid[128] = { 0 };

    DWORD status = 0;

    if (REQUIRED_ARGC_VALUE != argc) {
        print_usage(argv);
        return 1;
    }

    AssembleVMSwitchGuid(argv[1], argv[2], szVmSwitchGuid);
    AssembleVMBusGuid(argv[1], szVmBusGuid);

    printf("[+] Assembled VMSwitch Guid: %ws\n", szVmSwitchGuid);
    printf("[+] Assembled VMBus Guid: %ws\n", szVmBusGuid);

    // Open an handle to Harness
    printf("[+] Creating Harness Handle...\n");
    status = CreateHarnessHandle(&hHarness);
    if (STATUS_SUCCESS != status) {
        printf("ERROR! Couldn't Create Harness Handle! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }

    getchar();

    // Open an handle to VMSwitch
    printf("[+] Creating VMSwitch Handle...\n");
    status = CreateVmswitchHandle(&hVmSwitch, szVmSwitchGuid);
    if (STATUS_SUCCESS != status) {
        printf("[!] ERROR! Couldn't Create VMSwitch Handle! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }
    
    getchar();

    // Open an handle to VMBus
    printf("[+] Creating VMBus Handle...\n");
    status = CreateVmbusHandle(&hVmbusHandle, szVmBusGuid);
    if (STATUS_SUCCESS != status) {
        printf("[!] ERROR! Couldn't Create VMBus Handle! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }
  
    getchar();

    printf("[+] Initializing VMBus...\n");
    status = InitializeVMBus(hVmbusHandle, argv[3]);
    if (STATUS_SUCCESS != status) {
        printf("[!] ERROR! Couldn't Initialize VMBus! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }

    getchar();

    printf("[+] Triggering VMSwitch Morph Function...\n");
    status = TriggerVMSwitchMorphFunction(hVmSwitch, argv[4], INPUT_BUFFER_LENGTH, hVmbusHandle);
    if (STATUS_SUCCESS != status) {
        printf("[!] ERROR! Couldn't Initialize VMSwitch and Trigger Morph! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }

    getchar();

    printf("[+] Triggering Harness Retreive Channel Logic...\n");
    status = TriggerRetreiveChannel(hHarness);
    if (STATUS_SUCCESS != status) {
        printf("ERROR! Couldn't Trigger Retreive Channel! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }

    getchar();

    printf("[+] Triggering Harness Init Opaque Structs Logic...\n");
    status = TriggerInitOpaqueStructs(hHarness);
    if (STATUS_SUCCESS != status) {
        printf("[!] ERROR! Couldn't Trigger Init Opaque Structs! Exiting...\n");
        status = STATUS_FAILED;
        goto cleanup;
    }

    printf("[*] Waiting for a key press... Don't press unless you want all handles to be closed!\n");
    getchar();

cleanup:
    if (INVALID_HANDLE_VALUE != hHarness)
        CloseHandle(hHarness);
    if (INVALID_HANDLE_VALUE != hVmbusHandle)
        CloseHandle(hVmbusHandle);
    if (INVALID_HANDLE_VALUE != hVmSwitch)
        CloseHandle(hVmSwitch);
    return status;
}