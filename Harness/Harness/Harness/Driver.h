#pragma once
#include "Globals.h"

#define DOS_DEVICE_NAME L"\\DosDevices\\Harness"
#define NT_DEVICE_NAME L"\\Device\\Harness"

// VMSwitch.sys, 23154.1000 function offsets
#define VMSWITCH_OFFSET_HANDLE_RNDIS_MESSAGE 0x366D0
#define VMSWITCH_OFFSET_PROCESS_PACKET 0x35500
typedef UINT64* (*pVmsVmNicPvtVersion1HandleRndisSendMessage)(VMBCHANNEL pChannel, void* pBuf, PMDL pMdl, void* PacketCompletionContext);

NTSTATUS SendPacket(PVOID pControlPacket, PVOID dataBuf, ULONG dataBufLen);