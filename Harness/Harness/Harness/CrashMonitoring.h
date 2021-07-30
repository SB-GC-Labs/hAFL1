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

#pragma once
#include <ntddk.h>
#include "Globals.h"


#define UNW_FLAG_NHANDLER   0
#define UNW_FLAG_EHANDLER   1
#define UNW_FLAG_UHANDLER   2

#define HYPERCALL_KAFL_CRASH_DUMP 22
#define HYPERCALL_KAFL_CRASH_SIZE 23
#define HYPERCALL_KAFL_PANIC    8

NTSTATUS
ModuleInitialize(
    VOID);

VOID
ModuleTeardown(
    VOID
);

VOID
ModuleLookup(
    IN  ULONG_PTR   Address,
    OUT PCHAR* Name,
    OUT PULONG_PTR  Offset
);

extern VOID
RtlCaptureContext(
    __out PCONTEXT    Context
);

typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
    ULONG64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, * PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
    ULONG Count;
    UCHAR Search;
    UCHAR RaiseStatusIndex;
    BOOLEAN Unwind;
    BOOLEAN Exception;
    ULONG64 LowAddress;
    ULONG64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[UNWIND_HISTORY_TABLE_SIZE];
} UNWIND_HISTORY_TABLE, * PUNWIND_HISTORY_TABLE;

extern PRUNTIME_FUNCTION
RtlLookupFunctionEntry(
    __in ULONG64 ControlPc,
    __out PULONG64 ImageBase,
    __inout_opt PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
);

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;

extern PEXCEPTION_ROUTINE
RtlVirtualUnwind(
    __in ULONG HandlerType,
    __in ULONG64 ImageBase,
    __in ULONG64 ControlPc,
    __in PRUNTIME_FUNCTION FunctionEntry,
    __inout PCONTEXT ContextRecord,
    __out PVOID* HandlerData,
    __out PULONG64 EstablisherFrame,
    __inout_opt PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
);

void kAFL_Hypercall(UINT64 dwHypercall, UINT64 buf);
