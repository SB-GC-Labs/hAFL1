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

#include "CrashMonitoring.h"

VOID
BugCheckStackDump(
    IN  PCONTEXT    Context
)
{
#define PARAMETER_COUNT     4
#define MAXIMUM_ITERATIONS  20
    char buffer[256] = { 0 };
    __try {
        ULONG   Iteration;

        for (Iteration = 0; Iteration < MAXIMUM_ITERATIONS; Iteration++) {
            memset(buffer, 0, 256);

            PRUNTIME_FUNCTION   FunctionEntry;
            ULONG64             ImageBase;
            ULONG64             RIP;
            ULONG64             RSP;
            ULONG64             Parameter[PARAMETER_COUNT] = { 0 };
            ULONG               Index;
            PCHAR               Name;
            ULONG64             Offset;

            if (Context->Rip == 0)
                break;

            FunctionEntry = RtlLookupFunctionEntry(Context->Rip,
                &ImageBase,
                NULL);

            if (FunctionEntry != NULL) {
                CONTEXT                         UnwindContext;
                ULONG64                         ControlPc;
                PVOID                           HandlerData;
                ULONG64                         EstablisherFrame;
                KNONVOLATILE_CONTEXT_POINTERS   ContextPointers;

                UnwindContext = *Context;
                ControlPc = Context->Rip;
                HandlerData = NULL;
                EstablisherFrame = 0;
                RtlZeroMemory(&ContextPointers, sizeof(KNONVOLATILE_CONTEXT_POINTERS));

                (VOID)RtlVirtualUnwind(UNW_FLAG_UHANDLER,
                    ImageBase,
                    ControlPc,
                    FunctionEntry,
                    &UnwindContext,
                    &HandlerData,
                    &EstablisherFrame,
                    &ContextPointers);

                *Context = UnwindContext;
            }
            else {
                Context->Rip = *(PULONG64)(Context->Rsp);
                Context->Rsp += sizeof(ULONG64);
            }

            RSP = Context->Rsp;
            RIP = Context->Rip;

            Index = 0;
            Offset = 0;
            for (;;) {
                if (Index == PARAMETER_COUNT)
                    break;

                Parameter[Index] = *(PULONG64)(RSP + Offset);

                Index += 1;
                Offset += 8;
            }

            ModuleLookup(RIP, &Name, &Offset);

            if (Name != NULL) {
                RtlStringCchPrintfA(buffer, 256, "BUGCHECK: %016X: (%016X %016X %016X %016X) %s + %p\n",
                    RSP,
                    Parameter[0],
                    Parameter[1],
                    Parameter[2],
                    Parameter[3],
                    Name,
                    (PVOID)Offset);
            }
            else {
                RtlStringCchPrintfA(buffer, 256, "BUGCHECK: %016X: (%016X %016X %016X %016X) %p\n",
                    RSP,
                    Parameter[0],
                    Parameter[1],
                    Parameter[2],
                    Parameter[3],
                    (PVOID)RIP);
            }

            kAFL_Hypercall(HYPERCALL_KAFL_CRASH_SIZE, (UINT64)256);
            kAFL_Hypercall(HYPERCALL_KAFL_CRASH_DUMP, (UINT64)buffer);
        }
        memset(buffer, 0, 256);
        RtlStringCchPrintfA(buffer, 256, "======================================\n\n");
        kAFL_Hypercall(HYPERCALL_KAFL_CRASH_SIZE, (UINT64)256);
        kAFL_Hypercall(HYPERCALL_KAFL_CRASH_DUMP, (UINT64)buffer);
    }


    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }
}

VOID
BugcheckCallback(
    IN  PVOID               Argument,
    IN  ULONG               Length
)
{
    KBUGCHECK_DATA KiBugCheckData = { 0 };

    ULONG                   Code;
    ULONG_PTR               Parameter1;
    ULONG_PTR               Parameter2;
    ULONG_PTR               Parameter3;
    ULONG_PTR               Parameter4;
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Length);

    AuxKlibGetBugCheckData(&KiBugCheckData);

    Code = (ULONG)KiBugCheckData.BugCheckCode;
    Parameter1 = KiBugCheckData.Parameter1;
    Parameter2 = KiBugCheckData.Parameter2;
    Parameter3 = KiBugCheckData.Parameter3;
    Parameter4 = KiBugCheckData.Parameter4;

    __try {
        CONTEXT Context;

        RtlCaptureContext(&Context);
        BugCheckStackDump(&Context);
        kAFL_Hypercall(HYPERCALL_KAFL_PANIC, 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Error of some kind
    }


}
