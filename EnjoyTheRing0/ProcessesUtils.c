#include "ProcessesUtils.h"


typedef NTSTATUS NTKERNELAPI (NTAPI *_PsGetContextThread)(IN PETHREAD Thread, IN OUT PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode);
typedef NTSTATUS NTKERNELAPI (NTAPI *_PsSetContextThread)(IN PETHREAD Thread, IN PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode);

typedef NTSTATUS NTKERNELAPI (NTAPI *_PsSuspendProcess)(IN PEPROCESS Process);
typedef NTSTATUS NTKERNELAPI (NTAPI *_PsResumeProcess)(IN PEPROCESS Process);

typedef NTSTATUS NTKERNELAPI (NTAPI *_ObRegisterCallbacks)(IN POB_CALLBACK_REGISTRATION CallBackRegistration, OUT PVOID *RegistrationHandle);
typedef VOID	 NTKERNELAPI (NTAPI *_ObUnRegisterCallbacks)(IN PVOID RegistrationHandle);

typedef NTSTATUS NTKERNELAPI (NTAPI *_ZwQueryInformationProcess)(
	HANDLE hProcess,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS NTKERNELAPI (NTAPI *_ZwSetInformationProcess)(
	HANDLE hProcess, 
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
);



PVOID GetKernelProcAddress(LPWSTR ProcedureName) {
	UNICODE_STRING SystemRoutineName;
	RtlInitUnicodeString(&SystemRoutineName, ProcedureName);
	return MmGetSystemRoutineAddress(&SystemRoutineName);
}



PEPROCESS GetPEPROCESS(HANDLE ProcessId) {
	PEPROCESS Process;
	return NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)) ? Process : NULL;
}

PETHREAD GetPETHREAD(HANDLE ThreadId) {
	PETHREAD Thread;
	return NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &Thread)) ? Thread : NULL;
}



BOOL AttachToProcess(HANDLE ProcessId, OUT PKAPC_STATE ApcState) {
	if (ApcState == NULL) return FALSE;
	PEPROCESS Process;
	if NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)) {
		KeStackAttachProcess(Process, ApcState);
		ObDereferenceObject(Process);
		return TRUE;
	}
	return FALSE;
}

BOOL DetachFromProcess(IN PKAPC_STATE ApcState) {
	if (ApcState == NULL) return FALSE;
	KeUnstackDetachProcess(ApcState);
	return TRUE;
}



NTSTATUS OpenProcess(HANDLE ProcessId, OUT PHANDLE hProcess) {
	if (ProcessId == PsGetCurrentProcessId()) {
		*hProcess = ZwCurrentProcess();
		return STATUS_SUCCESS;
	}

	CLIENT_ID ClientId;
	ClientId.UniqueProcess = ProcessId;
	ClientId.UniqueThread  = 0;

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	return ZwOpenProcess(hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &ClientId);
}

NTSTATUS TerminateProcess(HANDLE hProcess, NTSTATUS ExitStatus) {
	return ZwTerminateProcess(hProcess, ExitStatus);
}

NTSTATUS KillProcess(HANDLE ProcessId) {
	HANDLE hProcess = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	Status = OpenProcess(ProcessId, &hProcess);
	if NT_SUCCESS(Status) {
		Status = TerminateProcess(hProcess, STATUS_SUCCESS);
		CloseProcess(hProcess);
	}
	return Status;
}

NTSTATUS CreateSystemThread(OUT PHANDLE hThread, PKSTART_ROUTINE ThreadProc, PVOID Arguments) {
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	return PsCreateSystemThread(hThread, GENERIC_ALL, &ObjectAttributes, NULL, NULL, ThreadProc, Arguments);
}

NTSTATUS ExitSystemThread(NTSTATUS ExitStatus) {
	return PsTerminateSystemThread(ExitStatus);
}



NTSTATUS VirtualAlloc(HANDLE hProcess, SIZE_T Size, IN OUT PVOID *VirtualAddress) {
	return ZwAllocateVirtualMemory(hProcess, VirtualAddress, 0, &Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
};

NTSTATUS VirtualFree(HANDLE hProcess, PVOID VirtualAddress) {
	SIZE_T RegionSize = 0;
	return ZwFreeVirtualMemory(hProcess, &VirtualAddress, &RegionSize, MEM_RELEASE);
}



NTSTATUS VirtualAllocInProcess(HANDLE ProcessId, SIZE_T Size, IN OUT PVOID *VirtualAddress) {
	HANDLE hProcess;
	NTSTATUS Status = OpenProcess(ProcessId, &hProcess);
	return NT_SUCCESS(Status) ? VirtualAlloc(hProcess, Size, VirtualAddress) : Status;
}

NTSTATUS VirtualFreeInProcess(HANDLE ProcessId, PVOID VirtualAddress) {
	HANDLE hProcess;
	NTSTATUS Status = OpenProcess(ProcessId, &hProcess);
	return NT_SUCCESS(Status) ? VirtualFree(hProcess, VirtualAddress) : Status;
}



PHYSICAL_ADDRESS GetPhysicalAddressInProcess(HANDLE ProcessId, PVOID BaseVirtualAddress) {
	KAPC_STATE ApcState;
	PHYSICAL_ADDRESS PhysicalAddress;
	if (AttachToProcess(ProcessId, &ApcState)) {
		PhysicalAddress = GetPhysicalAddress(BaseVirtualAddress);
		DetachFromProcess(&ApcState);
	} else {
		PhysicalAddress.QuadPart = 0;
	}

	return PhysicalAddress;
}



PVOID MapVirtualMemory(
	HANDLE ProcessId, 
	PVOID VirtualAddress,
	OPTIONAL PVOID MapToVirtualAddress,
	ULONG Size, 
	KPROCESSOR_MODE ProcessorMode, 
	OUT PMDL* pMdl
) {

#define UnlockFreeAndNilMdl(Mdl) MmUnlockPages((Mdl)); IoFreeMdl((Mdl)); (Mdl) = NULL;

	if (pMdl == NULL) return NULL;

	PVOID MappedAddress = NULL;
	PMDL Mdl = NULL;
	Mdl = IoAllocateMdl(VirtualAddress, Size, FALSE, FALSE, NULL);
	if (Mdl) {
		PEPROCESS Process;
		if NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)) {
			__try {
				MmProbeAndLockProcessPages(Mdl, Process, KernelMode, IoReadAccess);
				
				__try {
					MappedAddress = MmMapLockedPagesSpecifyCache(Mdl, ProcessorMode, MmNonCached, MapToVirtualAddress, FALSE, NormalPagePriority);
				} __except (EXCEPTION_EXECUTE_HANDLER) {
					UnlockFreeAndNilMdl(Mdl);
				}

				// Если исключение не было сгенерировано, но адрес мы не получили:
				if ((MappedAddress == NULL) && (Mdl != NULL)) {
					UnlockFreeAndNilMdl(Mdl);
				}

			} __except (EXCEPTION_EXECUTE_HANDLER) {
				IoFreeMdl(Mdl);
			}

			ObDereferenceObject(Process);
		}
	}

	*pMdl = Mdl;
	return MappedAddress;

#undef UnlockFreeAndNilMdl

}

VOID UnmapVirtualMemory(PMDL Mdl, PVOID MappedMemory) {
	if ((Mdl == NULL) || (MappedMemory == NULL)) return;
	MmUnmapLockedPages(MappedMemory, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
}



typedef enum _PROCESS_MEMORY_OPERATION {
	MemoryRead,
	MemoryWrite,
} PROCESS_MEMORY_OPERATION;


typedef struct _MEMORY_OPERATION_INFO {
	HANDLE ProcessId;
	PVOID  VirtualAddress;
	PVOID  Buffer;
	ULONG  BufferSize;
	BOOL   IsUsermodeBuffer;
	MEMORY_ACCESS_TYPE AccessType;
} MEMORY_OPERATION_INFO, *PMEMORY_OPERATION_INFO;

BOOL FASTCALL OperateMemoryThroughMdlAccess(PMEMORY_OPERATION_INFO OperationInfo, PROCESS_MEMORY_OPERATION MemoryOperation) {
	PMDL Mdl;
	PVOID MappedMemory = MapVirtualMemory(OperationInfo->ProcessId, OperationInfo->VirtualAddress, NULL, (ULONG)OperationInfo->BufferSize, KernelMode, &Mdl);
	if (MappedMemory && Mdl) {
		BOOL Status = TRUE;
		__try {
			switch (MemoryOperation) {
				case MemoryRead	: RtlCopyMemory(OperationInfo->Buffer, MappedMemory, OperationInfo->BufferSize); break;
				case MemoryWrite: RtlCopyMemory(MappedMemory, OperationInfo->Buffer, OperationInfo->BufferSize); break;
			}
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			Status = FALSE;
		}
		UnmapVirtualMemory(Mdl, MappedMemory);
		return Status;
	}
	return FALSE;
}

BOOL FASTCALL OperateMemoryThroughCombinedAccess(PMEMORY_OPERATION_INFO OperationInfo, PROCESS_MEMORY_OPERATION MemoryOperation) {
	BOOL Status = FALSE;
	PMDL Mdl;
	PVOID MappedMemory = MapVirtualMemory(OperationInfo->ProcessId, OperationInfo->VirtualAddress, NULL, OperationInfo->BufferSize, KernelMode, &Mdl);
	if (MappedMemory && Mdl) {
		// Получаем физический адрес отображения:
		PHYSICAL_ADDRESS PhysicalAddress = MmGetPhysicalAddress(MappedMemory);
		PVOID PhysicalMappedMemory = MmMapIoSpace(PhysicalAddress, OperationInfo->BufferSize, MmNonCached);
		if (PhysicalMappedMemory) {
			Status = TRUE;
			__try {
				switch (MemoryOperation) {
					case MemoryRead	: RtlCopyMemory(OperationInfo->Buffer, PhysicalMappedMemory, OperationInfo->BufferSize); break;
					case MemoryWrite: RtlCopyMemory(PhysicalMappedMemory, OperationInfo->Buffer, OperationInfo->BufferSize); break;
				}
			} __except (EXCEPTION_EXECUTE_HANDLER) {
				Status = FALSE;
			}
			MmUnmapIoSpace(PhysicalMappedMemory, OperationInfo->BufferSize);
		}
		UnmapVirtualMemory(Mdl, MappedMemory);
	}

	return Status;
}

BOOL FASTCALL OperateMemoryThroughPhysicalAccess(PMEMORY_OPERATION_INFO OperationInfo, PROCESS_MEMORY_OPERATION MemoryOperation) {
	PHYSICAL_ADDRESS PhysicalAddress = GetPhysicalAddressInProcess(OperationInfo->ProcessId, OperationInfo->VirtualAddress);
	if (PhysicalAddress.QuadPart == 0) return FALSE;
	
	PVOID MappedMemory = MmMapIoSpace(PhysicalAddress, OperationInfo->BufferSize, MmNonCached);
	if (MappedMemory == NULL) return FALSE;

	BOOL Status = TRUE;
	__try {
		switch (MemoryOperation) {
		case MemoryRead: RtlCopyMemory(OperationInfo->Buffer, MappedMemory, OperationInfo->BufferSize); break;
		case MemoryWrite: RtlCopyMemory(MappedMemory, OperationInfo->Buffer, OperationInfo->BufferSize); break;
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		Status = FALSE;
	}

	MmUnmapIoSpace(MappedMemory, OperationInfo->BufferSize);

	return Status;
}

BOOL FASTCALL OperateProcessMemory(PMEMORY_OPERATION_INFO OperationInfo, PROCESS_MEMORY_OPERATION MemoryOperation) {
	if (OperationInfo == NULL) return FALSE;
		
	// Если передали юзермодный буфер - проверяем его на чтение\запись:
	if (OperationInfo->IsUsermodeBuffer) {
		if (!MmIsAddressValid(OperationInfo->Buffer)) return FALSE;
		BOOL UsermodeBufferReady = FALSE;
		switch (MemoryOperation) {
			case MemoryRead: 
				UsermodeBufferReady = IsUsermodeMemoryWriteable(OperationInfo->Buffer, OperationInfo->BufferSize, 1);
				break;

			case MemoryWrite:
				UsermodeBufferReady = IsUsermodeMemoryReadable(OperationInfo->Buffer, OperationInfo->BufferSize, 1);
				break;
		}
		if (!UsermodeBufferReady) return FALSE;
	}

	BOOL Status;
	switch (OperationInfo->AccessType) {
		case MdlAccess: 
			Status = OperateMemoryThroughMdlAccess(OperationInfo, MemoryOperation); 
			break;

		case MdlWithPhysicalAccess:
			Status = OperateMemoryThroughCombinedAccess(OperationInfo, MemoryOperation);
			break;

		case DirectPhysicalAccess:
			Status = OperateMemoryThroughPhysicalAccess(OperationInfo, MemoryOperation);
			break;

		default:
			Status = FALSE;
			break;
	}

	return Status;
}

BOOL ReadProcessMemory(HANDLE ProcessId, PVOID VirtualAddress, PVOID Buffer, ULONG BufferSize, BOOL IsUsermodeBuffer, MEMORY_ACCESS_TYPE AccessType) {
	MEMORY_OPERATION_INFO OperationInfo;
	OperationInfo.ProcessId        = ProcessId;
	OperationInfo.VirtualAddress   = VirtualAddress;
	OperationInfo.Buffer           = Buffer;
	OperationInfo.BufferSize       = BufferSize;
	OperationInfo.IsUsermodeBuffer = IsUsermodeBuffer;
	OperationInfo.AccessType       = AccessType;
	return OperateProcessMemory(&OperationInfo, MemoryRead);
}

BOOL WriteProcessMemory(HANDLE ProcessId, PVOID VirtualAddress, PVOID Buffer, ULONG BufferSize, BOOL IsUsermodeBuffer, MEMORY_ACCESS_TYPE AccessType) {
	MEMORY_OPERATION_INFO OperationInfo;
	OperationInfo.ProcessId        = ProcessId;
	OperationInfo.VirtualAddress   = VirtualAddress;
	OperationInfo.Buffer           = Buffer;
	OperationInfo.BufferSize       = BufferSize;
	OperationInfo.IsUsermodeBuffer = IsUsermodeBuffer;
	OperationInfo.AccessType       = AccessType;
	return OperateProcessMemory(&OperationInfo, MemoryWrite);
}

#pragma warning(push)
#pragma warning(disable: 4055)

NTSTATUS GetThreadContext(IN PETHREAD Thread, IN OUT PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode) {
	_PsGetContextThread PsGetContextThread = (_PsGetContextThread)GetKernelProcAddress(L"PsGetContextThread");
	if (PsGetContextThread == NULL) return STATUS_NOT_IMPLEMENTED;
	return PsGetContextThread(Thread, Context, PreviousMode);
}

NTSTATUS SetThreadContext(IN PETHREAD Thread, IN PCONTEXT Context, IN KPROCESSOR_MODE PreviousMode) {
	_PsSetContextThread PsSetContextThread = (_PsSetContextThread)GetKernelProcAddress(L"PsSetContextThread");
	if (PsSetContextThread == NULL) return STATUS_NOT_IMPLEMENTED;
	return PsSetContextThread(Thread, Context, PreviousMode);
}


NTSTATUS SetInformationProcess(
	HANDLE hProcess,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
) {
	_ZwSetInformationProcess ZwSetInformationProcess = (_ZwSetInformationProcess)GetKernelProcAddress(L"ZwSetInformationProcess");
	if (ZwSetInformationProcess == NULL) return STATUS_NOT_IMPLEMENTED;
	return ZwSetInformationProcess(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS QueryInformationProcess(
	HANDLE hProcess,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
) {
	_ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)GetKernelProcAddress(L"ZwQueryInformationProcess");
	if (ZwQueryInformationProcess == NULL) return STATUS_NOT_IMPLEMENTED;
	return ZwQueryInformationProcess(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS SuspendProcess(IN PEPROCESS Process) {
	if (Process == NULL) return STATUS_INVALID_PARAMETER;
	_PsSuspendProcess PsSuspendProcess = (_PsSuspendProcess)GetKernelProcAddress(L"PsSuspendProcess");
	if (PsSuspendProcess == NULL) return STATUS_NOT_IMPLEMENTED;
	return PsSuspendProcess(Process);
}

NTSTATUS ResumeProcess(IN PEPROCESS Process) {
	if (Process == NULL) return STATUS_INVALID_PARAMETER;
	_PsResumeProcess PsResumeProcess = (_PsResumeProcess)GetKernelProcAddress(L"PsResumeProcess");
	if (PsResumeProcess == NULL) return STATUS_NOT_IMPLEMENTED;
	return PsResumeProcess(Process);
}

NTSTATUS RegisterCallbacks(IN POB_CALLBACK_REGISTRATION CallBackRegistration, OUT PVOID *RegistrationHandle) {
	_ObRegisterCallbacks ObRegisterCallbacks = (_ObRegisterCallbacks)GetKernelProcAddress(L"ObRegisterCallbacks");
	if (ObRegisterCallbacks == NULL) return STATUS_NOT_IMPLEMENTED;
	return ObRegisterCallbacks(CallBackRegistration, RegistrationHandle);
}

VOID UnRegisterCallbacks(IN PVOID RegistrationHandle) {
	_ObUnRegisterCallbacks ObUnRegisterCallbacks = (_ObUnRegisterCallbacks)GetKernelProcAddress(L"ObUnRegisterCallbacks");
	if (ObUnRegisterCallbacks == NULL) return;
	ObUnRegisterCallbacks(RegistrationHandle);
}
#pragma warning(pop)

#ifdef _AMD64_
PKTRAP_FRAME GetTrapFrame() {
/* x86:
	TrapFrame = (PKTRAP_FRAME)((PBYTE)Thread->InitialStack - 
				ALIGN_UP(sizeof(KTRAP_FRAME), KTRAP_FRAME_ALIGN) - 
				sizeof(FX_SAVE_AREA));
*/
	return (PKTRAP_FRAME)((PBYTE)IoGetInitialStack() - sizeof(KTRAP_FRAME));
}

VOID RaiseIOPLByTrapFrame() {
	PKTRAP_FRAME TrapFrame = GetTrapFrame();
	TrapFrame->EFlags |= IOPL_ACCESS_MASK;
}

VOID ResetIOPLByTrapFrame() {
	PKTRAP_FRAME TrapFrame = GetTrapFrame();
	TrapFrame->EFlags &= ~IOPL_ACCESS_MASK;
}
#endif


#ifdef _X86_
typedef NTSTATUS NTKERNELAPI (NTAPI *_Ke386QueryIoAccessMap)   (DWORD dwFlag, PVOID pIOPM);
typedef NTSTATUS NTKERNELAPI (NTAPI *_Ke386SetIoAccessMap)     (DWORD dwFlag, PVOID pIOPM);
typedef NTSTATUS NTKERNELAPI (NTAPI *_Ke386IoSetAccessProcess) (PEPROCESS Process, DWORD dwFlag);

// Размер IOPM = 65536 портов / 8 бит:
#define IOPM_SIZE 8192
#define NTVDM_IOPM_OFFSET 0x88

#define QUERY_DISALLOWING_IOPM 0
#define COPY_IOPM 1

#define ENABLE_IOPM 1
#define DISABLE_IOPM 0


NTSTATUS RaiseIOPM(OPTIONAL HANDLE ProcessId) {
	PEPROCESS Process = ProcessId ? GetPEPROCESS(ProcessId) : PsGetCurrentProcess();
	if (Process == NULL) return STATUS_INVALID_PARAMETER;

#pragma warning(push)
#pragma warning(disable: 4055)
	_Ke386SetIoAccessMap Ke386SetAccessMap = (_Ke386SetIoAccessMap)GetKernelProcAddress(L"Ke386SetIoAccessMap");
	_Ke386IoSetAccessProcess Ke386IoSetAccessProcess = (_Ke386IoSetAccessProcess)GetKernelProcAddress(L"Ke386IoSetAccessProcess");
#pragma warning(pop)

	if (Ke386SetAccessMap && Ke386IoSetAccessProcess) {
		PVOID IOPM = GetMem(IOPM_SIZE);
		
		NTSTATUS Status;
		Status = Ke386SetAccessMap(COPY_IOPM, IOPM);
		if NT_SUCCESS(Status) Status = Ke386IoSetAccessProcess(Process, ENABLE_IOPM);
		
		FreeMem(IOPM);
		if (ProcessId) ObDereferenceObject(Process);

		return Status;
	} 

	if (ProcessId) ObDereferenceObject(Process);
	return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ResetIOPM(OPTIONAL HANDLE ProcessId) {
	PEPROCESS Process = ProcessId ? GetPEPROCESS(ProcessId) : PsGetCurrentProcess();
	if (Process == NULL) return STATUS_INVALID_PARAMETER;

#pragma warning(push)
#pragma warning(disable: 4055)
	_Ke386QueryIoAccessMap Ke386QueryAccessMap = (_Ke386QueryIoAccessMap)GetKernelProcAddress(L"Ke386QueryIoAccessMap");
	_Ke386SetIoAccessMap Ke386SetAccessMap = (_Ke386SetIoAccessMap)GetKernelProcAddress(L"Ke386SetIoAccessMap");
	_Ke386IoSetAccessProcess Ke386IoSetAccessProcess = (_Ke386IoSetAccessProcess)GetKernelProcAddress(L"Ke386IoSetAccessProcess");
#pragma warning(pop)

	if (Ke386QueryAccessMap && Ke386SetAccessMap && Ke386IoSetAccessProcess) {
		PVOID IOPM = GetMem(IOPM_SIZE);
		RtlFillMemory(IOPM, IOPM_SIZE, 0xFF);

		NTSTATUS Status;
		Status = Ke386QueryAccessMap(QUERY_DISALLOWING_IOPM, IOPM);
		if NT_SUCCESS(Status) {
			Status = Ke386SetAccessMap(COPY_IOPM, IOPM);
			if NT_SUCCESS(Status) Status = Ke386IoSetAccessProcess(Process, DISABLE_IOPM);
		}
		
		FreeMem(IOPM);
		if (ProcessId) ObDereferenceObject(Process);

		return Status;
	}

	if (ProcessId) ObDereferenceObject(Process);
	return STATUS_NOT_IMPLEMENTED;
}
#endif

PULONG ScanEFlags() {
	// Выделяем юзермодную память для контекста:
	PCONTEXT Context = NULL;
	VirtualAlloc(ZwCurrentProcess(), sizeof(CONTEXT), &Context);

	// Получаем контекст:
	RtlZeroMemory(Context, sizeof(CONTEXT));
	Context->ContextFlags = CONTEXT_CONTROL;
	
	PETHREAD CurrentThread = PsGetCurrentThread();

	// Получаем оригинальное значение EFlags:
	NTSTATUS Status = GetThreadContext(CurrentThread, Context, UserMode);
	ULONG EFlagsValue = Context->EFlags;
	ULONG MaskedEFlags = MaskEFlagsReservedBits(EFlagsValue);

	PULONG EFlagsPtr = NULL;

	if NT_SUCCESS(Status) {
		// Получаем пределы стека:
		PULONG LowLimit, HighLimit;
		IoGetStackLimits((PULONG_PTR)&LowLimit, (PULONG_PTR)&HighLimit);

		// Проходимся по стеку и ищем нужное значение:
#pragma warning(suppress: 4213)
		for (EFlagsPtr = (PULONG)((PBYTE)IoGetInitialStack() - sizeof(EFlagsValue)); EFlagsPtr >= LowLimit; ((PBYTE)EFlagsPtr)--) {
			if (MaskEFlagsReservedBits(*EFlagsPtr) == MaskedEFlags) {
				// Меняем CF в EFlags:
				Context->EFlags = (Context->EFlags & 1) == 1 ? Context->EFlags ^ 1 : Context->EFlags | 1;
				SetThreadContext(CurrentThread, Context, UserMode);

				// Если найденное значение поменялось - значит нашли верно:
				if (MaskEFlagsReservedBits(*EFlagsPtr) == MaskEFlagsReservedBits(Context->EFlags)) break;

				// Восстанавливаем оригинальный EFlags:
				Context->EFlags = EFlagsValue;
				SetThreadContext(CurrentThread, Context, UserMode);
			}
		}
	}

	// Восстанавливаем оригинальный EFlags:
	Context->EFlags = EFlagsValue;
	SetThreadContext(CurrentThread, Context, UserMode);

	// Освобождаем контекст:
	VirtualFree(ZwCurrentProcess(), Context);

	return EFlagsPtr;
}

VOID RaiseIOPLByTrapFrameScan() {
	PULONG EFlags = ScanEFlags();
	if (EFlags) {
		*EFlags |= IOPL_ACCESS_MASK;
	}
}

VOID ResetIOPLByTrapFrameScan() {
	PULONG EFlags = ScanEFlags();
	if (EFlags) {
		*EFlags &= ~IOPL_ACCESS_MASK;
	}
}

#ifdef _X86_
VOID RaiseIOPLByTSS() {
	PTSS TSS = GetTSSPointer(NULL);
	*(PULONG)(TSS->ESP0 - ESP0_EFLAGS_OFFSET) |= IOPL_ACCESS_MASK;
}

VOID ResetIOPLByTSS() {
	PTSS TSS = GetTSSPointer(NULL);
	*(PULONG)(TSS->ESP0 - ESP0_EFLAGS_OFFSET) &= ~IOPL_ACCESS_MASK;
}
#endif




NTSTATUS RegisterHandlesOperationsNotifier(IN PHANDLES_NOTIFY_STRUCT HandlesNotifyStruct, OUT PVOID *RegistrationHandle) {
	// Определяем тип операции и задаём сами каллбэки:
	OB_OPERATION_REGISTRATION OperationRegistration;
	OperationRegistration.ObjectType = HandlesNotifyStruct->ObjectType; // PsProcessType / PsThreadType / ExDesktopObjectType
	OperationRegistration.Operations = HandlesNotifyStruct->Operations; // OB_OPERATION_HANDLE_CREATE || OB_OPERATION_HANDLE_DUPLICATE 
	OperationRegistration.PostOperation = HandlesNotifyStruct->PostOperation;
	OperationRegistration.PreOperation  = HandlesNotifyStruct->PreOperation;

	// Определяем "высоту" фильтра в стеке фильтров:
	UNICODE_STRING Altitude;
	RtlInitUnicodeString(&Altitude, L"389020"); // It's a magic!

	// Заполняем структуру регистрации каллбэка:
	OB_CALLBACK_REGISTRATION CallbackRegistration;
	CallbackRegistration.Altitude                   = Altitude;
	CallbackRegistration.OperationRegistration      = &OperationRegistration;
	CallbackRegistration.OperationRegistrationCount = 1;
	CallbackRegistration.RegistrationContext        = HandlesNotifyStruct->RegistrationContext; // Параметр, который будет передан в каллбэк
	CallbackRegistration.Version                    = OB_FLT_REGISTRATION_VERSION;

	// Регистрируем каллбэк:
	return RegisterCallbacks(&CallbackRegistration, RegistrationHandle);
}

VOID UnregisterHandlesOperationsNotifier(PVOID RegistrationHandle) {
	UnRegisterCallbacks(RegistrationHandle);
}