#include "IOCTLDispatcher.h"

VOID OnDriverLoad() {
#ifdef PROTECTION_SUPPORT
	RegisterProtection();
#endif
}

VOID OnHandleCreate() {
	if (HandlesCount < 0x7FFFFFFF) InterlockedIncrement(&HandlesCount);
}

VOID OnHandleClose() {
	if (HandlesCount > 0) InterlockedDecrement(&HandlesCount);
#ifdef PROTECTION_SUPPORT
	RemoveProtectedProcess(ANY_PROCESS, GetCurrentProcessId());
#endif
}

VOID OnDriverUnload() {
#ifdef PROTECTION_SUPPORT
	ClearProtectedProcessesList();
	UnregisterProtection();
#endif
}

NTSTATUS FASTCALL DispatchIOCTL(IN PIOCTL_INFO RequestInfo, OUT PULONG ResponseLength) 
{
	NTSTATUS Status = STATUS_SUCCESS;

#define INPUT(Type)  ((Type)(RequestInfo->InputBuffer)) 
#define OUTPUT(Type) ((Type)(RequestInfo->OutputBuffer))
#define SET_RESPONSE_LENGTH(Length) if (ResponseLength) {*ResponseLength = (Length);}

#ifdef _X86_
#pragma warning(push)
#pragma warning(disable: 4305)
#endif

	switch (RequestInfo->ControlCode) {
	
// DriverFunctions:

	case GET_HANDLES_COUNT:
		*OUTPUT(PULONG) = HandlesCount;
		SET_RESPONSE_LENGTH(sizeof(ULONG));
		break;

// NativeFunctions:

	case START_BEEPER:
		__outbyte(0x61, __inbyte(0x61) | 3); 
		break;
	
	case STOP_BEEPER: 
		__outbyte(0x61, __inbyte(0x61) & 252);
		break;
	
	case SET_BEEPER_REGIME: 
		__outbyte(0x43, 0xB6);
		break;
	
	case SET_BEEPER_OUT: 
		__outbyte(0x61, __inbyte(0x61) | 2);
		break;
	
	case SET_BEEPER_IN: 
		__outbyte(0x61, __inbyte(0x61) & 253);
		break;

	case SET_BEEPER_DIVIDER:
		SetBeeperDivider(*INPUT(PWORD));
		break;

	case SET_BEEPER_FREQUENCY:
		SetBeeperFrequency(*INPUT(PWORD));
		break;

	case READ_IO_PORT_BYTE:
		*OUTPUT(PBYTE) = __inbyte(*INPUT(PWORD));
		SET_RESPONSE_LENGTH(sizeof(BYTE));
		break;

	case READ_IO_PORT_WORD:
		*OUTPUT(PWORD) = __inword(*INPUT(PWORD));
		SET_RESPONSE_LENGTH(sizeof(WORD));
		break;

	case READ_IO_PORT_DWORD:
		*OUTPUT(PDWORD32) = __indword(*INPUT(PWORD));
		SET_RESPONSE_LENGTH(sizeof(DWORD));
		break;

	case WRITE_IO_PORT_BYTE:
		__outbyte(
			INPUT(PWRITE_IO_PORT_BYTE_INPUT)->PortNumber,
			INPUT(PWRITE_IO_PORT_BYTE_INPUT)->Data
		);
		break;

	case WRITE_IO_PORT_WORD:
		__outword(
			INPUT(PWRITE_IO_PORT_WORD_INPUT)->PortNumber,
			INPUT(PWRITE_IO_PORT_WORD_INPUT)->Data
		);
		break;

	case WRITE_IO_PORT_DWORD:
		__outdword(
			INPUT(PWRITE_IO_PORT_DWORD_INPUT)->PortNumber,
			INPUT(PWRITE_IO_PORT_DWORD_INPUT)->Data
		);
		break;

	case RDPMC:
		*OUTPUT(PULONGLONG) = __readpmc(*INPUT(PULONG));
		SET_RESPONSE_LENGTH(sizeof(ULONGLONG));
		break;

	case RDMSR:
		*OUTPUT(PULONGLONG) = __readmsr(*INPUT(PULONG));
		SET_RESPONSE_LENGTH(sizeof(ULONGLONG));
		break;

	case WRMSR:
		__writemsr(INPUT(PWRMSR_INPUT)->Index, INPUT(PWRMSR_INPUT)->Data);
		break;

	case HALT:
		__halt();
		break;

// MemoryUtils:

	case ALLOC_KERNEL_MEMORY:
		*OUTPUT(PUINT64) = (SIZE_T)GetMem(*INPUT(PSIZE_T));
		SET_RESPONSE_LENGTH(sizeof(UINT64));
		break;

	case FREE_KERNEL_MEMORY:
		FreeMem((PVOID)*INPUT(PUINT64));
		break;

	case MOVE_MEMORY:
		RtlMoveMemory(
			(PVOID)INPUT(PMOVE_MEMORY_INPUT)->Destination,
			(PVOID)INPUT(PMOVE_MEMORY_INPUT)->Source,
			(SIZE_T)INPUT(PMOVE_MEMORY_INPUT)->Size
		);
		break;

	case COPY_MEMORY:
		RtlCopyMemory(
			(PVOID)INPUT(PCOPY_MEMORY_INPUT)->Destination,
			(PVOID)INPUT(PCOPY_MEMORY_INPUT)->Source,
			(SIZE_T)INPUT(PCOPY_MEMORY_INPUT)->Size
		);
		break;

	case ZERO_MEMORY:
		RtlZeroMemory(
			(PVOID)INPUT(PZERO_MEMORY_INPUT)->Destination,
			(SIZE_T)INPUT(PZERO_MEMORY_INPUT)->Size
		);
		break;

	case FILL_MEMORY:
		RtlFillMemory(
			(PVOID)INPUT(PFILL_MEMORY_INPUT)->Destination,
			(SIZE_T)INPUT(PFILL_MEMORY_INPUT)->Size,
			(BYTE)INPUT(PFILL_MEMORY_INPUT)->FillingByte
		);
		break;

	case EQUAL_MEMORY:
		*OUTPUT(PBOOL) = RtlEqualMemory(
			(PVOID)INPUT(PEQUAL_MEMORY_INPUT)->Destination,
			(PVOID)INPUT(PEQUAL_MEMORY_INPUT)->Source,
			(SIZE_T)INPUT(PEQUAL_MEMORY_INPUT)->Size
		);
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case ALLOC_PHYSICAL_MEMORY:
		*OUTPUT(PUINT64) = (SIZE_T)AllocPhysicalMemory(
			INPUT(PALLOC_PHYSICAL_MEMORY_INPUT)->PhysicalAddress,
			(SIZE_T)INPUT(PALLOC_PHYSICAL_MEMORY_INPUT)->Size
		);
		SET_RESPONSE_LENGTH(sizeof(UINT64));
		break;

	case FREE_PHYSICAL_MEMORY:
		FreePhysicalMemory((PVOID)*INPUT(PUINT64));
		break;

	case GET_PHYSICAL_ADDRESS:
		*OUTPUT(PPHYSICAL_ADDRESS) = GetPhysicalAddressInProcess(
			(HANDLE)INPUT(PGET_PHYSICAL_ADDRESS_INPUT)->ProcessID,
			(PVOID)INPUT(PGET_PHYSICAL_ADDRESS_INPUT)->VirtualAddress
		);
		SET_RESPONSE_LENGTH(sizeof(PHYSICAL_ADDRESS));
		break;

	case READ_PHYSICAL_MEMORY:
		*OUTPUT(PBOOL) = ReadPhysicalMemory(
			INPUT(PREAD_PHYSICAL_MEMORY_INPUT)->PhysicalAddress,
			(PVOID)INPUT(PREAD_PHYSICAL_MEMORY_INPUT)->Buffer,
			INPUT(PREAD_PHYSICAL_MEMORY_INPUT)->BufferSize
		);
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case WRITE_PHYSICAL_MEMORY:
		*OUTPUT(PBOOL) = WritePhysicalMemory(
			INPUT(PWRITE_PHYSICAL_MEMORY_INPUT)->PhysicalAddress,
			(PVOID)INPUT(PWRITE_PHYSICAL_MEMORY_INPUT)->Buffer,
			INPUT(PWRITE_PHYSICAL_MEMORY_INPUT)->BufferSize
		);
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case READ_DMI_MEMORY:
		if (IsUsermodeMemoryWriteable((PVOID)*INPUT(PUINT64), DMI_SIZE, NON_ALIGNED)) {
			if (ReadDmiMemory((PVOID)*INPUT(PUINT64), DMI_SIZE)) {
				SET_RESPONSE_LENGTH(DMI_SIZE);
			} else {
				Status = STATUS_UNSUCCESSFUL;
			}
		} else {
			Status = STATUS_INFO_LENGTH_MISMATCH;
		}
		*OUTPUT(PNTSTATUS) = Status;
		break;

// ShellCode:

	case EXECUTE_SHELL_CODE:
		*OUTPUT(PSHELL_STATUS) = ExecuteShell(
			(PVOID)INPUT(PEXECUTE_SHELL_CODE_INPUT)->EntryPoint,
			(PVOID)INPUT(PEXECUTE_SHELL_CODE_INPUT)->CodeBlock,
			(PVOID)INPUT(PEXECUTE_SHELL_CODE_INPUT)->InputData,
			(PVOID)INPUT(PEXECUTE_SHELL_CODE_INPUT)->OutputData,
			(PVOID)INPUT(PEXECUTE_SHELL_CODE_INPUT)->Result
		);
		SET_RESPONSE_LENGTH(sizeof(SHELL_STATUS));
		break;

// ProcessesUtils:

	case ALLOC_VIRTUAL_MEMORY:
		OUTPUT(PALLOC_VIRTUAL_MEMORY_OUTPUT)->Status = VirtualAllocInProcess(
			(HANDLE)INPUT(PALLOC_VIRTUAL_MEMORY_INPUT)->ProcessId,
			(SIZE_T)INPUT(PALLOC_VIRTUAL_MEMORY_INPUT)->Size,
			(PVOID*)&OUTPUT(PALLOC_VIRTUAL_MEMORY_OUTPUT)->VirtualAddress
		);
		SET_RESPONSE_LENGTH(sizeof(ALLOC_VIRTUAL_MEMORY_OUTPUT));
		break;

	case FREE_VIRTUAL_MEMORY:
		*OUTPUT(PNTSTATUS) = VirtualFreeInProcess(
			(HANDLE)INPUT(PFREE_VIRTUAL_MEMORY_INPUT)->ProcessId,
			(PVOID)INPUT(PFREE_VIRTUAL_MEMORY_INPUT)->VirtualAddress
		);
		SET_RESPONSE_LENGTH(sizeof(NTSTATUS));
		break;

	case MAP_VIRTUAL_MEMORY:
		OUTPUT(PMAP_VIRTUAL_MEMORY_OUTPUT)->MappedMemory = MapVirtualMemory(
			(HANDLE)INPUT(PMAP_VIRTUAL_MEMORY_INPUT)->ProcessId,
			INPUT(PMAP_VIRTUAL_MEMORY_INPUT)->VirtualAddress,
			INPUT(PMAP_VIRTUAL_MEMORY_INPUT)->MapToVirtualAddress,
			INPUT(PMAP_VIRTUAL_MEMORY_INPUT)->Size,
			UserMode,
			(PMDL*)&(OUTPUT(PMAP_VIRTUAL_MEMORY_OUTPUT)->Mdl)
		);
		SET_RESPONSE_LENGTH(sizeof(MAP_VIRTUAL_MEMORY_OUTPUT));
		break;

	case UNMAP_VIRTUAL_MEMORY:
		UnmapVirtualMemory(
			INPUT(PUNMAP_VIRTUAL_MEMORY_INPUT)->Mdl,
			INPUT(PUNMAP_VIRTUAL_MEMORY_INPUT)->MappedMemory
		);
		break;

	case READ_PROCESS_MEMORY:
		*OUTPUT(PBOOL) = ReadProcessMemory(
			(HANDLE)INPUT(PREAD_PROCESS_MEMORY_INPUT)->ProcessId,
			(PVOID)INPUT(PREAD_PROCESS_MEMORY_INPUT)->VirtualAddress,
			(PVOID)INPUT(PREAD_PROCESS_MEMORY_INPUT)->Buffer,
			INPUT(PREAD_PROCESS_MEMORY_INPUT)->BytesToRead,
			TRUE,
			(MEMORY_ACCESS_TYPE)INPUT(PREAD_PROCESS_MEMORY_INPUT)->AccessType
		);
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case WRITE_PROCESS_MEMORY:
		*OUTPUT(PBOOL) = WriteProcessMemory(
			(HANDLE)INPUT(PWRITE_PROCESS_MEMORY_INPUT)->ProcessId,
			(PVOID)INPUT(PWRITE_PROCESS_MEMORY_INPUT)->VirtualAddress,
			(PVOID)INPUT(PWRITE_PROCESS_MEMORY_INPUT)->Buffer,
			INPUT(PWRITE_PROCESS_MEMORY_INPUT)->BytesToWrite,
			TRUE,
			(MEMORY_ACCESS_TYPE)INPUT(PWRITE_PROCESS_MEMORY_INPUT)->AccessType
		);
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case RAISE_IOPL_BY_TF:
#ifdef _AMD64_
		RaiseIOPLByTrapFrame();
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case RESET_IOPL_BY_TF:
#ifdef _AMD64_
		ResetIOPLByTrapFrame();
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case RAISE_IOPL_BY_TF_SCAN:
		RaiseIOPLByTrapFrameScan();
		break;

	case RESET_IOPL_BY_TF_SCAN:
		ResetIOPLByTrapFrameScan();
		break;

	case RAISE_IOPL_BY_TSS:
#ifdef _X86_
		RaiseIOPLByTSS();
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case RESET_IOPL_BY_TSS:
#ifdef _x86_
		ResetIOPLByTSS();
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case RAISE_IOPM:
#ifdef _X86_
		*OUTPUT(PNTSTATUS) = RaiseIOPM((HANDLE)*INPUT(PUINT64));
		SET_RESPONSE_LENGTH(sizeof(NTSTATUS));
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case RESET_IOPM:
#ifdef _X86_
		*OUTPUT(PNTSTATUS) = ResetIOPM((HANDLE)*INPUT(PUINT64));
		SET_RESPONSE_LENGTH(sizeof(NTSTATUS));
#else
		Status = STATUS_NOT_IMPLEMENTED;
#endif
		break;

	case KILL_PROCESS:
		KillProcess((HANDLE)*INPUT(PUINT64));
		break;

// Protection:

	case ADD_PROTECTED_PROCESS:
		AddProtectedProcess(
			(HANDLE)INPUT(PADD_REMOVE_PROCESS_INPUT)->ProcessId,
			(HANDLE)INPUT(PADD_REMOVE_PROCESS_INPUT)->DefenderId
		);
		break;

	case REMOVE_PROTECTED_PROCESS:
		RemoveProtectedProcess(
			(HANDLE)INPUT(PADD_REMOVE_PROCESS_INPUT)->ProcessId,
			(HANDLE)INPUT(PADD_REMOVE_PROCESS_INPUT)->DefenderId
		);
		break;

	case IS_PROCESS_PROTECTED:
		*OUTPUT(PBOOL) = IsProcessProtected((HANDLE)*INPUT(PUINT64), ANY_PROCESS) == PROCESS_PROTECTED;
		SET_RESPONSE_LENGTH(sizeof(BOOL));
		break;

	case PRINT_PROTECTED_PROCESSES:
		PrintProtectedProcessesList();
		break;

// PCI:

	case READ_PCI_CONFIG:
		OUTPUT(PREAD_PCI_CONFIG_OUTPUT)->Status = ReadPciConfig(
			INPUT(PREAD_PCI_CONFIG_INPUT)->PciAddress,
			INPUT(PREAD_PCI_CONFIG_INPUT)->PciOffset,
			(PVOID)INPUT(PREAD_PCI_CONFIG_INPUT)->Buffer,
			INPUT(PREAD_PCI_CONFIG_INPUT)->BufferSize,
			&OUTPUT(PREAD_PCI_CONFIG_OUTPUT)->BytesRead
		);
		SET_RESPONSE_LENGTH(sizeof(READ_PCI_CONFIG_OUTPUT));
		break;

	case WRITE_PCI_CONFIG:
		OUTPUT(PWRITE_PCI_CONFIG_OUTPUT)->Status = WritePciConfig(
			INPUT(PWRITE_PCI_CONFIG_INPUT)->PciAddress,
			INPUT(PWRITE_PCI_CONFIG_INPUT)->PciOffset,
			(PVOID)INPUT(PWRITE_PCI_CONFIG_INPUT)->Buffer,
			INPUT(PWRITE_PCI_CONFIG_INPUT)->BufferSize,
			&OUTPUT(PWRITE_PCI_CONFIG_OUTPUT)->BytesWritten
		);
		SET_RESPONSE_LENGTH(sizeof(WRITE_PCI_CONFIG_OUTPUT));
		break;

// Other:

	case STALL_EXECUTION_PROCESSOR:
		KeStallExecutionProcessor(*INPUT(PULONG));
		break;

	case BUG_CHECK:
		KeBugCheck(*INPUT(PULONG));
		break;

	case BUG_CHECK_EX:
		KeBugCheckEx(
			INPUT(PBUG_CHECK_EX_INPUT)->BugCheckCode,
			INPUT(PBUG_CHECK_EX_INPUT)->BugCheckParameter1,
			INPUT(PBUG_CHECK_EX_INPUT)->BugCheckParameter2,
			INPUT(PBUG_CHECK_EX_INPUT)->BugCheckParameter3,
			INPUT(PBUG_CHECK_EX_INPUT)->BugCheckParameter4
		);
		break;

	default: 
		Status = STATUS_NOT_IMPLEMENTED;
		break;
	}

	return Status;

#ifdef _X86_
#pragma warning(pop)
#endif

#undef INPUT
#undef OUTPUT

#undef SET_RESPONSE_LENGTH

}