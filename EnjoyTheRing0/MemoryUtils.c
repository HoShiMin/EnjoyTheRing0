#include "MemoryUtils.h"

static const unsigned long MemoryTag = 'KBLI';

PVOID GetMem(SIZE_T Bytes) {
	if (Bytes == 0) return NULL;
	PVOID Memory = ExAllocatePoolWithTag(NonPagedPool, Bytes, MemoryTag);
	if (Memory) RtlSecureZeroMemory(Memory, Bytes);
	return Memory;
}

VOID FreeMem(PVOID Pointer) {
	if (Pointer) ExFreePoolWithTag(Pointer, MemoryTag);
}



PVOID AllocPhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes) {
	PhysicalAddress.QuadPart += (NumberOfBytes - 1);
	return MmAllocateContiguousMemory(NumberOfBytes, PhysicalAddress);
}

PVOID AllocCacheablePhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CachingType) {
	PHYSICAL_ADDRESS HighestAddress;
	PHYSICAL_ADDRESS BoundaryAddressMultiple;
	HighestAddress.QuadPart = PhysicalAddress.QuadPart + (NumberOfBytes - 1);
	BoundaryAddressMultiple.QuadPart = 0;
	return MmAllocateContiguousMemorySpecifyCache(NumberOfBytes, PhysicalAddress, HighestAddress, BoundaryAddressMultiple, CachingType);
}

VOID FreePhysicalMemory(PVOID BaseAddress) {
	MmFreeContiguousMemory(BaseAddress);
}

PHYSICAL_ADDRESS GetPhysicalAddress(PVOID BaseVirtualAddress) {
	if (!MmIsAddressValid(BaseVirtualAddress)) {
		PHYSICAL_ADDRESS PhysicalAddress;
		PhysicalAddress.QuadPart = 0;
		return PhysicalAddress;
	}
	return MmGetPhysicalAddress(BaseVirtualAddress);
}

PVOID MapPhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CachingType) {
	return MmMapIoSpace(PhysicalAddress, NumberOfBytes, CachingType);
}

#ifdef ENABLE_WIN10_EXTENSIONS
PVOID MapPhysicalMemoryWithProtect(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect) {
	return MmMapIoSpaceEx(PhysicalAddress, NumberOfBytes, Protect);
}
#endif

BOOL ReadPhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, PVOID Buffer, SIZE_T BufferSize) {
	PVOID VirtualAddress = MmMapIoSpace(PhysicalAddress, BufferSize, MmNonCached);
	if (VirtualAddress == NULL) return FALSE;

	RtlCopyMemory(Buffer, VirtualAddress, BufferSize);
	
	MmUnmapIoSpace(VirtualAddress, BufferSize);
	return TRUE;
}

BOOL WritePhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, PVOID Buffer, SIZE_T BufferSize) {
	PVOID VirtualAddress = MmMapIoSpace(PhysicalAddress, BufferSize, MmNonCached);
	if (VirtualAddress == NULL) return FALSE;

	RtlCopyMemory(VirtualAddress, Buffer, BufferSize);
	
	MmUnmapIoSpace(VirtualAddress, BufferSize);
	return TRUE;
}

VOID UnmapPhysicalMemory(PVOID BaseVirtualAddress, SIZE_T NumberOfBytes) {
	MmUnmapIoSpace(BaseVirtualAddress, NumberOfBytes);
}

BOOL ReadDmiMemory(PVOID Buffer, SIZE_T BufferSize) {
	if (BufferSize < DMI_SIZE) return FALSE;

	PHYSICAL_ADDRESS DmiAddress;
	DmiAddress.QuadPart = 0xF0000;
	PVOID DmiMemory = MmMapIoSpace(DmiAddress, DMI_SIZE, MmNonCached);
	BOOL Status = DmiMemory != NULL;
	if (Status) {
		RtlCopyMemory(Buffer, DmiMemory, DMI_SIZE);
		MmUnmapIoSpace(DmiMemory, DMI_SIZE);
	}
	return Status;
}

BOOL SecureVirtualMemory(PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG ProbeMode, OUT PHANDLE SecureHandle) {
	if (SecureHandle == NULL) return FALSE;
	*SecureHandle = MmSecureVirtualMemory(VirtualAddress, NumberOfBytes, ProbeMode);
	return SecureHandle != NULL;
}

BOOL UnsecureVirtualMemory(HANDLE SecureHandle) {
	if (SecureHandle) MmUnsecureVirtualMemory(SecureHandle);
	return SecureHandle != NULL;
}

BOOL IsAddressValid(PVOID VirtualAddress) {
	return (BOOL)MmIsAddressValid(VirtualAddress);
} 

BOOL IsUsermodeMemoryReadable(PVOID Address, SIZE_T NumberOfBytes, ULONG RequiredAlignment) {
	__try {
		ProbeForRead(Address, NumberOfBytes, RequiredAlignment);
		return TRUE;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

BOOL IsUsermodeMemoryWriteable(PVOID Address, SIZE_T NumberOfBytes, ULONG RequiredAlignment) {
	__try {
		ProbeForWrite(Address, NumberOfBytes, RequiredAlignment);
		return TRUE;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

#ifdef ENABLE_WIN10_EXTENSIONS
NTSTATUS CopyMemoryEx(PVOID Destination, MM_COPY_ADDRESS Source, SIZE_T NumberOfBytes, ULONG Flags, OUT PSIZE_T BytesCopied) {
	return MmCopyMemory(Destination, Source, NumberOfBytes, Flags, BytesCopied);
}
#endif
