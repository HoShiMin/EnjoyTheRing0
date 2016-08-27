#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntdef.h>
#include <windef.h>

//#define ENABLE_WIN10_EXTENSIONS

// Выделение и освобождение виртуальной NonPaged-памяти из пула:
PVOID GetMem(SIZE_T Bytes);
VOID  FreeMem(PVOID Pointer);

// Работа с памятью:
#define CopyMemory(Destination, Source, Length)		RtlCopyMemory(Destination, Source, Length)
#define MoveMemory(Destination, Source, Length)		RtlMoveMemory(Destination, Source, Length)
#define ZeroMemory(Destination, Length)				RtlZeroMemory(Destination, Length)
#define FillMemory(Destination, Length, Fill)		RtlFillMemory(Destination, Length, Fill)
#define EqualMemory(Destination, Source, Length)	RtlEqualMemory(Destination, Source, Length)

// Выделение непрерывных участков физической памяти:
PVOID AllocPhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes);
PVOID AllocCacheablePhysicalMemory(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CachingType);
VOID  FreePhysicalMemory(PVOID BaseAddress);

/* Работа с физической памятью:
	GetPhysicalAddress           - получить физический адрес виртуальной памяти в контексте текущего процесса
	MapPhysicalMemory            - отобразить физическую память на виртуальную с настройкой кэширования
	MapPhysicalMemoryWithProtect - отобразить физическую память на виртуальную с настройкой прав доступа
	ReadPhysicalMemory           - прочитать блок физической памяти в ядерный буфер
	WritePhysicalMemory          - записать содержимое ядерного буфера в физическую память
	UnmapPhysicalMemory          - размапить физическую память
*/
PHYSICAL_ADDRESS GetPhysicalAddress          (PVOID BaseVirtualAddress);
PVOID            MapPhysicalMemory           (PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CachingType);
#ifdef ENABLE_WIN10_EXTENSIONS
PVOID            MapPhysicalMemoryWithProtect(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, ULONG Protect);
#endif
BOOL             ReadPhysicalMemory          (PHYSICAL_ADDRESS PhysicalAddress, PVOID Buffer, SIZE_T BufferSize);
BOOL             WritePhysicalMemory         (PHYSICAL_ADDRESS PhysicalAddress, PVOID Buffer, SIZE_T BufferSize);
VOID             UnmapPhysicalMemory         (PVOID BaseVirtualAddress, SIZE_T NumberOfBytes);

// Чтение DMI - структуры SMBIOS:
#define DMI_SIZE 65536
BOOL ReadDmiMemory(PVOID Buffer, SIZE_T BufferSize);

// "Защитить" память от урезания прав доступа или освобождения (ProbeMode - самый "ограничительный" приемлемый режим):
BOOL SecureVirtualMemory(PVOID VirtualAddress, SIZE_T NumberOfBytes, ULONG ProbeMode, OUT PHANDLE SecureHandle);
BOOL UnsecureVirtualMemory(HANDLE SecureHandle);

// Проверка на валидность адреса:
BOOL IsAddressValid(PVOID VirtualAddress);

// Проверка на возможность чтения\записи юзермодной памяти и "выровненности" адреса:
#define NON_ALIGNED 1
BOOL IsUsermodeMemoryReadable (PVOID Address, SIZE_T NumberOfBytes, ULONG RequiredAlignment);
BOOL IsUsermodeMemoryWriteable(PVOID Address, SIZE_T NumberOfBytes, ULONG RequiredAlignment);

#ifdef ENABLE_WIN10_EXTENSIONS
NTSTATUS CopyMemoryEx(PVOID Destination, MM_COPY_ADDRESS Source, SIZE_T NumberOfBytes, ULONG Flags, OUT PSIZE_T BytesCopied);
#endif
