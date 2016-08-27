#pragma once

#include "ProcessesUtils.h"
#include "NativeFunctions.h"
#include "ShellCode.h"
#include "Protection.h"
#include "PCI.h"

#define PROTECTION_SUPPORT

// Обработчики событий драйвера:
VOID OnDriverLoad();
VOID OnHandleCreate();
VOID OnHandleClose();
VOID OnDriverUnload();

// Количество открытых дескрипторов драйвера:
static volatile LONG HandlesCount = 0;

// Информация о запросе:
typedef struct _IOCTL_INFO {
	PVOID InputBuffer;
	PVOID OutputBuffer;
	ULONG InputBufferSize;
	ULONG OutputBufferSize;
	ULONG ControlCode;
} IOCTL_INFO, *PIOCTL_INFO;

// Диспетчер запросов:
NTSTATUS FASTCALL DispatchIOCTL(IN PIOCTL_INFO RequestInfo, OUT PULONG ResponseLength);

#define IOCTL(Code) (CTL_CODE(0x8000, Code, METHOD_NEITHER, FILE_ANY_ACCESS))

// NativeFunctions:

typedef struct _WRITE_IO_PORT_BYTE_INPUT {
	WORD PortNumber;
	BYTE Data;
} WRITE_IO_PORT_BYTE_INPUT, *PWRITE_IO_PORT_BYTE_INPUT;

typedef struct _WRITE_IO_PORT_WORD_INPUT {
	WORD PortNumber;
	WORD Data;
} WRITE_IO_PORT_WORD_INPUT, *PWRITE_IO_PORT_WORD_INPUT;

typedef struct _WRITE_IO_PORT_DWORD_INPUT {
	WORD  PortNumber;
	DWORD Data;
} WRITE_IO_PORT_DWORD_INPUT, *PWRITE_IO_PORT_DWORD_INPUT;

typedef struct _WRMSR_INPUT {
	ULONG     Index;
	ULONGLONG Data;
} WRMSR_INPUT, *PWRMSR_INPUT;

// MemoryUtils:

typedef struct _MOVE_MEMORY_INPUT {
	PVOID64 Destination;
	PVOID64 Source;
	UINT64  Size;
} MOVE_MEMORY_INPUT, *PMOVE_MEMORY_INPUT;

typedef struct _COPY_MEMORY_INPUT {
	PVOID64 Destination;
	PVOID64 Source;
	UINT64  Size;
} COPY_MEMORY_INPUT, *PCOPY_MEMORY_INPUT;

typedef struct _ZERO_MEMORY_INPUT {
	PVOID64 Destination;
	UINT64  Size;
} ZERO_MEMORY_INPUT, *PZERO_MEMORY_INPUT;

typedef struct _FILL_MEMORY_INPUT {
	PVOID64 Destination;
	UINT64  Size;
	BYTE    FillingByte;
} FILL_MEMORY_INPUT, *PFILL_MEMORY_INPUT;

typedef struct _EQUAL_MEMORY_INPUT {
	PVOID64 Destination;
	PVOID64 Source;
	UINT64  Size;
} EQUAL_MEMORY_INPUT, *PEQUAL_MEMORY_INPUT;

typedef struct _ALLOC_PHYSICAL_MEMORY_INPUT {
	PHYSICAL_ADDRESS PhysicalAddress;
	UINT64 Size;
} ALLOC_PHYSICAL_MEMORY_INPUT, *PALLOC_PHYSICAL_MEMORY_INPUT;

typedef struct _GET_PHYSICAL_ADDRESS_INPUT {
	UINT64  ProcessID;
	PVOID64 VirtualAddress;
} GET_PHYSICAL_ADDRESS_INPUT, *PGET_PHYSICAL_ADDRESS_INPUT;

typedef struct _READ_PHYSICAL_MEMORY_INPUT {
	PHYSICAL_ADDRESS PhysicalAddress;
	PVOID64 Buffer;
	ULONG   BufferSize;
} READ_PHYSICAL_MEMORY_INPUT, *PREAD_PHYSICAL_MEMORY_INPUT;

typedef struct _WRITE_PHYSICAL_MEMORY_INPUT {
	PHYSICAL_ADDRESS PhysicalAddress;
	PVOID64 Buffer;
	ULONG   BufferSize;
} WRITE_PHYSICAL_MEMORY_INPUT, *PWRITE_PHYSICAL_MEMORY_INPUT;

// ShellCode:

typedef struct _EXECUTE_SHELL_CODE_INPUT {
	IN PVOID64 EntryPoint;
	IN PVOID64 CodeBlock;
	IN OPTIONAL PVOID64 InputData;
	IN OPTIONAL PVOID64 OutputData;
	IN OPTIONAL PVOID64 Result;
} EXECUTE_SHELL_CODE_INPUT, *PEXECUTE_SHELL_CODE_INPUT;

// ProcessesUtils:

typedef struct _ALLOC_VIRTUAL_MEMORY_INPUT {
	UINT64 ProcessId;
	UINT64 Size;
} ALLOC_VIRTUAL_MEMORY_INPUT, *PALLOC_VIRTUAL_MEMORY_INPUT;

typedef struct _ALLOC_VIRTUAL_MEMORY_OUTPUT {
	PVOID64  VirtualAddress;
	NTSTATUS Status;
} ALLOC_VIRTUAL_MEMORY_OUTPUT, *PALLOC_VIRTUAL_MEMORY_OUTPUT;

typedef struct _FREE_VIRTUAL_MEMORY_INPUT {
	UINT64  ProcessId;
	PVOID64 VirtualAddress;
} FREE_VIRTUAL_MEMORY_INPUT, *PFREE_VIRTUAL_MEMORY_INPUT;

typedef struct _MAP_VIRTUAL_MEMORY_INPUT {
	UINT64  ProcessId;
	PVOID64 VirtualAddress;
	PVOID64 MapToVirtualAddress;
	ULONG   Size;
} MAP_VIRTUAL_MEMORY_INPUT, *PMAP_VIRTUAL_MEMORY_INPUT;

typedef struct _MAP_VIRTUAL_MEMORY_OUTPUT {
	PVOID64 Mdl;
	PVOID64 MappedMemory;
} MAP_VIRTUAL_MEMORY_OUTPUT, *PMAP_VIRTUAL_MEMORY_OUTPUT;

typedef struct _UNMAP_VIRTUAL_MEMORY_INPUT {
	PVOID64 Mdl;
	PVOID64 MappedMemory;
} UNMAP_VIRTUAL_MEMORY_INPUT, *PUNMAP_VIRTUAL_MEMORY_INPUT;

typedef struct _READ_PROCESS_MEMORY_INPUT {
	UINT64  ProcessId;
	PVOID64 VirtualAddress;
	PVOID64 Buffer;
	ULONG   BytesToRead;
	BYTE    AccessType;
} READ_PROCESS_MEMORY_INPUT, *PREAD_PROCESS_MEMORY_INPUT;

typedef struct _WRITE_PROCESS_MEMORY_INPUT {
	UINT64  ProcessId;
	PVOID64 VirtualAddress;
	PVOID64 Buffer;
	ULONG   BytesToWrite;
	BYTE    AccessType;
} WRITE_PROCESS_MEMORY_INPUT, *PWRITE_PROCESS_MEMORY_INPUT;

// Protection:

typedef struct _ADD_REMOVE_PROCESS_INPUT {
	UINT64 ProcessId;
	UINT64 DefenderId;
} ADD_REMOVE_PROCESS_INPUT, *PADD_REMOVE_PROCESS_INPUT;

// PCI:

typedef struct _READ_PCI_CONFIG_INPUT {
	ULONG	PciAddress;
	ULONG	PciOffset;
	PVOID64 Buffer;
	ULONG	BufferSize;
} READ_PCI_CONFIG_INPUT, *PREAD_PCI_CONFIG_INPUT;

typedef struct _READ_PCI_CONFIG_OUTPUT {
	NTSTATUS Status;
	ULONG BytesRead;
} READ_PCI_CONFIG_OUTPUT, *PREAD_PCI_CONFIG_OUTPUT;

typedef struct _WRITE_PCI_CONFIG_INPUT {
	ULONG	PciAddress;
	ULONG	PciOffset;
	PVOID64 Buffer;
	ULONG	BufferSize;
} WRITE_PCI_CONFIG_INPUT, *PWRITE_PCI_CONFIG_INPUT;

typedef struct _WRITE_PCI_CONFIG_OUTPUT {
	NTSTATUS Status;
	ULONG BytesWritten;
} WRITE_PCI_CONFIG_OUTPUT, *PWRITE_PCI_CONFIG_OUTPUT;

// Other:

typedef struct _BUG_CHECK_EX_INPUT {
	ULONG BugCheckCode;
	ULONG BugCheckParameter1;
	ULONG BugCheckParameter2;
	ULONG BugCheckParameter3;
	ULONG BugCheckParameter4;
} BUG_CHECK_EX_INPUT, *PBUG_CHECK_EX_INPUT;

// DriverFunctions:

#define GET_HANDLES_COUNT          IOCTL(0x800)

// NativeFunctions:

#define START_BEEPER               IOCTL(0x801)
#define STOP_BEEPER                IOCTL(0x802)
#define SET_BEEPER_REGIME          IOCTL(0x803)
#define SET_BEEPER_OUT             IOCTL(0x804)
#define SET_BEEPER_IN              IOCTL(0x805)
#define SET_BEEPER_DIVIDER         IOCTL(0x806)
#define SET_BEEPER_FREQUENCY       IOCTL(0x807)

#define READ_IO_PORT_BYTE          IOCTL(0x808)
#define READ_IO_PORT_WORD          IOCTL(0x809)
#define READ_IO_PORT_DWORD         IOCTL(0x80A)

#define WRITE_IO_PORT_BYTE         IOCTL(0x80B)
#define WRITE_IO_PORT_WORD         IOCTL(0x80C)
#define WRITE_IO_PORT_DWORD        IOCTL(0x80D)

#define RDPMC                      IOCTL(0x80E)
#define RDMSR                      IOCTL(0x80F)
#define WRMSR                      IOCTL(0x810)

#define HALT                       IOCTL(0x811)

// MemoryUtils:

#define ALLOC_KERNEL_MEMORY        IOCTL(0x812)
#define FREE_KERNEL_MEMORY         IOCTL(0x813)

#define MOVE_MEMORY                IOCTL(0x814)
#define COPY_MEMORY                IOCTL(0x815)
#define ZERO_MEMORY                IOCTL(0x816)
#define FILL_MEMORY                IOCTL(0x817)
#define EQUAL_MEMORY               IOCTL(0x818)

#define ALLOC_PHYSICAL_MEMORY      IOCTL(0x819)
#define FREE_PHYSICAL_MEMORY       IOCTL(0x81A)
#define GET_PHYSICAL_ADDRESS       IOCTL(0x81B)
#define READ_PHYSICAL_MEMORY       IOCTL(0x81C)
#define WRITE_PHYSICAL_MEMORY      IOCTL(0x81D)

#define READ_DMI_MEMORY            IOCTL(0x81E)

// ShellCode:

#define EXECUTE_SHELL_CODE         IOCTL(0x81F)

// ProcessesUtils:

#define ALLOC_VIRTUAL_MEMORY       IOCTL(0x820)
#define FREE_VIRTUAL_MEMORY        IOCTL(0x821)

#define MAP_VIRTUAL_MEMORY         IOCTL(0x822)
#define UNMAP_VIRTUAL_MEMORY       IOCTL(0x823)

#define READ_PROCESS_MEMORY        IOCTL(0x824)
#define WRITE_PROCESS_MEMORY       IOCTL(0x825)

#define RAISE_IOPL_BY_TF           IOCTL(0x826)
#define RESET_IOPL_BY_TF           IOCTL(0x827)

#define RAISE_IOPL_BY_TF_SCAN      IOCTL(0x828)
#define RESET_IOPL_BY_TF_SCAN      IOCTL(0x829)

#define RAISE_IOPL_BY_TSS          IOCTL(0x82A)
#define RESET_IOPL_BY_TSS          IOCTL(0x82B)

#define RAISE_IOPM                 IOCTL(0x82C)
#define RESET_IOPM                 IOCTL(0x82D)

#define KILL_PROCESS               IOCTL(0x82E)

// Protection:

#define ADD_PROTECTED_PROCESS      IOCTL(0x82F)
#define REMOVE_PROTECTED_PROCESS   IOCTL(0x830)
#define IS_PROCESS_PROTECTED       IOCTL(0x831)
#define PRINT_PROTECTED_PROCESSES  IOCTL(0x832)

// PCI:

#define READ_PCI_CONFIG            IOCTL(0x833)
#define WRITE_PCI_CONFIG           IOCTL(0x834)

// Other:

#define STALL_EXECUTION_PROCESSOR  IOCTL(0x835)

#define BUG_CHECK                  IOCTL(0x836)
#define BUG_CHECK_EX               IOCTL(0x837)