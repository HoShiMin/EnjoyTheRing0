#pragma once

#include <wdm.h>
#include <ntdef.h>
#include <windef.h>

// I/O:

VOID __fastcall StartBeeper();
VOID __fastcall StopBeeper();
VOID __fastcall SetBeeperRegime();
VOID __fastcall SetBeeperOut();
VOID __fastcall SetBeeperIn();
VOID __fastcall SetBeeperDivider(WORD Divider);
VOID __fastcall SetBeeperFrequency(WORD Frequency);

VOID __fastcall WriteIoPortByte (WORD PortNumber, BYTE  Data);
VOID __fastcall WriteIoPortWord (WORD PortNumber, WORD  Data);
VOID __fastcall WriteIoPortDword(WORD PortNumber, DWORD Data);

BYTE  __fastcall ReadIoPortByte (WORD PortNumber);
WORD  __fastcall ReadIoPortWord (WORD PortNumber);
DWORD __fastcall ReadIoPortDword(WORD PortNumber);

// Interrupts:

#pragma pack(push, 1)
typedef struct _REGISTERS_STATE {
#ifdef _AMD64_
	DWORD64 RAX;
	DWORD64 RCX;
	DWORD64 RDX;
#else
	DWORD32 EAX;
	DWORD32 ECX;
	DWORD32 EDX;
#endif
} REGISTERS_STATE, *PREGISTERS_STATE;
#pragma pack(pop)

VOID __fastcall _CLI();
VOID __fastcall _STI();
VOID __fastcall _HLT();
VOID __fastcall _INT(BYTE InterruptNumber, PREGISTERS_STATE RegistersState);

// MSR:

ULONGLONG __fastcall _RDPMC(ULONG Index);
ULONGLONG __fastcall _RDMSR(ULONG Index);
VOID      __fastcall _WRMSR(ULONG Index, PULONGLONG Value);

// SystemRegisters:

/*
  CR0 - содержимое контрольных битов
  CR2, CR3 - для страничной трансляции
  CR4 - биты, определяющие системные возможности
  CR8 - изменяет приоритет внешних прерываний
  Остальные CR не используются, при попытке обращения будет сгенерировано #UD (Undefined Opcode)

  DR0..DR3 - линейные адреса брейкпоинтов
  DR4, DR5 - связаны с DR6 и DR7, если CR4.DE = 0
  DR6 - статусный отладочный регистр
  DR7 - контрольный отладочный регистр
  Остальные DR зарезервированы, при обращении будет сгенерировано #UD
*/

#define READ_CR  (BYTE)0x20
#define WRITE_CR (BYTE)0x22
#define READ_DR  (BYTE)0x21
#define WRITE_DR (BYTE)0x23 
#define SYS_REG_OPERATION(Operation, RegisterNumber) ((WORD)(((BYTE)Operation << 8) | (BYTE)RegisterNumber))

#define READ_CR0 (WORD)SYS_REG_OPERATION(READ_CR, 0)
#define READ_CR2 (WORD)SYS_REG_OPERATION(READ_CR, 2)
#define READ_CR3 (WORD)SYS_REG_OPERATION(READ_CR, 3)
#define READ_CR4 (WORD)SYS_REG_OPERATION(READ_CR, 4)
#define READ_CR8 (WORD)SYS_REG_OPERATION(READ_CR, 8)

#define WRITE_CR0 (WORD)SYS_REG_OPERATION(WRITE_CR, 0)
#define WRITE_CR2 (WORD)SYS_REG_OPERATION(WRITE_CR, 2)
#define WRITE_CR3 (WORD)SYS_REG_OPERATION(WRITE_CR, 3)
#define WRITE_CR4 (WORD)SYS_REG_OPERATION(WRITE_CR, 4)
#define WRITE_CR8 (WORD)SYS_REG_OPERATION(WRITE_CR, 8)

#define READ_DR0 (WORD)SYS_REG_OPERATION(READ_DR, 0)
#define READ_DR1 (WORD)SYS_REG_OPERATION(READ_DR, 1)
#define READ_DR2 (WORD)SYS_REG_OPERATION(READ_DR, 2)
#define READ_DR3 (WORD)SYS_REG_OPERATION(READ_DR, 3)
#define READ_DR6 (WORD)SYS_REG_OPERATION(READ_DR, 6)
#define READ_DR7 (WORD)SYS_REG_OPERATION(READ_DR, 7)

#define WRITE_DR0 (WORD)SYS_REG_OPERATION(WRITE_DR, 0)
#define WRITE_DR1 (WORD)SYS_REG_OPERATION(WRITE_DR, 1)
#define WRITE_DR2 (WORD)SYS_REG_OPERATION(WRITE_DR, 2)
#define WRITE_DR3 (WORD)SYS_REG_OPERATION(WRITE_DR, 3)
#define WRITE_DR6 (WORD)SYS_REG_OPERATION(WRITE_DR, 6)
#define WRITE_DR7 (WORD)SYS_REG_OPERATION(WRITE_DR, 7)

VOID    __fastcall DisableWriteProtection();
VOID    __fastcall EnableWriteProtection();
BOOLEAN __fastcall IsSMEPPresent();
BOOLEAN __fastcall IsSMAPPresent();
VOID    __fastcall DisableSMEP();
VOID    __fastcall DisableSMAP();
VOID    __fastcall EnableSMEP();
VOID    __fastcall EnableSMAP();
SIZE_T  __fastcall OperateCrDrRegister(WORD Action, OPTIONAL SIZE_T OptionalData);

#pragma pack(push, 1)

// AMD64 APMv2, стр. 334:
#ifdef _X86_
#pragma warning(push)
#pragma warning(disable: 4214)
#pragma warning(disable: 4201)
typedef struct _TSS {
	WORD	Link;
	WORD	Reserved1;
	ULONG	ESP0;
	WORD	SS0;
	WORD	Reserved2;
	ULONG	ESP1;
	WORD	SS1;
	WORD	Reserved3;
	ULONG	ESP2;
	WORD	SS2;
	WORD	Reserved4;
	ULONG	CR3;
	ULONG	EIP;
	ULONG	EFlags;
	ULONG	EAX;
	ULONG	ECX;
	ULONG	EDX;
	ULONG	EBX;
	ULONG	ESP;
	ULONG	EBP;
	ULONG	ESI;
	ULONG	EDI;
	WORD	ES;
	WORD	Reserved5;
	WORD	CS;
	WORD	Reserved6;
	WORD	SS;
	WORD	Reserved7;
	WORD	DS;
	WORD	Reserved8;
	WORD	FS;
	WORD	Reserved9;
	WORD	GS;
	WORD	Reserved10;
	WORD	LDTSelector;
	WORD	Reserved11;
	union {
		struct {
			unsigned short Trap			: 1;
			unsigned short Reserved12	: 15;
		};
		WORD	wReserved12;
	};
	WORD	IOPBBaseAddress;
} TSS, *PTSS;
#pragma warning(pop)
#else
typedef struct _TSS {
	ULONG	Reserved1;
	ULONG64 ESP0;
	ULONG64 ESP1;
	ULONG64 ESP2;
	ULONG64 Reserved2;
	ULONG64 IST1;
	ULONG64 IST2;
	ULONG64 IST3;
	ULONG64 IST4;
	ULONG64 IST5;
	ULONG64 IST6;
	ULONG64	IST7;
	ULONG64	Reserved3;
	WORD	Reserved4;
	WORD	IOPBBaseAddress;
} TSS, *PTSS;
#endif

#define ExtractLimitFromGdtEntry(GdtEntry) ((ULONG)((GdtEntry->LimitHigh << 16) | (GdtEntry->LimitLow)))

#ifdef _X86_
#define ExtractBaseFromGdtEntry(GdtEntry) ((PVOID)((GdtEntry->BaseAddressHigh << 24) | (GdtEntry->BaseAddressMiddle << 16) | (GdtEntry->BaseAddressLow)))
// AMD64 APMv2, стр. 80:
typedef struct _GDTENTRY {
	unsigned LimitLow			: 16;
	unsigned BaseAddressLow		: 16;
	unsigned BaseAddressMiddle	: 8;
	unsigned Type				: 4;
	unsigned System				: 1;
	unsigned DPL				: 2;
	unsigned Present			: 1;
	unsigned LimitHigh			: 4;
	unsigned Available			: 1;
	unsigned Reserved			: 1;
	unsigned DefaultOperandSize : 1;
	unsigned Granularity		: 1;
	unsigned BaseAddressHigh	: 8;
} GDTENTRY, *PGDTENTRY;
#else
#define ExtractBaseFromGdtEntry(GdtEntry) ((PVOID)(((UINT64)GdtEntry->BaseAddressHighest << 32) | (GdtEntry->BaseAddressHigh << 24) | (GdtEntry->BaseAddressMiddle << 16) | (GdtEntry->BaseAddressLow)))
// AMD64 APMv2, стр. 91:
typedef struct _GDTENTRY {
	unsigned LimitLow				: 16;
	unsigned BaseAddressLow			: 16;
	unsigned BaseAddressMiddle		: 8;
	unsigned Type					: 4;
	unsigned System					: 1;
	unsigned DPL					: 2;
	unsigned Present				: 1;
	unsigned LimitHigh				: 4;
	unsigned Available				: 1;
	unsigned Reserved1				: 2;
	unsigned Granularity			: 1;
	unsigned BaseAddressHigh		: 8;
	unsigned BaseAddressHighest		: 32;
	unsigned Reserved2				: 8;
	unsigned SystemOrTypeZeroBit8	: 1;
	unsigned SystemOrTypeZeroBit9	: 1;
	unsigned SystemOrTypeZeroBit10	: 1;
	unsigned SystemOrTypeZeroBit11	: 1;
	unsigned SystemOrTypeZeroBit12	: 1;
	unsigned Reserved3				: 3;
	unsigned Reserved4				: 16;
} GDTENTRY, *PGDTENTRY;
#endif

typedef struct _GDTR {
	WORD		Limit;
	PGDTENTRY	Base;
} GDTR, *PGDTR;

typedef struct _IDTR {
	WORD	Limit;
	PVOID	Base;
} IDTR, *PIDTR;


#pragma warning(push)
#pragma warning(disable: 4214)
#pragma warning(disable: 4201)
typedef struct _TR {
	union {
		struct {
			unsigned short RPL				: 2;
			unsigned short TableIndicator	: 1;
			unsigned short SelectorIndex	: 13; // Индекс в GDT (TSS Ptr = GDTR:Base + TR:SelectorIndex)
		};
		WORD Selector;
	};
} TR, *PTR;
#pragma warning(pop)

#pragma pack(pop)

#define SIDT 0x900A010F
#define SGDT 0x9002010F
#define STR  0x900A000F

#define LIDT 0x901A010F
#define LGDT 0x9012010F
#define LTR  0x901A000F

ULONG __fastcall IdtGdtTrOperation(DWORD32 Operation, PVOID Data);

PTSS GetTSSPointer(OUT OPTIONAL PULONG TSSLimit);