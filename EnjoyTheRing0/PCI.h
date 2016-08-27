#pragma once

#include <ntddk.h>

// Номера шины, устройства и функции в адрес PCI-устройства:
#define PciGetAddress(Bus, Device, Function)	(((Bus & 0xFF) << 8) | ((Device & 0x1F) << 3) | (Function & 7))

// Получить номер шины из адреса PCI-устройства:
#define PciGetBusNumber(Address)				((Address >> 8) & 0xFF)

// Получить номер устройства из адреса PCI-устройства:
#define PciGetDeviceNumber(Address)				((Address >> 3) & 0x1F)

// Получить номер функции из адреса PCI-устройства:
#define PciGetFunctionNumber(Address)			(Address & 7)

// Коды ошибок при работе с PCI:
#define PCI_ERROR_BUS_NOT_EXIST					0xE0000001L
#define PCI_ERROR_DEVICE_NOT_PRESENT_AT_SLOT	0xE0000002L
#define PCI_ERROR_BUS_DATA_TYPE					0xE0000003L

NTSTATUS ReadPciConfig(
	ULONG PciAddress,
	ULONG PciOffset,
	PVOID Buffer,
	ULONG BufferSize,
	OPTIONAL PULONG BytesRead
);

NTSTATUS WritePciConfig(
	ULONG PciAddress,
	ULONG PciOffset,
	PVOID Buffer,
	ULONG BufferSize,
	OPTIONAL PULONG BytesWritten
);