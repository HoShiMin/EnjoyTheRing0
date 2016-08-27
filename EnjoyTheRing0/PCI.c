#include "PCI.h"

#define PCI_BUS_NOT_EXIST		0 // Шины не существует
#define PCI_NO_DEVICE_AT_SLOT	2 // Нет устройства в указанном слоте

NTSTATUS ReadPciConfig(
	ULONG PciAddress, 
	ULONG PciOffset, 
	PVOID Buffer, 
	ULONG BufferSize, 
	OPTIONAL PULONG BytesRead
) {
	if (BytesRead) *BytesRead = 0;

	PCI_SLOT_NUMBER SlotNumber;
	SlotNumber.u.AsULONG = 0;
	SlotNumber.u.bits.DeviceNumber   = PciGetDeviceNumber(PciAddress);
	SlotNumber.u.bits.FunctionNumber = PciGetFunctionNumber(PciAddress);

	ULONG BusNumber = PciGetBusNumber(PciAddress);
	ULONG Status = HalGetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber.u.AsULONG, Buffer, PciOffset, BufferSize);

	switch (Status) {
	case PCI_BUS_NOT_EXIST: return PCI_ERROR_BUS_NOT_EXIST;
	case PCI_NO_DEVICE_AT_SLOT: return PCI_ERROR_DEVICE_NOT_PRESENT_AT_SLOT;
	default: 
		if (BytesRead) *BytesRead = Status;
		return STATUS_SUCCESS;
	}
}

NTSTATUS WritePciConfig(ULONG PciAddress,
	ULONG PciOffset,
	PVOID Buffer,
	ULONG BufferSize,
	OPTIONAL PULONG BytesWritten
) {
	if (BytesWritten) *BytesWritten = 0;

	PCI_SLOT_NUMBER SlotNumber;
	SlotNumber.u.AsULONG = 0;
	SlotNumber.u.bits.DeviceNumber   = PciGetDeviceNumber(PciAddress);
	SlotNumber.u.bits.FunctionNumber = PciGetFunctionNumber(PciAddress);

	ULONG BusNumber = PciGetBusNumber(PciAddress);
	ULONG Status = HalSetBusDataByOffset(PCIConfiguration, BusNumber, SlotNumber.u.AsULONG, Buffer, PciOffset, BufferSize);

	if (Status == 0) return PCI_ERROR_BUS_DATA_TYPE;

	if (BytesWritten) *BytesWritten = Status;
	return Status == BufferSize ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}