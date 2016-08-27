/*
Подробности:
- В.П.Солдатов "Программирование драйверов Windows: http://drp.su/ru/driver_dev/
*/

#include "IOCTLDispatcher.h"

// Имена устройства и символьной ссылки:
static PCWSTR DeviceNameStr = L"\\Device\\EnjoyTheRing0";
static PCWSTR DeviceLinkStr = L"\\??\\EnjoyTheRing0";

// Драйверные функции:
NTSTATUS DriverEntry	(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID     DriverUnload	(IN PDRIVER_OBJECT DriverObject);
NTSTATUS DriverCreate	(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket);
NTSTATUS DriverCleanup	(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket);
NTSTATUS DriverClose	(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket);
NTSTATUS DriverControl	(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket);

#pragma alloc_text("INIT", DriverEntry)

// Загрузка драйвера в систему:
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) 
{
	UNREFERENCED_PARAMETER(RegistryPath);
	
	NTSTATUS Status;

	// Назначаем события:
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE]  = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DriverCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE]   = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

	// Создаём устройство, ассоциирующееся с драйвером:
	UNICODE_STRING DeviceName;
	PDEVICE_OBJECT DeviceObject;
	RtlInitUnicodeString(&DeviceName, DeviceNameStr);
	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("[ETR0]: IoCreateDevice Error!\r\n");
		return Status;
	}

	// Создаём ссылку на устройство:
	UNICODE_STRING DeviceLink;
	RtlInitUnicodeString(&DeviceLink, DeviceLinkStr);
	Status = IoCreateSymbolicLink(&DeviceLink, &DeviceName);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("[ETR0]: IoCreateSymbolicLink Error!\r\n");
		IoDeleteDevice(DeviceObject);
		return Status;
	}

	DbgPrint("[ETR0]: Successfully loaded!\r\n");

	OnDriverLoad();

	return STATUS_SUCCESS;
}


// Событие обработки IOCTL:
NTSTATUS DriverControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// Получаем указатель на стек запросов и код (IOCTL) полученного запроса:
	PIO_STACK_LOCATION IRPStack = IoGetCurrentIrpStackLocation(IORequestPacket);

	// Собираем в структуру информацию о запросе:
	IOCTL_INFO RequestInfo;
	RequestInfo.ControlCode      = IRPStack->Parameters.DeviceIoControl.IoControlCode;
	RequestInfo.InputBuffer      = IRPStack->Parameters.DeviceIoControl.Type3InputBuffer;
	RequestInfo.OutputBuffer     = IORequestPacket->UserBuffer;
	RequestInfo.InputBufferSize  = IRPStack->Parameters.DeviceIoControl.InputBufferLength;
	RequestInfo.OutputBufferSize = IRPStack->Parameters.DeviceIoControl.OutputBufferLength;

	// Определяем возвращаемое количество байт:
	ULONG ResponseLength = 0;

	// Обрабатываем IRP:
	NTSTATUS Status;
	__try {
		Status = DispatchIOCTL(&RequestInfo, &ResponseLength);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_UNSUCCESSFUL;
		DbgPrint("[ETR0]: Exception catched!\r\n");
	}
	
	// Завершение запроса:
	IORequestPacket->IoStatus.Status = Status;
	IORequestPacket->IoStatus.Information = ResponseLength;
	IoCompleteRequest(IORequestPacket, IO_NO_INCREMENT);

	return Status;
}

// Событие создания драйвера (открытия устройства через CreateFile):
NTSTATUS DriverCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	OnHandleCreate();

	IORequestPacket->IoStatus.Status = STATUS_SUCCESS;
	IORequestPacket->IoStatus.Information = 0;
	IoCompleteRequest(IORequestPacket, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// Событие очистки ресурсов драйвера:
NTSTATUS DriverCleanup(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IORequestPacket->IoStatus.Status = STATUS_SUCCESS;
	IORequestPacket->IoStatus.Information = 0;
	IoCompleteRequest(IORequestPacket, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// Событие закрытия драйвера (закрытия устройства через CloseHandle):
NTSTATUS DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP IORequestPacket)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	OnHandleClose();

	IORequestPacket->IoStatus.Status = STATUS_SUCCESS;
	IORequestPacket->IoStatus.Information = 0;
	IoCompleteRequest(IORequestPacket, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Выгрузка драйвера:
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	OnDriverUnload();

	UNICODE_STRING DeviceLink;
	RtlInitUnicodeString(&DeviceLink, DeviceLinkStr);

	IoDeleteSymbolicLink(&DeviceLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("[ETR0]: Successfully unloaded!\r\n");

	return;
}