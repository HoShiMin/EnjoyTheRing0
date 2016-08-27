#include "DriversUtils.h"

LPWSTR DriversRegistryPath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";

NTSTATUS LoadDriver(LPWSTR DriverPath, LPWSTR DriverName) {
	HANDLE hKey;
	NTSTATUS Status;

	Status = CreateKey(HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services\\", &hKey);
	if (!NT_SUCCESS(Status)) return Status;

	SetKeyDword(hKey, L"Type", 0x00000001); // Type = Driver
	SetKeyDword(hKey, L"Start", 0x00000003); // Start = DemandStart
	SetKeyDword(hKey, L"ErrorControl", 0x00000001); // ErrorControl = Normal
	
	SetKeyString(hKey, L"DisplayName", DriverName);

	LPWSTR NtPath;
	ConcatenateStringsW(L"\\??\\", DriverPath, &NtPath);
	SetKeyExpandString(hKey, L"ImagePath", NtPath);

	LPWSTR RegistryPath;
	ConcatenateStringsW(DriversRegistryPath, DriverName, &RegistryPath);
	UNICODE_STRING ServicePath;
	RtlInitUnicodeString(&ServicePath, RegistryPath);
	Status = ZwLoadDriver(&ServicePath);

	FreeString(RegistryPath);
	FreeString(NtPath);
	CloseKey(hKey);

	return Status;
}

NTSTATUS UnloadDriver(LPWSTR DriverName) {
	LPWSTR RegistryPath;
	ConcatenateStringsW(DriversRegistryPath, DriverName, &RegistryPath);
	UNICODE_STRING ServicePath;
	RtlInitUnicodeString(&ServicePath, RegistryPath);
	NTSTATUS Status = ZwUnloadDriver(&ServicePath);
	FreeString(RegistryPath);
	return Status;
}