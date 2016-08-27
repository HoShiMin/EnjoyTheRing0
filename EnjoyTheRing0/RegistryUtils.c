#include "RegistryUtils.h"

LPWSTR GetFullKeyPath(LPWSTR Root, LPWSTR KeyPath) {
	LPWSTR FullKeyPath;
	ConcatenateStringsW(Root, KeyPath, &FullKeyPath);
	return FullKeyPath;
}



NTSTATUS CreateKey(LPWSTR Root, LPWSTR KeyPath, OUT PHANDLE hKey) {
	LPWSTR FullKeyPath = GetFullKeyPath(Root, KeyPath);
	UNICODE_STRING UnicodePath;
	RtlInitUnicodeString(&UnicodePath, FullKeyPath);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS Status = ZwCreateKey(hKey, KEY_ALL_ACCESS, &ObjectAttributes, 0, NULL, REG_OPTION_VOLATILE, NULL);

	FreeString(FullKeyPath);
	return Status;
}

NTSTATUS OpenKey(LPWSTR Root, LPWSTR KeyPath, OUT PHANDLE hKey) {
	LPWSTR FullKeyPath = GetFullKeyPath(Root, KeyPath);
	UNICODE_STRING UnicodePath;
	RtlInitUnicodeString(&UnicodePath, FullKeyPath);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &UnicodePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	NTSTATUS Status = ZwOpenKey(hKey, KEY_ALL_ACCESS, &ObjectAttributes);
	
	FreeString(FullKeyPath);
	return Status;
}



NTSTATUS DeleteKey(HANDLE hKey) {
	return ZwDeleteKey(hKey);
}



NTSTATUS SetKeyValue(HANDLE hKey, LPWSTR ValueName, ULONG Type, PVOID Data, ULONG DataSize) {
	UNICODE_STRING UnicodeValueName;
	RtlInitUnicodeString(&UnicodeValueName, ValueName);
	return ZwSetValueKey(hKey, &UnicodeValueName, 0, Type, Data, DataSize);
}

NTSTATUS SetKeyDword(HANDLE hKey, LPWSTR ValueName, DWORD Value) {
	return SetKeyValue(hKey, ValueName, REG_DWORD, &Value, sizeof(DWORD));
}

NTSTATUS SeyKeyBinary(HANDLE hKey, LPWSTR ValueName, PVOID Data, ULONG DataSize) {
	return SetKeyValue(hKey, ValueName, REG_BINARY, Data, DataSize);
}

NTSTATUS SetKeyString(HANDLE hKey, LPWSTR ValueName, LPWSTR String) {
	return SetKeyValue(hKey, ValueName, REG_SZ, String, (ULONG)LengthW(String) * sizeof(WCHAR) + sizeof(WCHAR));
}

NTSTATUS SetKeyExpandString(HANDLE hKey, LPWSTR ValueName, LPWSTR String) {
	return SetKeyValue(hKey, ValueName, REG_EXPAND_SZ, String, (ULONG)LengthW(String) * sizeof(WCHAR) + sizeof(WCHAR));
}



NTSTATUS GetKeyValue(HANDLE hKey, LPWSTR ValueName, PVOID OutputBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned) {
	if (BytesReturned != NULL) *BytesReturned = 0;
	
	UNICODE_STRING UnicodeValueName;
	RtlInitUnicodeString(&UnicodeValueName, ValueName);
	
	ULONG PartialInformationSize = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + BufferSize - 1;
	PKEY_VALUE_PARTIAL_INFORMATION PartialInformation = GetMem(PartialInformationSize);
	
	ULONG ResultLength = 0;
	NTSTATUS Status = ZwQueryValueKey(hKey, &UnicodeValueName, KeyValuePartialInformation, PartialInformation, PartialInformationSize, &ResultLength);
	
	if NT_SUCCESS(Status) {
		RtlCopyMemory(OutputBuffer, PartialInformation->Data, PartialInformation->DataLength);
		if (BytesReturned != NULL) *BytesReturned = PartialInformation->DataLength;
	} else if ((BytesReturned != NULL) && ((Status == STATUS_BUFFER_OVERFLOW) || (Status == STATUS_BUFFER_TOO_SMALL))) {
		*BytesReturned = ResultLength - sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1;
	}
	
	FreeMem(PartialInformation);
	return Status;
}

NTSTATUS GetKeyDword(HANDLE hKey, LPWSTR ValueName, OUT PDWORD Value) {
	return GetKeyValue(hKey, ValueName, Value, sizeof(DWORD), NULL);
}

NTSTATUS GetKeyBinary(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR OutputBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned) {
	return GetKeyValue(hKey, ValueName, OutputBuffer, BufferSize, BytesReturned);
}

NTSTATUS GetKeyString(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR OutputStringBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned) {
	return GetKeyValue(hKey, ValueName, OutputStringBuffer, BufferSize, BytesReturned);
}

NTSTATUS GetKeyStringWithAlloc(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR *OutputStringBuffer, OUT OPTIONAL PULONG BytesReturned) {
	if (BytesReturned != NULL) *BytesReturned = 0;
	*OutputStringBuffer = NULL;

	ULONG RequiredMemory = 0;
	NTSTATUS Status = GetKeyString(hKey, ValueName, NULL, 0, &RequiredMemory);
	
	if (((Status == STATUS_BUFFER_OVERFLOW) || (Status == STATUS_BUFFER_TOO_SMALL)) && (RequiredMemory > 0)) {
		LPWSTR Buffer = GetMem(RequiredMemory);
		Status = GetKeyValue(hKey, ValueName, Buffer, RequiredMemory, BytesReturned != NULL ? BytesReturned : NULL);
		if (!NT_SUCCESS(Status)) FreeMem(Buffer); else *OutputStringBuffer = Buffer;
	}

	return Status;
}



NTSTATUS DeleteKeyValue(HANDLE hKey, LPWSTR ValueName) {
	UNICODE_STRING UnicodeValueName;
	RtlInitUnicodeString(&UnicodeValueName, ValueName);
	return ZwDeleteValueKey(hKey, &UnicodeValueName);
}