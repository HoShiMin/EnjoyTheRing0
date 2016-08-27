#pragma once

#include "MemoryUtils.h"
#include "StringsUtils.h"

// Значение Root для CreateKey и OpenKey:
#define HKEY_CURRENT_USER  L"\\Registry\\User\\.Default\\"
#define HKEY_LOCAL_MACHINE L"\\Registry\\Machine\\"

NTSTATUS CreateKey(LPWSTR Root, LPWSTR KeyPath, OUT PHANDLE hKey);
NTSTATUS OpenKey  (LPWSTR Root, LPWSTR KeyPath, OUT PHANDLE hKey);
NTSTATUS DeleteKey(HANDLE hKey);

#define CloseKey(hKey) ZwClose(hKey)

NTSTATUS SetKeyValue (HANDLE hKey, LPWSTR ValueName, ULONG Type, PVOID Data, ULONG DataSize);
NTSTATUS SetKeyDword (HANDLE hKey, LPWSTR ValueName, DWORD Value);
NTSTATUS SeyKeyBinary(HANDLE hKey, LPWSTR ValueName, PVOID Data, ULONG DataSize);
NTSTATUS SetKeyString(HANDLE hKey, LPWSTR ValueName, LPWSTR String);
NTSTATUS SetKeyExpandString(HANDLE hKey, LPWSTR ValueName, LPWSTR String);

NTSTATUS GetKeyValue (HANDLE hKey, LPWSTR ValueName, PVOID OutputBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned);
NTSTATUS GetKeyDword (HANDLE hKey, LPWSTR ValueName, OUT PDWORD Value);

NTSTATUS GetKeyBinary(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR OutputBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned);
NTSTATUS GetKeyString(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR OutputStringBuffer, ULONG BufferSize, OUT OPTIONAL PULONG BytesReturned);
NTSTATUS GetKeyStringWithAlloc(HANDLE hKey, LPWSTR ValueName, OUT LPWSTR *OutputStringBuffer, OUT OPTIONAL PULONG BytesReturned);

NTSTATUS DeleteKeyValue(HANDLE hKey, LPWSTR ValueName);