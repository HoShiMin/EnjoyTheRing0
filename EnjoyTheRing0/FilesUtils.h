#pragma once

#include "MemoryUtils.h"
#include "StringsUtils.h"

// Сокращённые флаги доступа:
#define FULL_ACCESS         GENERIC_ALL
#define FULL_SHARED_ACCESS  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
#define NON_SHARED_ACCESS   0 // Исключительные права на файл (нет разделяемого доступа)

// Макрос для определения успешности выполнения CreateFile:
#define SUCCESS_FILE_OPERATION(Status, Handle) (NT_SUCCESS((NTSTATUS)Status) && ((HANDLE)Handle != 0))

// Создание или открытие файла или папки с настраиваемыми параметрами доступа:
NTSTATUS CreateFile(
	OUT PHANDLE hFile, 
	LPWSTR FilePath, 
	ACCESS_MASK AccessMask, 
	ULONG FileAttributes, 
	ULONG ShareAccess, 
	ULONG DispositionFlags, 
	ULONG CreateOptions
);

// Создание или открытие файлов с частоиспользуемыми параметрами (+ подготовка файлов для записи\чтения с флагом FILE_SYNCHRONOUS_IO_NONALERT):
NTSTATUS CreateEmptyFile(OUT PHANDLE hFile, LPWSTR FilePath);
NTSTATUS OpenFile       (OUT PHANDLE hFile, LPWSTR FilePath, BOOL CreateIfNotExists);
NTSTATUS AppendFile     (OUT PHANDLE hFile, LPWSTR FilePath, BOOL CreateIfNotExists);

NTSTATUS CreateDirectory(LPWSTR DirPath);

#define CloseFile(hFile) ZwClose(hFile)

// Переименование или перемещение файлов и папок (переименование и перемещение - одна и та же операция):
NTSTATUS MoveFileObject (LPWSTR OldFilePath     , LPWSTR NewFilePath     , BOOLEAN ReplaceIfExists, BOOL IsDirectory);
NTSTATUS MoveFile       (LPWSTR OldFilePath     , LPWSTR NewFilePath     , BOOLEAN ReplaceIfExists);
NTSTATUS MoveDirectory  (LPWSTR OldDirectoryName, LPWSTR NewDirectoryName, BOOLEAN ReplaceIfExists);
NTSTATUS RenameFile     (LPWSTR OldFilePath     , LPWSTR NewFilePath     , BOOLEAN ReplaceIfExists);
NTSTATUS RenameDirectory(LPWSTR OldDirectoryName, LPWSTR NewDirectoryName);

// Удаление:
NTSTATUS DeleteFileObject(LPWSTR Path);
NTSTATUS DeleteFile      (LPWSTR FilePath);
NTSTATUS DeleteDirectory (LPWSTR DirectoryPath);

// Проверка на существование:
BOOL FileObjectExists(LPWSTR Path, BOOL IsDirectory);
BOOL FileExists      (LPWSTR FilePath);
BOOL DirectoryExists (LPWSTR DirectoryPath);

LONGLONG GetFileSize(LPWSTR FilePath);

// Чтение и запись в файлы, в CreateOptions нужно дополнительно передать FILE_SYNCHRONOUS_IO_NONALERT:
NTSTATUS ReadFile (HANDLE hFile, PVOID Buffer, ULONG Size, IN OPTIONAL PLARGE_INTEGER Offset, OUT OPTIONAL PULONG BytesRead);
NTSTATUS WriteFile(HANDLE hFile, PVOID Buffer, ULONG Size, IN OPTIONAL PLARGE_INTEGER Offset, OUT OPTIONAL PULONG BytesWritten);

// Копирование файла:
NTSTATUS CopyFile(LPWSTR SrcFile, LPWSTR DestFile);