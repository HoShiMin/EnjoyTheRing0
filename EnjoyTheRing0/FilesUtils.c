#include "FilesUtils.h"

FORCEINLINE SIZE_T GetNtPath(LPWSTR Path, OUT LPWSTR* NtPath) {
	return ConcatenateStringsW(L"\\??\\", Path, NtPath);
}

FORCEINLINE VOID FreeNtPath(LPWSTR NtPath) {
	FreeString(NtPath);
}

FORCEINLINE SIZE_T InitUnicodeNtPath(LPWSTR Path, OUT PUNICODE_STRING NativePath, OUT LPWSTR* NtPath) {
	SIZE_T Length = GetNtPath(Path, NtPath);
	RtlInitUnicodeString(NativePath, *NtPath);
	return Length;
}

FORCEINLINE VOID FreeUnicodeNtPath(LPWSTR NtPath) {
	FreeString(NtPath);
}



NTSTATUS CreateFile(OUT PHANDLE hFile, LPWSTR FilePath, ACCESS_MASK AccessMask, ULONG FileAttributes, ULONG ShareAccess, ULONG DispositionFlags, ULONG CreateOptions) {
	NTSTATUS          Status;
	UNICODE_STRING    NativePath;
	LPWSTR            NtPathBuffer;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK   IoStatusBlock;
	LARGE_INTEGER     AllocationSize;

	AllocationSize.QuadPart = 0;

	// Инициализируем ObjectAttributes:
	InitUnicodeNtPath(FilePath, &NativePath, &NtPathBuffer);
	InitializeObjectAttributes(&ObjectAttributes, &NativePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// Создаём (открываем) файл:
	Status = ZwCreateFile(
		hFile,             // Сюда будет записан хэндл
		AccessMask,        // GENERIC_READ, GENERIC_WRITE и т.д.
		&ObjectAttributes, // Указатель на структуру с информацией о файле (путь и т.д.)
		&IoStatusBlock,    // Указатель на структуру, куда будет записана информация о статусе открытия файла
		&AllocationSize,   // Следует ли выделять память под файл
		FileAttributes,    // Атрибуты файла (FILE_ATTRIBUTE_NORMAL и т.д.)
		ShareAccess,       // Флаги разделяемого доступа
		DispositionFlags,  // Следует ли создавать файл, если он существует, и похожие флаги
		CreateOptions,     // Флаги синхронных операций над файлом
		NULL,
		0
	);

	FreeUnicodeNtPath(NtPathBuffer);

	return Status;
}

NTSTATUS CreateEmptyFile(OUT PHANDLE hFile, LPWSTR FilePath) {
	return CreateFile(
		hFile, 
		FilePath, 
		FULL_ACCESS, 
		FILE_ATTRIBUTE_NORMAL, 
		FULL_SHARED_ACCESS, 
		FILE_OVERWRITE_IF, 
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	);
}

NTSTATUS OpenFile(OUT PHANDLE hFile, LPWSTR FilePath, BOOL CreateIfNotExists) {
	return CreateFile(
		hFile, 
		FilePath, 
		FULL_ACCESS, 
		FILE_ATTRIBUTE_NORMAL, 
		FULL_SHARED_ACCESS, 
		CreateIfNotExists ? FILE_OPEN_IF : FILE_OPEN, 
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	);
}

NTSTATUS AppendFile(OUT PHANDLE hFile, LPWSTR FilePath, BOOL CreateIfNotExists) {
	return CreateFile(
		hFile,
		FilePath,
		FILE_APPEND_DATA,
		FILE_ATTRIBUTE_NORMAL,
		FULL_SHARED_ACCESS,
		CreateIfNotExists ? FILE_OPEN_IF : FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
	);
}

NTSTATUS CreateDirectory(LPWSTR DirPath) {
	HANDLE hDir = 0;
	NTSTATUS Status = CreateFile(&hDir, DirPath, SYNCHRONIZE, FILE_ATTRIBUTE_DIRECTORY, NON_SHARED_ACCESS, FILE_CREATE, FILE_DIRECTORY_FILE);
	if (SUCCESS_FILE_OPERATION(Status, hDir)) CloseFile(hDir);
	return Status;
}


BOOL FileObjectExists(LPWSTR Path, BOOL IsDirectory) {
	HANDLE hObject;
	
	NTSTATUS Status;
	if (IsDirectory) {
		Status = CreateFile(&hObject, Path, SYNCHRONIZE, FILE_ATTRIBUTE_DIRECTORY, FULL_SHARED_ACCESS, FILE_OPEN, FILE_DIRECTORY_FILE);
	} else {
		Status = CreateFile(&hObject, Path, SYNCHRONIZE, FILE_ATTRIBUTE_NORMAL, FULL_SHARED_ACCESS, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
	}

	BOOL ExistingStatus = SUCCESS_FILE_OPERATION(Status, hObject);
	if (ExistingStatus) CloseFile(hObject);

	return ExistingStatus;
}

BOOL FileExists(LPWSTR FilePath) {
	return FileObjectExists(FilePath, FALSE);
}

BOOL DirectoryExists(LPWSTR DirectoryPath) {
	return FileObjectExists(DirectoryPath, TRUE);
}



LONGLONG GetFileSize(LPWSTR FilePath) {
	HANDLE hFile;
	NTSTATUS CreationStatus = CreateFile(&hFile, FilePath, SYNCHRONIZE, FILE_ATTRIBUTE_NORMAL, FULL_SHARED_ACCESS, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
	if (!SUCCESS_FILE_OPERATION(CreationStatus, hFile)) return 0;
	
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_STANDARD_INFORMATION FileInfo;

	NTSTATUS Status = ZwQueryInformationFile(hFile, &IoStatusBlock, &FileInfo, sizeof(FileInfo), FileStandardInformation);
	CloseFile(hFile);

	return NT_SUCCESS(Status) ? FileInfo.EndOfFile.QuadPart : 0;
}



NTSTATUS MoveFileObject(LPWSTR OldFilePath, LPWSTR NewFilePath, BOOLEAN ReplaceIfExists, BOOL IsDirectory) {
	HANDLE hFile;
	NTSTATUS CreationStatus;

	if (IsDirectory) {
		CreationStatus = CreateFile(&hFile, OldFilePath, DELETE, FILE_ATTRIBUTE_DIRECTORY, NON_SHARED_ACCESS, FILE_OPEN, FILE_DIRECTORY_FILE);
	} else {
		CreationStatus = CreateFile(&hFile, OldFilePath, DELETE, FILE_ATTRIBUTE_NORMAL, NON_SHARED_ACCESS, FILE_OPEN, FILE_NON_DIRECTORY_FILE);
	}
	if (!SUCCESS_FILE_OPERATION(CreationStatus, hFile)) return CreationStatus;

	// Формируем Nt-путь к новому файлу:
	LPWSTR NewFileNativePath;
	ULONG FileNameLength = (ULONG)GetNtPath(NewFilePath, &NewFileNativePath);
	ULONG FileNameLengthInBytes = FileNameLength * sizeof(WCHAR); // Размер строки в байтах без учёта нуль-терминатора

	ULONG FileRenameInformationSize = sizeof(FILE_RENAME_INFORMATION) + FileNameLengthInBytes; // Размер структуры в байтах с учётом нуль-терминированной строки
	
	PFILE_RENAME_INFORMATION pFileRenameInformation = GetMem(FileRenameInformationSize);
	pFileRenameInformation->ReplaceIfExists = ReplaceIfExists;
	pFileRenameInformation->RootDirectory   = NULL;
	pFileRenameInformation->FileNameLength  = FileNameLengthInBytes; // Размер нового имени в БАЙТАХ без нуль-терминатора (!)
	SafeStrCpyW(pFileRenameInformation->FileName, FileNameLengthInBytes + sizeof(WCHAR), NewFileNativePath);

	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = ZwSetInformationFile(hFile, &IoStatusBlock, pFileRenameInformation, FileRenameInformationSize, FileRenameInformation);

	FreeString(NewFileNativePath);
	FreeMem(pFileRenameInformation);
	CloseFile(hFile);

	return Status;
}

NTSTATUS MoveFile(LPWSTR OldFileName, LPWSTR NewFileName, BOOLEAN ReplaceIfExists) {
	return MoveFileObject(OldFileName, NewFileName, ReplaceIfExists, FALSE);
}

NTSTATUS MoveDirectory(LPWSTR OldDirectoryName, LPWSTR NewDirectoryName, BOOLEAN ReplaceIfExists) {
	return MoveFileObject(OldDirectoryName, NewDirectoryName, ReplaceIfExists, TRUE);
}

NTSTATUS RenameFile(LPWSTR OldFileName, LPWSTR NewFileName, BOOLEAN ReplaceIfExists) {
	return MoveFileObject(OldFileName, NewFileName, ReplaceIfExists, FALSE);
}

NTSTATUS RenameDirectory(LPWSTR OldDirectoryName, LPWSTR NewDirectoryName) {
	return MoveFileObject(OldDirectoryName, NewDirectoryName, FALSE, TRUE);
}



NTSTATUS DeleteFileObject(LPWSTR Path) {
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING    NativePath;
	LPWSTR            NtPath;

	InitUnicodeNtPath(Path, &NativePath, &NtPath);
	InitializeObjectAttributes(&ObjectAttributes, &NativePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS Status = ZwDeleteFile(&ObjectAttributes);
	FreeUnicodeNtPath(NtPath);

	return Status;
}

NTSTATUS DeleteFile(LPWSTR FilePath) {
	return DeleteFileObject(FilePath);
}

NTSTATUS DeleteDirectory(LPWSTR DirectoryPath) {
	return DeleteFileObject(DirectoryPath);
}



NTSTATUS ReadFile(HANDLE hFile, PVOID Buffer, ULONG Size, IN OPTIONAL PLARGE_INTEGER Offset, OUT OPTIONAL PULONG BytesRead) {
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, Size, Offset, NULL);
	if (BytesRead != NULL) *BytesRead = (ULONG)IoStatusBlock.Information;
	return Status;
}

NTSTATUS WriteFile(HANDLE hFile, PVOID Buffer, ULONG Size, IN OPTIONAL PLARGE_INTEGER Offset, OUT OPTIONAL PULONG BytesWritten) {
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status = ZwWriteFile(hFile, 0, NULL, NULL, &IoStatusBlock, Buffer, Size, Offset, NULL);
	if (BytesWritten != NULL) *BytesWritten = (ULONG)IoStatusBlock.Information;
	return Status;
}



NTSTATUS CopyFile(LPWSTR SrcFile, LPWSTR DestFile) {
	HANDLE hSrcFile, hDestFile;
	NTSTATUS SrcOpeningStatus = OpenFile(&hSrcFile, SrcFile, FALSE);
	if (!SUCCESS_FILE_OPERATION(SrcOpeningStatus, hSrcFile)) return SrcOpeningStatus;

	NTSTATUS DestCreationStatus = CreateEmptyFile(&hDestFile, DestFile);
	if (!SUCCESS_FILE_OPERATION(DestCreationStatus, hDestFile)) {
		CloseFile(hSrcFile);
		return DestCreationStatus;
	}

	const ULONG BufferSize = 524288;
	PVOID Buffer = GetMem(BufferSize);

	ULONG BytesRead, BytesWritten;

	do {
		ReadFile(hSrcFile, Buffer, BufferSize, NULL, &BytesRead);
		WriteFile(hDestFile, Buffer, BytesRead, NULL, &BytesWritten);
	} while (BytesRead > 0);

	FreeMem(Buffer);

	CloseFile(hSrcFile);
	CloseFile(hDestFile);

	return STATUS_SUCCESS;
}
