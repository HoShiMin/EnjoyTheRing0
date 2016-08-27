#include "ShellCode.h"

// Отключаем выравнивание:
#pragma pack(push, 1)
typedef struct _SHELL_CODE_ARGUMENTS {
	PVOID GetProcAddress;
	PVOID InputData;
	PVOID OutputData;
	ULONG InputDataSize;
	ULONG OutputDataSize;
} SHELL_CODE_ARGUMENTS, *PSHELL_CODE_ARGUMENTS;
#pragma pack(pop)

// Прототип шелл-функции:
typedef SIZE_T(__stdcall *_ShellProc)(PSHELL_CODE_ARGUMENTS Arguments);

// Дескриптор подготовленной для шелла памяти:
typedef struct _MEMORY_DESCRIPTOR {
	PVOID UsermodeMemory;
	PVOID PreparedMemory;
	PMDL  Mdl;
	ULONG Size;
	USERMODE_MEMORY_ACCESS AccessMethod;
} MEMORY_DESCRIPTOR, *PMEMORY_DESCRIPTOR;

// Подготовка юзермодной памяти для работы в ядре:
BOOL FASTCALL PrepareUsermodeMemory(PUM_MEMORY_INFO UmMemoryInfo, PMEMORY_DESCRIPTOR MemoryDescriptor) {
	if ((UmMemoryInfo == NULL) && (MemoryDescriptor == NULL)) return FALSE;
	
	RtlZeroMemory(MemoryDescriptor, sizeof(MEMORY_DESCRIPTOR));
	MemoryDescriptor->AccessMethod = UmMemoryInfo->AccessMethod;
	MemoryDescriptor->UsermodeMemory = UmMemoryInfo->Address;
	MemoryDescriptor->Size = UmMemoryInfo->Size;

	if (MemoryDescriptor->AccessMethod == UMA_DIRECT_ACCESS) {
		MemoryDescriptor->PreparedMemory = UmMemoryInfo->Address;
		return TRUE;
	} else if ((MemoryDescriptor->UsermodeMemory == NULL) || (MemoryDescriptor->Size == 0)) {
		return FALSE;
	}

	switch (MemoryDescriptor->AccessMethod) {
		case UMA_ALLOC_KERNEL_MEMORY:
			MemoryDescriptor->PreparedMemory = GetMem(MemoryDescriptor->Size);
			break;

		case UMA_MAP_USERMODE_MEMORY:
			MemoryDescriptor->PreparedMemory = MapVirtualMemory(
				PsGetCurrentProcessId(),
				MemoryDescriptor->UsermodeMemory,
				NULL,
				MemoryDescriptor->Size,
				KernelMode,
				&MemoryDescriptor->Mdl
			);
			break;
	}

	return MemoryDescriptor->PreparedMemory != NULL;
}

// Освобождение подготовленной памяти:
VOID FASTCALL FreePreparedMemory(PMEMORY_DESCRIPTOR MemoryDescriptor) {
	if (MemoryDescriptor == NULL) return;
	if (MemoryDescriptor->AccessMethod == UMA_DIRECT_ACCESS) return;
	if (MemoryDescriptor->PreparedMemory == NULL) return;

	switch (MemoryDescriptor->AccessMethod) {
		case UMA_ALLOC_KERNEL_MEMORY:
			FreeMem(MemoryDescriptor->PreparedMemory);
			break;

		case UMA_MAP_USERMODE_MEMORY:
			if (MemoryDescriptor->Mdl == NULL) 
				UnmapVirtualMemory(MemoryDescriptor->Mdl, MemoryDescriptor->PreparedMemory);
			break;
	}

	RtlZeroMemory(MemoryDescriptor, sizeof(MEMORY_DESCRIPTOR));
}

// Тип буфера (входной\выходной):
typedef enum _SHELL_IO_BUFFER_TYPE {
	ShellInputBuffer,
	ShellOutputBuffer
} SHELL_IO_BUFFER_TYPE, *PSHELL_IO_BUFFER_TYPE;

// Подготовка буферов со входными и выходными данными:
BOOL FASTCALL PrepareIoBuffer(
	IN OPTIONAL PUM_MEMORY_INFO MemoryInfo, 
	IN PMEMORY_DESCRIPTOR MemoryDescriptor,
	SHELL_IO_BUFFER_TYPE ShellBufferType
) {
	if (MemoryDescriptor == NULL) return FALSE;
	RtlZeroMemory(MemoryDescriptor, sizeof(MEMORY_DESCRIPTOR));
	if (MemoryInfo == NULL) return TRUE;

	// Проверяем, что переданная из юзермода информация о памяти доступна для чтения:
	if (!IsUsermodeMemoryReadable(MemoryInfo, sizeof(UM_MEMORY_INFO), NON_ALIGNED)) return FALSE;

	if ((MemoryInfo->AccessMethod != UMA_DIRECT_ACCESS) && (MemoryInfo->Size == 0)) return FALSE;

	// Проверяем, что входной и выходной буферы доступны для чтения\записи:
	switch (ShellBufferType) {
		case ShellInputBuffer:
			if (!IsUsermodeMemoryReadable(MemoryInfo->Address, MemoryInfo->Size, NON_ALIGNED)) return FALSE;
			break;

		case ShellOutputBuffer:
			if (!IsUsermodeMemoryWriteable(MemoryInfo->Address, MemoryInfo->Size, NON_ALIGNED)) return FALSE;
			break;
	}

	// Готовим буфер для работы в ядре:
	return PrepareUsermodeMemory(MemoryInfo, MemoryDescriptor);
}

// Исполнялка шеллов:
SHELL_STATUS ExecuteShell(
	IN PVOID EntryPoint,
	IN PUM_MEMORY_INFO CodeBlock,
	IN OPTIONAL PUM_MEMORY_INFO InputData,
	IN OPTIONAL PUM_MEMORY_INFO OutputData,
	IN OPTIONAL PSIZE_T Result
) {
	// Проверяем валидность переданных аргументов:
	if (CodeBlock == NULL) return SHELL_INVALID_CODE_ADDRESS;
	if (CodeBlock->Address == NULL) return SHELL_INVALID_CODE_ADDRESS;
#pragma warning(suppress: 4305)
	if ((EntryPoint < CodeBlock->Address) || (EntryPoint >= (PVOID)((PBYTE)CodeBlock->Address + CodeBlock->Size))) return SHELL_INVALID_CODE_ADDRESS;

	// Готовим память под код:
	MEMORY_DESCRIPTOR CodeMemory;
	if (PrepareUsermodeMemory(CodeBlock, &CodeMemory)) {
		if (CodeMemory.AccessMethod == UMA_ALLOC_KERNEL_MEMORY)
			RtlCopyMemory(CodeMemory.PreparedMemory, CodeMemory.UsermodeMemory, CodeMemory.Size);
	} else {
		return SHELL_CODE_BUFFER_ERROR;
	}

	// Определяем дескрипторы входного и выходного буферов:
	MEMORY_DESCRIPTOR InputMemory, OutputMemory;

	BOOL InputPreparingStatus = InputData == NULL;
	BOOL OutputPreparingStatus = OutputData == NULL;

	// Готовим входной и выходной буферы:
	if (InputData) {
		InputPreparingStatus = PrepareIoBuffer(InputData, &InputMemory, ShellInputBuffer);
	} else {
		RtlZeroMemory(&InputMemory, sizeof(MEMORY_DESCRIPTOR));
	}

	if (OutputData) {
		OutputPreparingStatus = PrepareIoBuffer(OutputData, &OutputMemory, ShellOutputBuffer);
	} else {
		RtlZeroMemory(&OutputMemory, sizeof(MEMORY_DESCRIPTOR));
	}

	// Проверяем, успешно ли подготовили буферы:
	if (InputPreparingStatus && OutputPreparingStatus) {
		// Если используем выделение памяти в ядре - копируем входные данные в промежуточный буфер:
		if (InputMemory.AccessMethod == UMA_ALLOC_KERNEL_MEMORY)
			RtlCopyMemory(InputMemory.PreparedMemory, InputMemory.UsermodeMemory, InputMemory.Size);
	} else {
		FreePreparedMemory(&CodeMemory);
		FreePreparedMemory(&InputMemory);
		FreePreparedMemory(&OutputMemory);
		return InputPreparingStatus ? SHELL_OUTPUT_BUFFER_ERROR : SHELL_INPUT_BUFFER_ERROR;
	}

	// Заполняем структуру, передаваемую шеллкоду:
	SHELL_CODE_ARGUMENTS ShellArguments;
#pragma warning(suppress: 4152)
	ShellArguments.GetProcAddress = &GetKernelProcAddress;
	ShellArguments.InputData      = InputMemory.PreparedMemory;
	ShellArguments.OutputData     = OutputMemory.PreparedMemory;
	ShellArguments.InputDataSize  = InputMemory.Size;
	ShellArguments.OutputDataSize = OutputMemory.Size;

	// Сохраняем состояние FPU:
	KFLOATING_SAVE FPUState;
	if NT_ERROR(KeSaveFloatingPointState(&FPUState)) {
		FreePreparedMemory(&CodeMemory);
		FreePreparedMemory(&InputMemory);
		FreePreparedMemory(&OutputMemory);
		return SHELL_SAVING_FPU_STATE_ERROR;
	}

	// Отключаем SMEP и защиту от записи:
	GlobalDisableSmepSmap();
	GlobalDisableWriteProtection();

	SHELL_STATUS Status = SHELL_SUCCESS;

	// Выполняем шелл-код:
#pragma warning(suppress: 4305)
	SIZE_T EntryPointOffset = (SIZE_T)EntryPoint - (SIZE_T)CodeBlock->Address;
	_ShellProc ShellProc = (_ShellProc)((SIZE_T)CodeMemory.PreparedMemory + EntryPointOffset);
	__try {
		// Переходим на выполнение шелла:
		SIZE_T ShellResult = ShellProc(&ShellArguments);

		// Возвращаем результат:
		if (Result) {
			if (IsUsermodeMemoryWriteable(Result, sizeof(SIZE_T), NON_ALIGNED)) {
				*Result = ShellResult;
			} else {
				Status = SHELL_INVALID_RETURN_ADDRESS;
			}
		}

		// Возвращаем выходной буфер, если использовался промежуточный буфер в ядре:
		if ((OutputData) && (OutputMemory.AccessMethod == UMA_ALLOC_KERNEL_MEMORY)) 
			RtlCopyMemory(OutputData->Address, OutputMemory.PreparedMemory, OutputData->Size);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = SHELL_RUNTIME_ERROR;
	}

	// Включаем SMEP и защиту от записи:
	GlobalEnableWriteProtection();
	GlobalEnableSmepSmap();

	// Возвращаем состояние FPU:
	KeRestoreFloatingPointState(&FPUState);

	// Освобождаем ресурсы:
	FreePreparedMemory(&CodeMemory);
	FreePreparedMemory(&InputMemory);
	FreePreparedMemory(&OutputMemory);

	return Status;
}