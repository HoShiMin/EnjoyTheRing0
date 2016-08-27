#include "Protection.h"

typedef struct _PROTECTED_PROCESS_ENTRY {
	HANDLE ProcessId;
	HANDLE DefenderId;
} PROTECTED_PROCESS_ENTRY, *PPROTECTED_PROCESS_ENTRY;

typedef struct _PROTECTION_INFO {
	BOOL		IsInitialized;
	PVOID		ProcessesCallbackHandle;
	PVOID		ThreadsCallbackHandle;
	LINKED_LIST ProtectedProcesses;
} PROTECTION_INFO, *PPROTECTION_INFO;

static PROTECTION_INFO ProtectionInfo = { FALSE };

VOID FORCEINLINE FASTCALL SetRights(POB_PRE_OPERATION_INFORMATION OperationInformation, ACCESS_MASK Rights) {
	OperationInformation->Parameters->CreateHandleInformation.DesiredAccess    &= Rights;
	OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= Rights;
}

OB_PREOP_CALLBACK_STATUS NTAPI PreOpenCallback(IN PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (ProtectionInfo.ProtectedProcesses.EntriesCount == 0) return OB_PREOP_SUCCESS;

	if (OperationInformation->ObjectType == *PsProcessType) {
		HANDLE ProcessId = GetProcessId((PEPROCESS)OperationInformation->Object);
		if (IsProcessProtected(ProcessId, ANY_PROCESS) != PROCESS_PROTECTED) return OB_PREOP_SUCCESS;
		SetRights(OperationInformation, (ACCESS_MASK)~DEFENCE_SUMMARY_PROCESSES_FLAGS);
	}

	if (OperationInformation->ObjectType == *PsThreadType) {
		HANDLE ProcessId = GetProcessId(PETHREAD2PEPROCESS((PETHREAD)OperationInformation->Object));
		if (IsProcessProtected(ProcessId, ANY_PROCESS) != PROCESS_PROTECTED) return OB_PREOP_SUCCESS;
		SetRights(OperationInformation, (ACCESS_MASK)~DEFENCE_SUMMARY_THREADS_FLAGS);
	}
	
	return OB_PREOP_SUCCESS;
}

VOID NTAPI PostOpenCallback(IN PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation) {
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
	return;
}

BOOL RegisterProtection() {
	if (ProtectionInfo.IsInitialized) return TRUE;

	InitializeLinkedList(sizeof(PROTECTED_PROCESS_ENTRY), &ProtectionInfo.ProtectedProcesses, TRUE);

	NTSTATUS ProcessesCallbackStatus = STATUS_SUCCESS; 
	NTSTATUS ThreadsCallbackStatus   = STATUS_SUCCESS;

	// Каллбэк на процессы:
	if (ProtectionInfo.ProcessesCallbackHandle == NULL) {
		HANDLES_NOTIFY_STRUCT NotifyStruct;
		NotifyStruct.ObjectType				= PsProcessType;
		NotifyStruct.Operations				= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		NotifyStruct.PostOperation			= PostOpenCallback;
		NotifyStruct.PreOperation			= PreOpenCallback;
		NotifyStruct.RegistrationContext	= NULL;
		ProcessesCallbackStatus = RegisterHandlesOperationsNotifier(&NotifyStruct, &ProtectionInfo.ProcessesCallbackHandle);
	}

	// Каллбэк на потоки:
	if (ProtectionInfo.ThreadsCallbackHandle == NULL) {
		HANDLES_NOTIFY_STRUCT NotifyStruct;
		NotifyStruct.ObjectType				= PsThreadType;
		NotifyStruct.Operations				= OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		NotifyStruct.PostOperation			= PostOpenCallback;
		NotifyStruct.PreOperation			= PreOpenCallback;
		NotifyStruct.RegistrationContext	= NULL;
		ThreadsCallbackStatus = RegisterHandlesOperationsNotifier(&NotifyStruct, &ProtectionInfo.ThreadsCallbackHandle);
	}

	ProtectionInfo.IsInitialized = ((ProcessesCallbackStatus | ThreadsCallbackStatus) == STATUS_SUCCESS);
	if (!ProtectionInfo.IsInitialized) {
		if (ProtectionInfo.ProcessesCallbackHandle != NULL) 
			UnregisterHandlesOperationsNotifier(ProtectionInfo.ProcessesCallbackHandle);
		
		if (ProtectionInfo.ThreadsCallbackHandle != NULL)
			UnregisterHandlesOperationsNotifier(ProtectionInfo.ThreadsCallbackHandle);
		
		ProtectionInfo.ProcessesCallbackHandle = NULL;
		ProtectionInfo.ThreadsCallbackHandle   = NULL;
	}
	return ProtectionInfo.IsInitialized;
}

VOID UnregisterProtection() {
	if (!ProtectionInfo.IsInitialized) return;

	if (ProtectionInfo.ProcessesCallbackHandle != NULL) 
		UnregisterHandlesOperationsNotifier(ProtectionInfo.ProcessesCallbackHandle);

	if (ProtectionInfo.ThreadsCallbackHandle != NULL) 
		UnregisterHandlesOperationsNotifier(ProtectionInfo.ThreadsCallbackHandle);

	ProtectionInfo.ProcessesCallbackHandle = NULL;
	ProtectionInfo.ThreadsCallbackHandle   = NULL;

	ClearProtectedProcessesList();
	
	ProtectionInfo.IsInitialized = FALSE;
}





VOID AddProtectedProcess(HANDLE ProcessId, HANDLE DefenderId) {
	if (!ProtectionInfo.IsInitialized) return;

	PPROTECTED_PROCESS_ENTRY Process;
	PROTECTION_STATUS ProtectionStatus = IsProcessProtected(ProcessId, DefenderId);
	
	switch (ProtectionStatus) {
	case PROCESS_NOT_PROTECTED: 
	case DEFENDER_NOT_FOUND:
		AddLinkedListEntry(&ProtectionInfo.ProtectedProcesses);
		Process = (PPROTECTED_PROCESS_ENTRY)GetLLDataPtr(ProtectionInfo.ProtectedProcesses.LastEntry);
		Process->ProcessId = ProcessId;
		Process->DefenderId = DefenderId;
	}
}



typedef struct _REMOVE_PROCESS_INFO {
	HANDLE ProcessId;
	HANDLE DefenderId;
} REMOVE_PROCESS_INFO, *PREMOVE_PROCESS_INFO;

LINKED_LIST_ACTION FASTCALL RemoveProcessCallback(PPROTECTED_PROCESS_ENTRY Entry, PREMOVE_PROCESS_INFO ProcessInfo) {
	BOOL NeedToDelete = ((Entry->ProcessId == ProcessInfo->ProcessId) && (Entry->DefenderId == ProcessInfo->DefenderId))		||
						((ProcessInfo->ProcessId == ANY_PROCESS) && (ProcessInfo->DefenderId == ANY_PROCESS))				||
						((Entry->ProcessId == ProcessInfo->ProcessId) && (ProcessInfo->DefenderId == ANY_PROCESS))			||
						((ProcessInfo->ProcessId == ANY_PROCESS) && (Entry->DefenderId == ProcessInfo->DefenderId));
	
	return NeedToDelete ? LL_REMOVE : LL_CONTINUE;
}

VOID RemoveProtectedProcess(HANDLE ProcessId, HANDLE DefenderId) {
	if (!ProtectionInfo.IsInitialized) return;

	REMOVE_PROCESS_INFO ProcessInfo;
	ProcessInfo.ProcessId = ProcessId;
	ProcessInfo.DefenderId = DefenderId;
	ForEachLinkedListElement(&ProtectionInfo.ProtectedProcesses, &RemoveProcessCallback, &ProcessInfo);
}



typedef struct _FIND_PROCESS_INFO {
	HANDLE ProcessId;
	HANDLE DefenderId;
	BOOL ProcessFound;
	BOOL DefenderFound;
} FIND_PROCESS_INFO, *PFIND_PROCESS_INFO;

LINKED_LIST_ACTION FASTCALL FindProcessCallback(PPROTECTED_PROCESS_ENTRY Entry, PFIND_PROCESS_INFO ProcessInfo) {
	if (Entry->ProcessId == ProcessInfo->ProcessId) {
		ProcessInfo->ProcessFound = TRUE;
		if ((ProcessInfo->DefenderId == ANY_PROCESS) || (Entry->DefenderId == ProcessInfo->DefenderId)) {
			ProcessInfo->DefenderFound = TRUE;
			return LL_BREAK;
		}
	}
	return LL_CONTINUE;
}


PROTECTION_STATUS IsProcessProtected(HANDLE ProcessId, HANDLE DefenderId) {
	if (!ProtectionInfo.IsInitialized) return PROCESS_NOT_PROTECTED;

	// Перебираем все процессы:
	FIND_PROCESS_INFO ProcessInfo;
	ProcessInfo.ProcessId     = ProcessId;
	ProcessInfo.DefenderId    = DefenderId;
	ProcessInfo.ProcessFound  = FALSE;
	ProcessInfo.DefenderFound = FALSE;
	ForEachLinkedListElement(&ProtectionInfo.ProtectedProcesses, &FindProcessCallback, &ProcessInfo);
	if (ProcessInfo.ProcessFound && ProcessInfo.DefenderFound) return PROCESS_PROTECTED;
	if (ProcessInfo.ProcessFound) return DEFENDER_NOT_FOUND;
	return PROCESS_NOT_PROTECTED;
}



VOID ClearProtectedProcessesList() {
	if (!ProtectionInfo.IsInitialized) return;
	ClearLinkedList(&ProtectionInfo.ProtectedProcesses);
}



LINKED_LIST_ACTION FASTCALL PrintProtectedProcessesCallback(PPROTECTED_PROCESS_ENTRY Entry, PVOID Argument) {
	UNREFERENCED_PARAMETER(Argument);
	DbgPrint("  - DefenderId: %d, ProcessId: %d\r\n", Entry->DefenderId, Entry->ProcessId);
	return LL_CONTINUE;
}

VOID PrintProtectedProcessesList() {
	if (!ProtectionInfo.IsInitialized) return;
	DbgPrint(":: Protected processes:\r\n");
	ForEachLinkedListElement(&ProtectionInfo.ProtectedProcesses, &PrintProtectedProcessesCallback, NULL);
	DbgPrint(":: End of protected processes list\r\n");
}