#include "LinkedLists.h"

VOID FASTCALL InitializeLinkedList(ULONG DataSize, OUT PLINKED_LIST LinkedList, BOOL IsUserThread) {
	InitializeMutex(&LinkedList->Mutex, IsUserThread);
	
	LinkedList->EntrySize		= DataSize + sizeof(LINKED_LIST_ENTRY);
	LinkedList->EntriesCount		= 0;
	LinkedList->LastEntry		= NULL;
	LinkedList->FirstEntry		= NULL;
}


BOOL FASTCALL AddLinkedListEntry(IN PLINKED_LIST LinkedList) {
	AcquireLock(&LinkedList->Mutex);

	// Если элементов ещё нет:
	if (LinkedList->FirstEntry == NULL) {
		LinkedList->FirstEntry = GetMem(LinkedList->EntrySize);
		LinkedList->LastEntry = LinkedList->FirstEntry;
		if (LinkedList->FirstEntry == NULL) goto ReturnFalse;

		LinkedList->FirstEntry->PrevEntry = NULL;
		LinkedList->FirstEntry->NextEntry = NULL;

		goto ReturnTrue;
	}

	// Если есть - добавляем в конец:
	PLINKED_LIST_ENTRY NextEntry = GetMem(LinkedList->EntrySize);
	if (NextEntry == NULL) goto ReturnFalse;

	LinkedList->LastEntry->NextEntry = NextEntry;
	NextEntry->PrevEntry = LinkedList->LastEntry;
	NextEntry->NextEntry = NULL;
	LinkedList->LastEntry = NextEntry;

ReturnTrue:
	LinkedList->EntriesCount++;
	ReleaseLock(&LinkedList->Mutex);
	return TRUE;

ReturnFalse:
	ReleaseLock(&LinkedList->Mutex);
	return FALSE;
}

VOID FASTCALL RemoveLinkedListEntry(IN PLINKED_LIST LinkedList, IN PLINKED_LIST_ENTRY Entry) {
	if ((LinkedList == NULL) || (Entry == NULL)) return;
	
	AcquireLock(&LinkedList->Mutex);

	// Если элемент - единственный:
	if ((Entry->PrevEntry == NULL) && (Entry->NextEntry == NULL)) {
		LinkedList->FirstEntry = NULL;
		LinkedList->LastEntry = NULL;
		goto Exit;
	}

	// Если элемент - первый в списке:
	if (Entry->PrevEntry == NULL) {
		((PLINKED_LIST_ENTRY)Entry->NextEntry)->PrevEntry = NULL;
		LinkedList->FirstEntry = Entry->NextEntry;
	} else {
		((PLINKED_LIST_ENTRY)Entry->PrevEntry)->NextEntry = Entry->NextEntry;
	
		// Если элемент был последним в списке:
		if (Entry->NextEntry == NULL) {
			LinkedList->LastEntry = Entry->PrevEntry;
		} else {
			((PLINKED_LIST_ENTRY)Entry->NextEntry)->PrevEntry = Entry->PrevEntry;
		}
	}

Exit:
	FreeMem(Entry);
	LinkedList->EntriesCount--;
	ReleaseLock(&LinkedList->Mutex);
}

VOID FASTCALL ClearLinkedList(IN PLINKED_LIST LinkedList) {
	if (LinkedList == NULL) return;
	if (LinkedList->EntriesCount == 0) return;

	AcquireLock(&LinkedList->Mutex);

	PLINKED_LIST_ENTRY CurrentEntry = LinkedList->FirstEntry;
	while (CurrentEntry) {
		PLINKED_LIST_ENTRY NextEntry = CurrentEntry->NextEntry;
		FreeMem(CurrentEntry);
		CurrentEntry = NextEntry;
	}

	LinkedList->FirstEntry		= NULL;
	LinkedList->LastEntry		= NULL;
	LinkedList->EntriesCount		= 0;

	ReleaseLock(&LinkedList->Mutex);
}

VOID FASTCALL ForEachLinkedListElement(IN PLINKED_LIST LinkedList, IN _LinkedListCallback Callback, IN PVOID CallbackArgument) {
	if ((LinkedList == NULL) || (Callback == NULL)) return;
	if (LinkedList->EntriesCount == 0) return;

	AcquireLock(&LinkedList->Mutex);

	PLINKED_LIST_ENTRY Entry = LinkedList->FirstEntry;
	while (Entry) {
		PLINKED_LIST_ENTRY NextEntry = Entry->NextEntry;
		LINKED_LIST_ACTION Action = Callback(&Entry->Data, CallbackArgument);
		
		switch (Action) {
		case LL_CONTINUE: goto Continue;
		case LL_BREAK: goto Exit;
		case LL_REMOVE: 
			RemoveLinkedListEntry(LinkedList, Entry); 
			goto Continue;
		case LL_REMOVE | LL_BREAK:
			RemoveLinkedListEntry(LinkedList, Entry);
			goto Exit;
		}

Continue:
		Entry = NextEntry;
	}

Exit:
	ReleaseLock(&LinkedList->Mutex);
	return;
}