#pragma once

#include "Synchronization.h"

#pragma warning(push)
#pragma warning(disable: 4200)
typedef struct _LINKED_LIST_ENTRY {
	volatile PVOID	PrevEntry;
	volatile PVOID	NextEntry;
	BYTE	Data[];
} LINKED_LIST_ENTRY, *PLINKED_LIST_ENTRY;
#pragma warning(pop)

typedef struct _LINKED_LIST {
	MUTEX Mutex;
	volatile SIZE_T	EntrySize;
	volatile SIZE_T	EntriesCount;
	volatile PLINKED_LIST_ENTRY	FirstEntry;
	volatile PLINKED_LIST_ENTRY	LastEntry;
} LINKED_LIST, *PLINKED_LIST;

#define GetLLDataPtr(Entry)	(&((Entry)->Data))

typedef enum _LINKED_LIST_ACTION {
	LL_CONTINUE,
	LL_BREAK,
	LL_REMOVE
} LINKED_LIST_ACTION;

typedef LINKED_LIST_ACTION (FASTCALL *_LinkedListCallback)(IN PVOID Element, IN PVOID Argument);

VOID FASTCALL InitializeLinkedList(ULONG DataSize, OUT PLINKED_LIST LinkedList, BOOL IsUserThread);
BOOL FASTCALL AddLinkedListEntry(IN PLINKED_LIST LinkedList);
VOID FASTCALL RemoveLinkedListEntry(IN PLINKED_LIST LinkedList, IN PLINKED_LIST_ENTRY Entry);
VOID FASTCALL ClearLinkedList(IN PLINKED_LIST LinkedList);
VOID FASTCALL ForEachLinkedListElement(IN PLINKED_LIST LinkedList, IN _LinkedListCallback Callback, IN PVOID CallbackArgument);