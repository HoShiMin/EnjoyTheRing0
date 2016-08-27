#pragma once

#include "ProcessesUtils.h"

typedef struct _MUTEX {
	BOOL UserThread;
	volatile LONG LocksCount; // Количество блокировок внутри одного потока
	volatile PETHREAD LockedByThread;
	KGUARDED_MUTEX Mutex;
	KMUTEX LegacyMutex;
} MUTEX, *PMUTEX;

VOID InitializeMutex(PMUTEX Mutex, BOOL IsUserThread);

VOID AcquireLock(PMUTEX Mutex);
VOID ReleaseLock(PMUTEX Mutex);

BOOL IsMutexLocked(PMUTEX Mutex);
VOID WaitMutex(PMUTEX Mutex);