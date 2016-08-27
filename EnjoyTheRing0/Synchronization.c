#include "Synchronization.h"

typedef VOID NTKERNELAPI	(FASTCALL *_InitializeGuardedMutex)		(PKGUARDED_MUTEX GuardedMutex);
typedef VOID NTKERNELAPI	(FASTCALL *_AcquireGuardedMutex)		(PKGUARDED_MUTEX GuardedMutex);
typedef VOID NTKERNELAPI	(FASTCALL *_ReleaseGuardedMutex)		(PKGUARDED_MUTEX GuardedMutex);
typedef BOOLEAN NTKERNELAPI (FASTCALL *_TryToAcquireGuardedMutex)	(PKGUARDED_MUTEX GuardedMutex);

static _InitializeGuardedMutex		InitializeGuardedMutex		= NULL;
static _AcquireGuardedMutex			AcquireGuardedMutex			= NULL;
static _ReleaseGuardedMutex			ReleaseGuardedMutex			= NULL;
static _TryToAcquireGuardedMutex	TryToAcquireGuardedMutex	= NULL;

static volatile BOOL IsSynchronizationInitialized = FALSE;
static volatile BOOL GuardedSupport = FALSE;

VOID InitUniversalMutexFunctions() {
#pragma warning(push)
#pragma warning(disable: 4055)
#pragma warning(disable: 4047)
	InitializeGuardedMutex		= (_InitializeGuardedMutex)		GetKernelProcAddress(L"KeInitializeGuardedMutex");
	AcquireGuardedMutex			= (_AcquireGuardedMutex)		GetKernelProcAddress(L"KeAcquireGuardedMutex");
	ReleaseGuardedMutex			= (_ReleaseGuardedMutex)		GetKernelProcAddress(L"KeReleaseGuardedMutex");
	TryToAcquireGuardedMutex	= (_TryToAcquireGuardedMutex)	GetKernelProcAddress(L"KeTryToAcquireGuardedMutex");

	GuardedSupport =	((SIZE_T)InitializeGuardedMutex & (SIZE_T)AcquireGuardedMutex & 
						(SIZE_T)ReleaseGuardedMutex & (SIZE_T)TryToAcquireGuardedMutex) != NULL;
#pragma warning(pop)
	IsSynchronizationInitialized = TRUE;
}

BOOL FORCEINLINE FASTCALL IsLockedBy(PMUTEX Mutex, PETHREAD Thread) {
	return Mutex->LockedByThread == Thread;
}

VOID FORCEINLINE FASTCALL LockLegacyMutex(PRKMUTEX Mutex, BOOL UserThread) {
	KeWaitForMutexObject(Mutex, UserThread ? UserRequest : Executive, KernelMode, FALSE, NULL);
}

VOID InitializeMutex(PMUTEX Mutex, BOOL IsUserThread) {
	if (!IsSynchronizationInitialized) InitUniversalMutexFunctions();
	
	ZeroMemory(Mutex, sizeof(MUTEX));

	if (GuardedSupport) {
		InitializeGuardedMutex(&Mutex->Mutex);	
	} else {
		KeInitializeMutex(&Mutex->LegacyMutex, 0);
		Mutex->UserThread = IsUserThread;
	}
}

VOID AcquireLock(PMUTEX Mutex) {
	if (GuardedSupport) {
		PETHREAD CurrentThread = PsGetCurrentThread();

		if (IsLockedBy(Mutex, CurrentThread)) {
			Mutex->LocksCount++;
			return;
		}

		AcquireGuardedMutex(&Mutex->Mutex);
		Mutex->LockedByThread = CurrentThread;
		Mutex->LocksCount = 1;
	} else {
		LockLegacyMutex(&Mutex->LegacyMutex, Mutex->UserThread);
	}
}

VOID ReleaseLock(PMUTEX Mutex) {
	if (GuardedSupport) {
		if (IsLockedBy(Mutex, PsGetCurrentThread())) {
			Mutex->LocksCount--;
			if (Mutex->LocksCount == 0) {
				Mutex->LockedByThread = NULL;
				ReleaseGuardedMutex(&Mutex->Mutex);
			}
		}
	} else {
		KeReleaseMutex(&Mutex->LegacyMutex, FALSE);
	}
}

BOOL IsMutexLocked(PMUTEX Mutex) {
	BOOL IsLocked;
	if (GuardedSupport) {
		IsLocked = TryToAcquireGuardedMutex(&Mutex->Mutex);
		if (IsLocked) ReleaseGuardedMutex(&Mutex->Mutex);
	} else {
		IsLocked = KeReadStateMutex(&Mutex->LegacyMutex) != 1;
	}
	return IsLocked;
}



VOID WaitMutex(PMUTEX Mutex) {
	if (GuardedSupport) {
		if (IsLockedBy(Mutex, PsGetCurrentThread())) return;
		AcquireLock(Mutex);
		ReleaseLock(Mutex);
	} else {
		LockLegacyMutex(&Mutex->LegacyMutex, Mutex->UserThread);
		KeReleaseMutex(&Mutex->LegacyMutex, TRUE);
	}
}

