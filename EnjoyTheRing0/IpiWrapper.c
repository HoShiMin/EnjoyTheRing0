#include "IpiWrapper.h"

// Указатель на функцию/эмулятор интерпроцессорного прерывания:
typedef VOID (NTAPI *_IpiCaller)(PVOID Function, PVOID Argument);
_IpiCaller IpiCaller = (_IpiCaller)NULL;


typedef VOID (NTAPI *_IpiProc)(IN PVOID Argument);

#pragma warning(push)
#pragma warning(disable: 4055)

VOID NTAPI EmulateIpi(PVOID Function, PVOID Argument) {
	KAFFINITY FullProcessorsAffinity = (KAFFINITY)0;

	ULONG ProcessorsCount = KeNumberProcessors;
	for (ULONG i = 0; i < ProcessorsCount; i++) {
		KAFFINITY CurrentAffinity = (KAFFINITY)(1 << i);
		KeSetSystemAffinityThread(CurrentAffinity);

		((_IpiProc)Function)(Argument);
		FullProcessorsAffinity |= CurrentAffinity;
	}

	KeSetSystemAffinityThread(FullProcessorsAffinity);
}

VOID FASTCALL CallIpi(PVOID Function, PVOID Argument) {
	if (IpiCaller) {
		IpiCaller(Function, Argument);
		return;
	}

	IpiCaller = (_IpiCaller)GetKernelProcAddress(L"KeIpiGenericCall");
	if (IpiCaller) {
		IpiCaller(Function, Argument);
		return;
	}

	IpiCaller = EmulateIpi;
	IpiCaller(Function, Argument);
}

#pragma warning(pop)