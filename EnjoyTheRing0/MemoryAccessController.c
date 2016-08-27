#include "MemoryAccessController.h"

static LONG WriteProtectionDisablesCount = 0;
static LONG SmepSmapDisablesCount = 0;

ULONG_PTR NTAPI GlobalDisableWPCallback(IN ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);
	DisableWriteProtection();
	return (ULONG_PTR)NULL;
}

ULONG_PTR NTAPI GlobalEnableWPCallback(IN ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);
	EnableWriteProtection();
	return (ULONG_PTR)NULL;
}

ULONG_PTR NTAPI GlobalDisableSmepSmapCallback(IN ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);
	if (IsSMEPPresent()) DisableSMEP();
	if (IsSMAPPresent()) DisableSMAP();
	return (ULONG_PTR)NULL;
}

ULONG_PTR NTAPI GlobalEnableSmepSmapCallback(IN ULONG_PTR Argument) {
	UNREFERENCED_PARAMETER(Argument);
	if (IsSMEPPresent()) EnableSMEP();
	if (IsSMAPPresent()) EnableSMAP();
	return (ULONG_PTR)NULL;
}

#pragma warning(push)
#pragma warning(disable: 4152)

VOID GlobalDisableWriteProtection() {
	CallIpi(&GlobalDisableWPCallback, NULL);
	InterlockedIncrement(&WriteProtectionDisablesCount);
}

VOID GlobalEnableWriteProtection() {
	if (WriteProtectionDisablesCount == 0) return;
	CallIpi(&GlobalEnableWPCallback, NULL);
	InterlockedDecrement(&WriteProtectionDisablesCount);
}

VOID GlobalDisableSmepSmap() {
	CallIpi(&GlobalDisableSmepSmapCallback, NULL);
	InterlockedIncrement(&SmepSmapDisablesCount);
}

VOID GlobalEnableSmepSmap() {
	if (SmepSmapDisablesCount == 0) return;
	CallIpi(&GlobalEnableSmepSmapCallback, NULL);
	InterlockedDecrement(&SmepSmapDisablesCount);
}

#pragma warning(pop)