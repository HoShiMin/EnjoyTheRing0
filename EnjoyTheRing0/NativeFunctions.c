#include "MemoryUtils.h"
#include "NativeFunctions.h"

PTSS GetTSSPointer(OUT OPTIONAL PULONG TSSLimit) {	
	TR TaskRegister;
	GDTR GDTRegister;

	IdtGdtTrOperation(STR, &TaskRegister);
	IdtGdtTrOperation(SGDT, &GDTRegister);

	PGDTENTRY TSSDescriptor = GDTRegister.Base + TaskRegister.SelectorIndex;

	if (TSSLimit) *TSSLimit = ExtractLimitFromGdtEntry(TSSDescriptor);
	return ExtractBaseFromGdtEntry(TSSDescriptor);	
}

