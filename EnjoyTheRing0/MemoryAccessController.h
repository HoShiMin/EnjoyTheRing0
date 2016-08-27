#pragma once

/*
	WriteProtection - Защита от записи в RX-регионы
	SMEP/SMAP - Защита от исполнения неисполняемых страниц (только Intel)
*/

#include "IpiWrapper.h"
#include "NativeFunctions.h"

VOID GlobalDisableWriteProtection();
VOID GlobalEnableWriteProtection();
VOID GlobalDisableSmepSmap();
VOID GlobalEnableSmepSmap();
