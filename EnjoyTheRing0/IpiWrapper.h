#pragma once

#include "ProcessesUtils.h"

// Вызов KeIpiGenericCall там, где доступно, и эмуляция - где недоступно:
VOID FASTCALL CallIpi(PVOID Function, PVOID Argument);