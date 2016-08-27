#pragma once

#include "RegistryUtils.h"

NTSTATUS LoadDriver(LPWSTR DriverPath, LPWSTR DriverName);
NTSTATUS UnloadDriver(LPWSTR DriverName);