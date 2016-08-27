#pragma once

#include "MemoryUtils.h"

#define MAX_CHARS 2147483647 // Максимальное значение DestMaxCharacters

// Выделение памяти под ANSI- и Wide-строки:
LPWSTR AllocWideString(SIZE_T MaxCharactersCount, BOOL AddNullTerminator, OUT OPTIONAL SIZE_T* AllocatedCharacters);
LPSTR  AllocAnsiString(SIZE_T MaxCharactersCount, BOOL AddNullTerminator, OUT OPTIONAL SIZE_T* AllocatedCharacters);

// DestMaxCharacters и MaxCharacters - размер буфера в СИМВОЛАХ с учётом символа для нуль-терминатора

NTSTATUS SafeStrCatA(LPSTR  Dest, SIZE_T DestMaxCharacters, LPSTR  ConcatenateWith);
NTSTATUS SafeStrCatW(LPWSTR Dest, SIZE_T DestMaxCharacters, LPWSTR ConcatenateWith);

NTSTATUS SafeStrCpyA(LPSTR  Dest, SIZE_T DestMaxCharacters, LPSTR  Source);
NTSTATUS SafeStrCpyW(LPWSTR Dest, SIZE_T DestMaxCharacters, LPWSTR Source);

NTSTATUS SafeStrLenA(LPSTR  String, SIZE_T MaxCharacters, PSIZE_T Length);
NTSTATUS SafeStrLenW(LPWSTR String, SIZE_T MaxCharacters, PSIZE_T Length);

// Длина строки в символах без нуль-терминатора:
SIZE_T LengthA(LPSTR  Str);
SIZE_T LengthW(LPWSTR Str);

// Выделение памяти и конкатенация строк, возвращает количество символов в итоговой строке БЕЗ нуль-терминатора;
// память необходимо освобождать с помощью FreeString:
SIZE_T ConcatenateStringsA(LPSTR  SrcString, LPSTR  ConcatenateWith, OUT LPSTR*  ResultString);
SIZE_T ConcatenateStringsW(LPWSTR SrcString, LPWSTR ConcatenateWith, OUT LPWSTR* ResultString);

// Освобождение памяти, выделенной при ConcatenateStrings:
#define FreeString(String) FreeMem(String)