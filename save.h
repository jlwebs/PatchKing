#pragma once
#include <windows.h>

bool ImportAndApplyPatches(HWND hwnd, const char *filepath);
bool ExportPatches(const char *filepath, bool asPatchKingFormat);
bool ExportTableToCSV(const char *filepath);
