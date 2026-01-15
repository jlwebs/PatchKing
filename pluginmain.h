#pragma once

#include "pluginsdk/_plugins.h"
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLUGIN_NAME "Patch King"
#define PLUGIN_VERSION 1
#define PLUG_EXPORT __declspec(dllexport)

extern HWND hwndDlg;
extern int hMenu;
extern int hMenuDisasm;
extern int hMenuDump;
extern int hMenuStack;
extern int pluginHandle;
extern HINSTANCE hInst;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct);
PLUG_EXPORT bool plugstop();
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct);

#ifdef __cplusplus
}
#endif
