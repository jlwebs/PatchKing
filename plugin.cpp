#include "plugin.h"
#include "icon_data.h" // Generated header
#include "pluginmain.h"

enum { MENU_PATCHES, MENU_PATCHES_CTX };

// Forward declaration
void OpenPatchWindow();
void ClosePatchWindow();

extern "C" PLUG_EXPORT void CBMENUENTRY(CBTYPE cbType,
                                        PLUG_CB_MENUENTRY *info) {
  switch (info->hEntry) {
  case MENU_PATCHES:
  case MENU_PATCHES_CTX: // Handle context menu click
    OpenPatchWindow();
    break;

  default:
    break;
  }
}

bool pluginInit(PLUG_INITSTRUCT *initStruct) { return true; }

void pluginSetup() {
  // Main Menu
  _plugin_menuaddentry(hMenu, MENU_PATCHES, "Patch King...");

  // Context Menu (Disassembler)
  _plugin_menuaddentry(hMenuDisasm, MENU_PATCHES_CTX, "Patch King");

  // Load Icon from embedded data
  if (sizeof(icon_data) > 0) {
    ICONDATA icon = {0};
    icon.data = (void *)icon_data;
    icon.size = sizeof(icon_data);

    // Set icon for menu items
    _plugin_menuentryseticon(pluginHandle, MENU_PATCHES, &icon);
    _plugin_menuentryseticon(pluginHandle, MENU_PATCHES_CTX, &icon);

    // Set icon for the entire main menu
    _plugin_menuseticon(hMenu, &icon);

    // Set icon for the disasm context menu (关键！)
    _plugin_menuseticon(hMenuDisasm, &icon);
  }
}

bool pluginStop() {
  ClosePatchWindow();
  return true;
}
