#include "PatchWindow.h"
#include "icon_data.h" // For Window Icon
#include "pluginmain.h"
#include "pluginsdk/_scriptapi_module.h"
#include <algorithm>
#include <commctrl.h>
#include <iomanip>

#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#pragma comment(lib, "comctl32.lib")

#define PLUGIN_NAME "Patch King"
#define PATCH_WINDOW_CLASS_NAME "PatchPluginWindowClass"
#define IDC_LIST_PATCHES 1001
#define IDC_EDIT_FILTER_OLD 1002
#define IDC_EDIT_FILTER_NEW 1003

// Menu IDs
#define ID_MENU_REFRESH 2001
#define ID_MENU_DELETE 2002
#define ID_MENU_DISASM 2003
#define ID_MENU_APPLY 2006
#define ID_MENU_RESTORE 2007
#define ID_MENU_LOAD 2008
#define ID_MENU_SAVE 2009
#define ID_MENU_REMOVE_ALL_IN_LIST 2010
#define ID_MENU_TOGGLE_BPS_ALL 2011

std::vector<PatchInfo> g_Patches;    // THE DISPLAYED LIST (Filtered)
std::vector<PatchInfo> g_AllPatches; // THE FULL LIST (Source of truth)

HWND hPatchWindow = NULL;
HWND hList = NULL;
HFONT g_hListFont = NULL;
HWND hFilterEditOld = NULL;
HWND hFilterEditNew = NULL;
HWND hChkInverseOld = NULL;
HWND hChkInverseNew = NULL;
#define ID_CHK_INVERSE_OLD 1005
#define ID_CHK_INVERSE_NEW 1006

WNDPROC oldListWndProc = NULL;
HFONT g_hBoldFont = NULL;

// Forward Declarations
void RefreshPatchList();
void ApplyFilter();
bool ApplyPatch(const PatchInfo &patch);
bool RestorePatch(const PatchInfo &patch);
void ShowContextMenu(HWND hwnd, POINT pt);

// Helper: Check if memory matches bytes
bool IsMemoryMatching(duint addr, const std::vector<unsigned char> &bytes) {
  if (bytes.empty())
    return false;
  std::vector<unsigned char> mem(bytes.size());
  if (!DbgMemRead(addr, mem.data(), bytes.size()))
    return false;
  return mem == bytes;
}

std::string BytesToHex(const std::vector<unsigned char> &bytes) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0)
      ss << " ";
    ss << std::setw(2) << (int)bytes[i];
  }
  return ss.str();
}

void Log(const char *format, ...) {
  char buffer[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  _plugin_logputs(buffer);
}

// Optimization: UTF-8 to ANSI conversion helper
std::string Utf8ToAnsi(const std::string &utf8) {
  if (utf8.empty())
    return "";
  // 1. UTF-8 -> Wide (UTF-16)
  int wLen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
  if (wLen == 0)
    return utf8; // Fail
  std::vector<wchar_t> wBuf(wLen);
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wBuf.data(), wLen);

  // 2. Wide -> ANSI (CP_ACP)
  int aLen =
      WideCharToMultiByte(CP_ACP, 0, wBuf.data(), -1, NULL, 0, NULL, NULL);
  if (aLen == 0)
    return utf8; // Fail
  std::vector<char> aBuf(aLen);
  WideCharToMultiByte(CP_ACP, 0, wBuf.data(), -1, aBuf.data(), aLen, NULL,
                      NULL);

  return std::string(aBuf.data());
}

// Finalized Solution: Official SDK Demands (OSD)
duint FindCorrectOldHead(duint patchAddr,
                         const std::vector<unsigned char> &oldBytes) {
  const DBGFUNCTIONS *funcs = DbgFunctions();
  if (!funcs)
    return patchAddr;

  // Strategy 1: Source Info
  char sourceFile[MAX_PATH] = {0};
  int line = 0;
  if (funcs->GetSourceFromAddr &&
      funcs->GetSourceFromAddr(patchAddr, sourceFile, &line)) {
    duint displacement = 0;
    duint addr = funcs->GetAddrFromLine(sourceFile, line, &displacement);
    if (addr != 0 && addr <= patchAddr) {
      return addr;
    }
  }

  // Strategy 2: DbgEval Expression
  char expr[128];
  bool success = false;
  _set_errno(0);
#ifdef _WIN64
  sprintf(expr, "dis.prev(0x%llX + 1)", (unsigned long long)patchAddr);
#else
  sprintf(expr, "dis.prev(0x%X + 1)", (unsigned int)patchAddr);
#endif

  duint head = DbgEval(expr, &success);
  if (success && head != 0 && head <= patchAddr) {
#ifdef _WIN64
    sprintf(expr, "dis.len(0x%llX)", (unsigned long long)head);
#else
    sprintf(expr, "dis.len(0x%X)", (unsigned int)head);
#endif
    duint len = DbgEval(expr, &success);
    if (success && patchAddr < head + len) {
      return head;
    }
  }

  // Strategy 3: Trace Record
  for (int off = 0; off <= 15; ++off) {
    if (patchAddr < (duint)off)
      break;
    duint test = patchAddr - off;
    if (funcs->GetTraceRecordByteType &&
        funcs->GetTraceRecordByteType(test) == 1) {
      return test;
    }
  }

  return patchAddr;
}

// Sync from debugger to g_AllPatches
void SyncPatchesFromDebugger() {
  const DBGFUNCTIONS *funcs = DbgFunctions();
  if (!funcs || !funcs->PatchEnum) {
    return;
  }

  size_t size = 0;
  if (!funcs->PatchEnum(NULL, &size) || size == 0) {
    g_AllPatches.clear();
    return;
  }

  std::vector<DBGPATCHINFO> dbgPatches(size / sizeof(DBGPATCHINFO));
  if (!funcs->PatchEnum(dbgPatches.data(), &size)) {
    return;
  }

  g_AllPatches.clear();

  // Sort
  std::sort(dbgPatches.begin(), dbgPatches.end(),
            [](const DBGPATCHINFO &a, const DBGPATCHINFO &b) {
              return a.addr < b.addr;
            });

  if (dbgPatches.empty())
    return;

  // Group
  PatchInfo current;
  current.address = dbgPatches[0].addr;
  current.moduleName = dbgPatches[0].mod;
  current.oldBytes.push_back(dbgPatches[0].oldbyte);
  current.newBytes.push_back(dbgPatches[0].newbyte);
  current.active = true;

  auto finalizeGroup = [&](PatchInfo &p) {
    p.head = FindCorrectOldHead(p.address, p.oldBytes);
    BASIC_INSTRUCTION_INFO bInfo;
    DISASM_INSTR dInstr;

    // Disassemble NEW
    DbgDisasmAt(p.head, &dInstr);
    p.disasm = dInstr.instruction;

    // Disassemble OLD
    unsigned char bytes[128] = {0};
    DbgMemRead(p.head, bytes, 120);
    for (size_t k = 0; k < p.oldBytes.size(); ++k) {
      size_t off = (size_t)(p.address + k - p.head);
      if (off < 120)
        bytes[off] = p.oldBytes[k];
    }
    if (funcs && funcs->DisasmFast) {
      funcs->DisasmFast(bytes, p.head, &bInfo);
      p.oldDisasm = bInfo.instruction;
    }
    char comment[MAX_COMMENT_SIZE] = "";
    bool found = false;

    // 1. Try Comment at HEAD (User or Auto if supported)
    // Use DbgGetCommentAt checking for both user and potentially auto comments
    if (DbgGetCommentAt(p.head, comment)) {
      // If it starts with \1, it's auto. x64dbg conventions.
      // We accept it either way.
      found = true;
    }

    // 2. Try Label at HEAD
    if (!found) {
      if (DbgGetLabelAt(p.head, SEG_DEFAULT, comment)) {
        found = true;
      }
    }

    // 3. Address Reference / Operand Analysis
    if (!found) {
      for (int k = 0; k < dInstr.argcount; ++k) {
        duint targetAddr = dInstr.arg[k].value;
        // Ignore small values (likely not pointers)
        if (targetAddr < 0x1000)
          continue;

        char info[MAX_COMMENT_SIZE] = "";

        // 3a. Try Label at Target
        if (DbgGetLabelAt(targetAddr, SEG_DEFAULT, info)) {
          snprintf(comment, MAX_COMMENT_SIZE, "0x%X: \"%s\"",
                   (unsigned int)targetAddr, info);
          found = true;
          break;
        }

        // 3b. Try String at Target
        // CRITICAL FIX: Do NOT try to read strings for Jump/Call targets (Code
        // addresses). Only try string resolution if mnemonic suggests data
        // access (push, mov, lea, etc.) Simple filter: If mnemonic starts with
        // 'j', 'c' (call), 'l' (loop), skip string check. Better: Explicitly
        // check for 'j', 'call', 'loop'.
        char mne[64];
        strncpy(mne, dInstr.instruction, 63); // "push eax" or "ja 0x..."?
        // Wait, dInstr.instruction is part of disassembly text?
        // No, definitions say: char mnemonic[64]; in DISASM_ARG?
        // Check DISASM_INSTR again.
        // In bridgemain.h:
        // typedef struct { ... char instruction[64]; DISASM_ARGTYPE type; ... }
        // DISASM_INSTR; Actually usually the structure has a 'mnemonic' field
        // separate or part of instruction text. But we can parse
        // dInstr.instruction (e.g. "push 0x401000") or just rely on manual
        // check.

        // NOTE: dInstr.instruction contains the full string "mnem op1, op2".
        // We need to check the first word.
        bool isBranch = false;
        if (dInstr.instruction[0] == 'j' || dInstr.instruction[0] == 'J')
          isBranch = true;
        if (_strnicmp(dInstr.instruction, "call", 4) == 0)
          isBranch = true;
        if (_strnicmp(dInstr.instruction, "loop", 4) == 0)
          isBranch = true;

        // If it is a branch, it points to code. Do NOT treat as string.
        if (!isBranch && DbgGetStringAt(targetAddr, info)) {
          // Truncate
          if (strlen(info) > 60)
            strcpy(info + 57, "...");
          snprintf(comment, MAX_COMMENT_SIZE, "0x%X: \"%s\"",
                   (unsigned int)targetAddr, info);
          found = true;
          break;
        }
      }
    }

    // 4. Fallback: Check Patch Address itself
    if (!found && p.address != p.head) {
      if (DbgGetCommentAt(p.address, comment))
        found = true;
      else if (DbgGetLabelAt(p.address, SEG_DEFAULT, comment))
        found = true;
    }

    if (found) {
      char *finalComment = comment;
      if (finalComment[0] == '\1') {
        finalComment++;
      }
      p.comment = Utf8ToAnsi(finalComment);
    }
  };

  for (size_t i = 1; i < dbgPatches.size(); ++i) {
    const auto &dp = dbgPatches[i];
    if (strcmp(dp.mod, current.moduleName.c_str()) == 0 &&
        dp.addr == current.address + current.oldBytes.size()) {
      current.oldBytes.push_back(dp.oldbyte);
      current.newBytes.push_back(dp.newbyte);
    } else {
      finalizeGroup(current);
      g_AllPatches.push_back(current);

      current.address = dp.addr;
      current.moduleName = dp.mod;
      current.oldBytes.clear();
      current.newBytes.clear();
      current.oldBytes.push_back(dp.oldbyte);
      current.newBytes.push_back(dp.newbyte);
      current.oldDisasm.clear();
      current.disasm.clear();
      current.comment.clear();
    }
  }

  if (!dbgPatches.empty()) {
    finalizeGroup(current);
    g_AllPatches.push_back(current);
  }

  // After sync, apply current filter to update g_Patches
  ApplyFilter();
}

void ApplyFilter() {
  char filterBufOld[256] = {0};
  char filterBufNew[256] = {0};

  if (hFilterEditOld)
    GetWindowText(hFilterEditOld, filterBufOld, 255);
  if (hFilterEditNew)
    GetWindowText(hFilterEditNew, filterBufNew, 255);

  bool invOld = (hChkInverseOld &&
                 SendMessage(hChkInverseOld, BM_GETCHECK, 0, 0) == BST_CHECKED);
  bool invNew = (hChkInverseNew &&
                 SendMessage(hChkInverseNew, BM_GETCHECK, 0, 0) == BST_CHECKED);

  std::string fOld = filterBufOld;
  std::string fNew = filterBufNew;

  if (fOld.empty() && fNew.empty()) {
    g_Patches = g_AllPatches;
  } else {
    try {
      std::regex reOld(fOld.empty() ? ".*" : fOld, std::regex::icase);
      std::regex reNew(fNew.empty() ? ".*" : fNew, std::regex::icase);

      g_Patches.clear();
      for (const auto &p : g_AllPatches) {
        bool matchOld = std::regex_search(p.oldDisasm, reOld) ||
                        std::regex_search(p.comment, reOld);
        bool matchNew = std::regex_search(p.disasm, reNew);

        bool passOld = true;
        if (!fOld.empty()) {
          passOld = invOld ? !matchOld : matchOld;
        }

        bool passNew = true;
        if (!fNew.empty()) {
          passNew = invNew ? !matchNew : matchNew;
        }

        if (passOld && passNew) {
          g_Patches.push_back(p);
        }
      }
    } catch (...) {
      g_Patches = g_AllPatches;
    }
  }
}

// Only refreshes the ListView using g_Patches (which should be already
// filtered)
void UpdateListView() {
  if (!hList)
    return;
  // Restore selection and scrolling? For now simple redraw
  int topIndex = ListView_GetTopIndex(hList);
  int selected = ListView_GetNextItem(hList, -1, LVNI_SELECTED);

  ListView_DeleteAllItems(hList);

  LVITEM lvItem;
  lvItem.mask = LVIF_TEXT | LVIF_PARAM;

  for (int i = 0; i < (int)g_Patches.size(); ++i) {
    const auto &patch = g_Patches[i];

    std::stringstream ssAddr;
    ssAddr << std::hex << std::uppercase << patch.address;
    std::string addrStr = ssAddr.str();

    lvItem.iItem = i;
    lvItem.iSubItem = 0;
    lvItem.pszText = (LPSTR)addrStr.c_str();
    lvItem.lParam = (LPARAM)i; // Store index into g_Patches
    ListView_InsertItem(hList, &lvItem);

    std::string oldBytesStr = BytesToHex(patch.oldBytes);
    ListView_SetItemText(hList, i, 1, (LPSTR)oldBytesStr.c_str());

    std::string newBytesStr = BytesToHex(patch.newBytes);
    ListView_SetItemText(hList, i, 2, (LPSTR)newBytesStr.c_str());

    ListView_SetItemText(hList, i, 3, (LPSTR)patch.oldDisasm.c_str());
    ListView_SetItemText(hList, i, 4, (LPSTR)patch.disasm.c_str());
    ListView_SetItemText(hList, i, 5, (LPSTR)patch.comment.c_str());
  }

  // Restore selection if possible (by index)
  if (selected != -1 && selected < (int)g_Patches.size()) {
    ListView_SetItemState(hList, selected, LVIS_SELECTED | LVIS_FOCUSED,
                          LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(hList, selected, FALSE);
  }
}

void RefreshPatchList() {
  SyncPatchesFromDebugger();
  UpdateListView();

  // Force full window redraw to update custom draw states
  // (backgrounds/breakpoints)
  if (hList)
    InvalidateRect(hList, NULL, TRUE);
  if (hPatchWindow)
    InvalidateRect(hPatchWindow, NULL, TRUE);
}

extern "C" __declspec(dllimport) void GuiDisasmAt(duint addr, duint cip);
extern "C" __declspec(dllimport) void GuiUpdateAllViews();
extern "C" __declspec(dllimport) void GuiUpdateDisassemblyView();
extern "C" __declspec(dllimport) void GuiRepaintTableView();

bool ImportAndApplyPatches(const char *filepath);
bool ExportPatches(const char *filepath);
bool GetFileNameFromUser(char *buffer, int maxLen, bool save);

bool ApplyPatch(const PatchInfo &patch) {
  if (patch.newBytes.empty())
    return false;
  const DBGFUNCTIONS *funcs = DbgFunctions();
  return (funcs && funcs->MemPatch)
             ? funcs->MemPatch(patch.address, patch.newBytes.data(),
                               patch.newBytes.size())
             : false;
}

bool RestorePatch(const PatchInfo &patch) {
  if (patch.oldBytes.empty())
    return false;
  const DBGFUNCTIONS *funcs = DbgFunctions();
  return (funcs && funcs->MemPatch)
             ? funcs->MemPatch(patch.address, patch.oldBytes.data(),
                               patch.oldBytes.size())
             : false;
}

void ToggleBreakpoint(duint addr) {
  BPXTYPE bpType = DbgGetBpxTypeAt(addr);
  char cmd[64];

  if (bpType != bp_none) {
    // Breakpoint exists -> Cancel it (bc)
    sprintf(cmd, "bc 0x%X", (unsigned int)addr);
  } else {
    // No breakpoint -> Set it (bp)
    sprintf(cmd, "bp 0x%X", (unsigned int)addr);
  }

  DbgCmdExecDirect(cmd);
  GuiUpdateAllViews();
  GuiUpdateDisassemblyView();
  GuiRepaintTableView(); // Explicit repaint

  // Force redraw of list to update Red highlight immediately
  if (hList)
    InvalidateRect(hList, NULL, TRUE);
}

// --- Menu & Input Helper Functions ---

void ExecuteAction(HWND hwnd, int commandID, int selectedIndex) {
  if (selectedIndex < 0 || selectedIndex >= (int)g_Patches.size())
    return;

  // Auto-advance helper
  auto AutoAdvance = [&]() {
    if (selectedIndex < ListView_GetItemCount(hList) - 1) {
      int next = selectedIndex + 1;
      ListView_SetItemState(hList, next, LVIS_SELECTED | LVIS_FOCUSED,
                            LVIS_SELECTED | LVIS_FOCUSED);
      ListView_EnsureVisible(hList, next, FALSE);
    }
  };

  switch (commandID) {
  case ID_MENU_DISASM:
    GuiDisasmAt(g_Patches[selectedIndex].head,
                g_Patches[selectedIndex].address);
    GuiUpdateAllViews();
    break;
  case ID_MENU_APPLY:
    if (ApplyPatch(g_Patches[selectedIndex])) {
      Log("[PatchMgr] Applied %p\n", g_Patches[selectedIndex].address);
      GuiUpdateAllViews();
      if (hList)
        InvalidateRect(hList, NULL, TRUE); // Redraw
      AutoAdvance();
    }
    break;
  case ID_MENU_RESTORE:
    if (RestorePatch(g_Patches[selectedIndex])) {
      Log("[PatchMgr] Restored %p\n", g_Patches[selectedIndex].address);
      GuiUpdateAllViews();
      if (hList)
        InvalidateRect(hList, NULL, TRUE); // Redraw
      AutoAdvance();
    }
    break;
  case ID_MENU_DELETE:
    if (selectedIndex >= 0 && selectedIndex < (int)g_Patches.size()) {
      g_Patches.erase(g_Patches.begin() + selectedIndex);
      UpdateListView();

      // Restore selection
      int newCount = (int)g_Patches.size();
      if (newCount > 0) {
        int newSel = selectedIndex;
        if (newSel >= newCount)
          newSel = newCount - 1;
        ListView_SetItemState(hList, newSel, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(hList, newSel, FALSE);
      }
    }
    break;
  }
}

void ShowContextMenu(HWND hwnd, POINT pt) {
  HMENU hMenu = CreatePopupMenu();
  AppendMenu(hMenu, MF_STRING, ID_MENU_LOAD, "Import Patch File...\tCtrl+O");
  AppendMenu(hMenu, MF_STRING, ID_MENU_SAVE, "Export Patch File...\tCtrl+S");
  AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
  AppendMenu(hMenu, MF_STRING, ID_MENU_REFRESH, "Refresh\tF5");
  AppendMenu(hMenu, MF_STRING, ID_MENU_REMOVE_ALL_IN_LIST,
             "Remove All in List");

  int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
  if (iItem != -1) {
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, ID_MENU_DISASM,
               "Follow in Disassembler\tEnter");
    AppendMenu(hMenu, MF_STRING, ID_MENU_APPLY, "Apply Patch\tSpace");
    AppendMenu(hMenu, MF_STRING, ID_MENU_RESTORE, "Restore Patch\tEsc");
    AppendMenu(hMenu, MF_STRING, ID_MENU_DELETE, "Hide Entry Now\tDel");
    AppendMenu(hMenu, MF_STRING, 5555, "Toggle Breakpoint\tF2");
    AppendMenu(hMenu, MF_STRING, ID_MENU_TOGGLE_BPS_ALL, "Toggle BPs to All");
  }

  int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y,
                           0, hwnd, NULL);
  DestroyMenu(hMenu);

  if (cmd == 5555 && iItem != -1) {
    ToggleBreakpoint(g_Patches[iItem].head);
  } else if (cmd == ID_MENU_TOGGLE_BPS_ALL) {
    for (const auto &p : g_Patches) {
      ToggleBreakpoint(p.head);
    }
  } else if (cmd != 0) {
    SendMessage(hwnd, WM_COMMAND, cmd, 0);
  }
}

// Subclassed ListView Procedure for Hotkeys
LRESULT CALLBACK PatchListSubclassProc(HWND hwnd, UINT msg, WPARAM wParam,
                                       LPARAM lParam) {
  switch (msg) {
  case WM_KEYDOWN: {
    int iItem = ListView_GetNextItem(hwnd, -1, LVNI_SELECTED);
    bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;

    switch (wParam) {
    case VK_SPACE:
      if (iItem != -1) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_APPLY, 0);
        return 0;
      }
      break;
    case VK_ESCAPE: // Restore = Esc
      if (iItem != -1) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_RESTORE, 0);
        return 0;
      }
      break;
    case VK_RETURN:
      if (iItem != -1) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_DISASM, 0);
        return 0;
      }
      break;
    case VK_DELETE:
      if (iItem != -1) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_DELETE, 0);
        return 0;
      }
      break;
    case VK_F2:
      if (iItem != -1) {
        ToggleBreakpoint(g_Patches[iItem].head);
        return 0;
      }
      break;
    case 'O':
      if (ctrl) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_LOAD, 0);
        return 0;
      }
      break;
    case 'S':
      if (ctrl) {
        SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_SAVE, 0);
        return 0;
      }
      break;
    case VK_F5:
      SendMessage(GetParent(hwnd), WM_COMMAND, ID_MENU_REFRESH, 0);
      return 0;
    }
  } break;
  }
  return CallWindowProc(oldListWndProc, hwnd, msg, wParam, lParam);
}

// Main Window Procedure
LRESULT CALLBACK PatchWndProc(HWND hwnd, UINT msg, WPARAM wParam,
                              LPARAM lParam) {
  switch (msg) {

  case WM_CREATE: {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int editHeight = 35;
    int chkWidth = 70; // Checkbox width (Increased for "Inv")
    int spacing = 5;   // Spacing to avoid text overlap

    int totalWidth = rc.right;
    int halfWidth = totalWidth / 2;

    // Left Group: [Filter Edit Old][Gap][Inv Checkbox]
    // 1. Filter Edit Old
    hFilterEditOld = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0,
        rc.bottom - editHeight, halfWidth - chkWidth - spacing, editHeight,
        hwnd, (HMENU)IDC_EDIT_FILTER_OLD, hInst, NULL);
    SendMessage(hFilterEditOld, EM_SETCUEBANNER, FALSE,
                (LPARAM)L"Filter Old...");

    // 2. Inverse Checkbox Old
    hChkInverseOld =
        CreateWindow("BUTTON", "Inv", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                     halfWidth - chkWidth, rc.bottom - editHeight, chkWidth,
                     editHeight, hwnd, (HMENU)ID_CHK_INVERSE_OLD, hInst, NULL);

    // Right Group: [Filter Edit New][Gap][Inv Checkbox]
    // 3. Filter Edit New
    hFilterEditNew = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        halfWidth, rc.bottom - editHeight, halfWidth - chkWidth - spacing,
        editHeight, hwnd, (HMENU)IDC_EDIT_FILTER_NEW, hInst, NULL);
    SendMessage(hFilterEditNew, EM_SETCUEBANNER, FALSE,
                (LPARAM)L"Filter New...");

    // 4. Inverse Checkbox New
    hChkInverseNew =
        CreateWindow("BUTTON", "Inv", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                     rc.right - chkWidth, rc.bottom - editHeight, chkWidth,
                     editHeight, hwnd, (HMENU)ID_CHK_INVERSE_NEW, hInst, NULL);

    hList = CreateWindowEx(0, WC_LISTVIEW, "",
                           WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
                           0, 0, rc.right, rc.bottom - editHeight, hwnd,
                           (HMENU)IDC_LIST_PATCHES, hInst, NULL);

    ListView_SetExtendedListViewStyle(hList,
                                      LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    // Set Font to 9pt Segoe UI (Compress height)
    HDC hdc = GetDC(hwnd);
    int logPixelsY = GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(hwnd, hdc);
    int height = -MulDiv(9, logPixelsY, 72);
    g_hListFont =
        CreateFont(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                   DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                   DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    SendMessage(hList, WM_SETFONT, (WPARAM)g_hListFont, TRUE);

    oldListWndProc = (WNDPROC)SetWindowLongPtr(hList, GWLP_WNDPROC,
                                               (LONG_PTR)PatchListSubclassProc);

    LVCOLUMN lvc;
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.cx = 170;
    lvc.pszText = (LPSTR) "Address";
    ListView_InsertColumn(hList, 0, &lvc);

    lvc.cx = 120;
    lvc.pszText = (LPSTR) "Old Bytes";
    ListView_InsertColumn(hList, 1, &lvc);

    lvc.cx = 120;
    lvc.pszText = (LPSTR) "New Bytes";
    ListView_InsertColumn(hList, 2, &lvc);

    lvc.cx = 520; // Increased (+60%)
    lvc.pszText = (LPSTR) "Old";
    ListView_InsertColumn(hList, 3, &lvc);

    lvc.cx = 520; // Increased (+60%)
    lvc.pszText = (LPSTR) "New";
    ListView_InsertColumn(hList, 4, &lvc);

    lvc.cx = 320; // Increased (+60%)
    lvc.pszText = (LPSTR) "Comment";
    ListView_InsertColumn(hList, 5, &lvc);
    break;
  }
  case WM_SIZE: {
    RECT rc;
    GetClientRect(hwnd, &rc);
    int editHeight = 35;
    int chkWidth = 70;
    int spacing = 5;
    int halfWidth = rc.right / 2;

    if (hList && hFilterEditOld && hFilterEditNew && hChkInverseOld &&
        hChkInverseNew) {
      SetWindowPos(hList, NULL, 0, 0, rc.right, rc.bottom - editHeight,
                   SWP_NOZORDER);

      // Left Group: [Filter Edit Old][Gap][Inv Checkbox]
      SetWindowPos(hFilterEditOld, NULL, 0, rc.bottom - editHeight,
                   halfWidth - chkWidth - spacing, editHeight, SWP_NOZORDER);
      SetWindowPos(hChkInverseOld, NULL, halfWidth - chkWidth,
                   rc.bottom - editHeight, chkWidth, editHeight, SWP_NOZORDER);

      // Right Group: [Filter Edit New][Gap][Inv Checkbox]
      SetWindowPos(hFilterEditNew, NULL, halfWidth, rc.bottom - editHeight,
                   halfWidth - chkWidth - spacing, editHeight, SWP_NOZORDER);
      SetWindowPos(hChkInverseNew, NULL, rc.right - chkWidth,
                   rc.bottom - editHeight, chkWidth, editHeight, SWP_NOZORDER);
    }
    break;
  }
  case WM_NOTIFY: {
    LPNMHDR pnmh = (LPNMHDR)lParam;
    if (pnmh->idFrom == IDC_LIST_PATCHES) {
      switch (pnmh->code) {
      case NM_DBLCLK: {
        int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
        if (iItem != -1)
          ExecuteAction(hwnd, ID_MENU_DISASM, iItem);
        break;
      }
      case NM_RCLICK: {
        POINT pt;
        GetCursorPos(&pt);
        ShowContextMenu(hwnd, pt);
        break;
      }
      case NM_CUSTOMDRAW: {
        LPNMLVCUSTOMDRAW pnmcd = (LPNMLVCUSTOMDRAW)lParam;
        switch (pnmcd->nmcd.dwDrawStage) {
        case CDDS_PREPAINT:
          return CDRF_NOTIFYITEMDRAW;
        case CDDS_ITEMPREPAINT:
          return CDRF_NOTIFYSUBITEMDRAW;
        case CDDS_ITEMPREPAINT | CDDS_SUBITEM: {
          int iItem = (int)pnmcd->nmcd.dwItemSpec;
          if (iItem >= 0 && iItem < (int)g_Patches.size()) {

            // Initialize standard colors
            COLORREF textColor = RGB(0, 0, 0);     // Default Black
            COLORREF bkColor = RGB(255, 255, 255); // Default White

            // 1. Breakpoint Highlight (Highest Priority for Text Color)
            // Applied to Address Column (subitem 0)
            if (pnmcd->iSubItem == 0) {
              BPXTYPE bpType = DbgGetBpxTypeAt(g_Patches[iItem].head);
              if (bpType != bp_none) {
                bkColor = RGB(255, 100, 100); // Red Background
                textColor =
                    RGB(0, 0, 255); // Bright Blue Text (Distinct from Black)

                // Bold Font for Breakpoints
                if (!g_hBoldFont) {
                  HFONT hFont = (HFONT)SendMessage(hList, WM_GETFONT, 0, 0);
                  LOGFONT lf = {0};
                  if (GetObject(hFont, sizeof(LOGFONT), &lf)) {
                    lf.lfWeight = FW_BOLD;
                    g_hBoldFont = CreateFontIndirect(&lf);
                  }
                }
                if (g_hBoldFont)
                  SelectObject(pnmcd->nmcd.hdc, g_hBoldFont);
              }
            }

            // 2. State Coloring (Yellow) - Mutually Exclusive (New vs Old)
            // Only affects Data columns (1-4)
            if (pnmcd->iSubItem >= 1 && pnmcd->iSubItem <= 4) {
              bool matchesNew = IsMemoryMatching(g_Patches[iItem].address,
                                                 g_Patches[iItem].newBytes);
              bool matchesOld = IsMemoryMatching(g_Patches[iItem].address,
                                                 g_Patches[iItem].oldBytes);

              if (matchesNew) {
                if (pnmcd->iSubItem == 2 ||
                    pnmcd->iSubItem == 4) {     // New Bytes or New Disasm
                  bkColor = RGB(255, 255, 224); // Light Yellow
                  textColor = RGB(0, 100, 0);   // Dark Green
                }
              } else if (matchesOld) {
                if (pnmcd->iSubItem == 1 ||
                    pnmcd->iSubItem == 3) {     // Old Bytes or Old Disasm
                  bkColor = RGB(255, 255, 224); // Light Yellow
                  textColor = RGB(0, 100, 0);   // Dark Green
                }
              }
            }

            // 3. Selection Override (User Request: Pale Blue)
            // If selected, we override BACKGROUND ONLY to Pale Blue.
            // Text color remains whatever we calculated above (Black, Dark
            // Green, or Dark Blue).
            if (pnmcd->nmcd.uItemState & CDIS_SELECTED) {
              bkColor = RGB(225, 240, 255); // Pale Blue
              pnmcd->nmcd.uItemState &=
                  ~CDIS_SELECTED; // Custom selection color
            }

            // Apply final colors
            pnmcd->clrText = textColor;
            pnmcd->clrTextBk = bkColor;

            return CDRF_NEWFONT;
          }
          return CDRF_DODEFAULT;
        }
        }
        break;
      }
      }
      break;
    }
    break;
  }
  case WM_COMMAND: {
    switch (LOWORD(wParam)) {
    case IDC_EDIT_FILTER_OLD:
    case IDC_EDIT_FILTER_NEW:
      if (HIWORD(wParam) == EN_CHANGE) {
        ApplyFilter();
        UpdateListView(); // Update ListView directly
      }
      break;

    case ID_CHK_INVERSE_OLD:
    case ID_CHK_INVERSE_NEW:
      // Only respond to click events
      if (HIWORD(wParam) == BN_CLICKED) {
        ApplyFilter();
        UpdateListView();
      }
      break;

    case ID_MENU_LOAD: {
      char filepath[MAX_PATH];
      if (GetFileNameFromUser(filepath, MAX_PATH, false)) {
        if (ImportAndApplyPatches(filepath)) {
          RefreshPatchList();
        }
      }
      break;
    }
    case ID_MENU_SAVE: {
      char filepath[MAX_PATH];
      if (GetFileNameFromUser(filepath, MAX_PATH, true))
        ExportPatches(filepath);
      break;
    }
    case ID_MENU_REFRESH: {
      RefreshPatchList();
      break;
    }

    case ID_MENU_REMOVE_ALL_IN_LIST: {
      // Remove all patches that are currently visible in the filtered list
      if (g_Patches.empty()) {
        MessageBoxA(hwnd, "No patches in the current list to remove.",
                    "Remove All", MB_ICONINFORMATION);
        break;
      }

      char msg[256];
      sprintf(msg,
              "Remove all %d patches in the current list from the "
              "debugger?\n\nThis will restore them to their original bytes.",
              (int)g_Patches.size());
      int result = MessageBoxA(hwnd, msg, "Confirm Remove All",
                               MB_YESNO | MB_ICONQUESTION);

      if (result == IDYES) {
        const DBGFUNCTIONS *dbgFuncs = DbgFunctions();
        if (!dbgFuncs || !dbgFuncs->MemPatch) {
          MessageBoxA(hwnd, "MemPatch API not available", "Error",
                      MB_ICONERROR);
          break;
        }

        int successCount = 0;
        int failCount = 0;

        // Restore each patch to its old bytes
        for (const auto &patch : g_Patches) {
          bool allRestored = true;
          for (size_t k = 0; k < patch.oldBytes.size(); ++k) {
            duint addr = patch.address + k;
            unsigned char oldByte = patch.oldBytes[k];
            if (!dbgFuncs->MemPatch(addr, &oldByte, 1)) {
              allRestored = false;
            }
          }
          if (allRestored) {
            successCount++;
          } else {
            failCount++;
          }
        }

        GuiUpdateAllViews();
        RefreshPatchList();

        sprintf(msg, "Batch removal complete.\n\nRestored: %d\nFailed: %d",
                successCount, failCount);
        MessageBoxA(hwnd, msg, "Remove All Result", MB_ICONINFORMATION);
      }
      break;
    }

    case ID_MENU_DISASM:
    case ID_MENU_APPLY:
    case ID_MENU_RESTORE:
    case ID_MENU_DELETE: {
      int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
      if (iItem != -1)
        ExecuteAction(hwnd, LOWORD(wParam), iItem);
      break;
    }
    }
    break;
  }
  case WM_CLOSE:
    DestroyWindow(hwnd);
    break;
  case WM_DESTROY:
    if (g_hBoldFont) {
      DeleteObject(g_hBoldFont);
      g_hBoldFont = NULL;
    }
    if (g_hListFont) {
      DeleteObject(g_hListFont);
      g_hListFont = NULL;
    }
    hPatchWindow = NULL;
    break;
  default:
    return DefWindowProc(hwnd, msg, wParam, lParam);
  }
  return 0;
}

// Helpers
void RegisterPatchWindowClass() {
  WNDCLASSEX wc = {0};
  wc.cbSize = sizeof(WNDCLASSEX);
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = PatchWndProc;
  wc.hInstance = hInst;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
  wc.lpszClassName = PATCH_WINDOW_CLASS_NAME;

  // Load Custom Icon from embedded data
  // .ico file format: Header(6) + DirEntry(16) -> Offset at 18
  HICON hIcon = NULL;
  if (sizeof(icon_data) > 22) {
    DWORD offset = *(DWORD *)(icon_data + 18);
    DWORD size = *(DWORD *)(icon_data + 14);
    if (offset + size <= sizeof(icon_data)) {
      hIcon = CreateIconFromResource((PBYTE)icon_data + offset, size, TRUE,
                                     0x30000);
    }
  }
  if (!hIcon)
    hIcon = LoadIcon(NULL, IDI_APPLICATION); // Fallback

  wc.hIcon = hIcon;
  RegisterClassEx(&wc);
}

void OpenPatchWindow() {
  if (hPatchWindow) {
    if (IsIconic(hPatchWindow))
      ShowWindow(hPatchWindow, SW_RESTORE);
    SetForegroundWindow(hPatchWindow);
    return;
  }
  RegisterPatchWindowClass();
  hPatchWindow = CreateWindowEx(
      0, PATCH_WINDOW_CLASS_NAME, "Patch King", WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, CW_USEDEFAULT, 1900, 600, hwndDlg, NULL, hInst, NULL);
  if (hPatchWindow) {
    ShowWindow(hPatchWindow, SW_SHOW);
    UpdateWindow(hPatchWindow);
    RefreshPatchList();
  }
}

void ClosePatchWindow() {
  if (hPatchWindow)
    SendMessage(hPatchWindow, WM_CLOSE, 0, 0);
}

bool GetFileNameFromUser(char *buffer, int maxLen, bool save) {
  OPENFILENAME ofn = {0};
  ofn.lStructSize = sizeof(ofn);
  ofn.hwndOwner = hPatchWindow;
  ofn.lpstrFilter =
      "Patch Files (*.txt;*.patch;*.1337)\0*.txt;*.patch;*.1337\0All Files "
      "(*.*)\0*.*\0";
  ofn.lpstrFile = buffer;
  ofn.nMaxFile = maxLen;
  ofn.Flags = OFN_EXPLORER | (save ? OFN_OVERWRITEPROMPT : OFN_FILEMUSTEXIST);
  buffer[0] = '\0';
  return save ? GetSaveFileNameA(&ofn) : GetOpenFileNameA(&ofn);
}

bool ImportAndApplyPatches(const char *filepath) {
  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    MessageBoxA(hPatchWindow, "Failed to open file!", "Error", MB_ICONERROR);
    return false;
  }

  const DBGFUNCTIONS *dbgFuncs = DbgFunctions();
  if (!dbgFuncs || !dbgFuncs->MemPatch) {
    fclose(fp);
    MessageBoxA(hPatchWindow, "Debugger not ready (MemPatch unavailable).",
                "Error", MB_ICONERROR);
    return false;
  }

  // Strategy A: Robust ImageBase Resolution
  duint imageBase = 0;

  // 1. Try Script API (Most Reliable for Main PE)
  imageBase = Script::Module::GetMainModuleBase();
  Log("[PatchMgr] GetMainModuleBase() returned: %p\n", (void *)imageBase);

  // 2. Try DbgEval if Script API failed
  if (imageBase == 0 && dbgFuncs->ValFromString) {
    dbgFuncs->ValFromString("imagebase", &imageBase);
    Log("[PatchMgr] ValFromString('imagebase') returned: %p\n",
        (void *)imageBase);
  }

  // 3. Fallback: Use CIP (Current Instruction Pointer) module base if
  // imagebase failed
  // 3. Fallback: Use CIP (Current Instruction Pointer) module base if
  // imagebase failed
  if (imageBase == 0) {
    duint cip = 0;
    if (dbgFuncs->ValFromString)
      dbgFuncs->ValFromString("cip", &cip);

    if ((cip != 0) && dbgFuncs->ModBaseFromAddr) {
      imageBase = dbgFuncs->ModBaseFromAddr(cip);
      Log("[PatchMgr] Fallback to CIP Base: %p\n", (void *)imageBase);
    }
  }

  // Get Module Name for FileOffsetToVa (Safe Usage)
  char mainModName[MAX_MODULE_SIZE] = {0};
  if (imageBase != 0 && dbgFuncs->ModNameFromAddr) {
    dbgFuncs->ModNameFromAddr(imageBase, mainModName, false);
    Log("[PatchMgr] Main Module Name: %s\n", mainModName);
  }

  char buffer[512];
  int successCount = 0;
  int failCount = 0;
  int lineNum = 0;

  while (fgets(buffer, sizeof(buffer), fp)) {
    lineNum++;
    std::string line(buffer);

    // Trim
    while (!line.empty() && (isspace((unsigned char)line.back())))
      line.pop_back();
    while (!line.empty() && (isspace((unsigned char)line.front())))
      line.erase(0, 1);

    if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '>')
      continue;

    // Parse
    size_t col = line.find(':');
    size_t arr = line.find("->");

    duint addr = 0;
    unsigned char newB = 0;
    bool validParse = false;

    try {
      if (col != std::string::npos && arr != std::string::npos && arr > col) {
        addr = (duint)std::stoull(line.substr(0, col), nullptr, 16);
        newB = (unsigned char)std::stoul(line.substr(arr + 2), nullptr, 16);
        validParse = true;
      } else if (col != std::string::npos) {
        addr = (duint)std::stoull(line.substr(0, col), nullptr, 16);
        newB = (unsigned char)std::stoul(line.substr(col + 1), nullptr, 16);
        validParse = true;
      }
    } catch (...) {
      Log("[PatchMgr] Line %d: Parse error '%s'\n", lineNum, line.c_str());
      failCount++;
      continue;
    }

    if (!validParse)
      continue;

    bool patched = false;

    // Attempt 1: Raw Address
    if (dbgFuncs->MemPatch(addr, &newB, 1)) {
      Log("[PatchMgr] Line %d: Patched via Raw Address (%p)\n", lineNum,
          (void *)addr);
      patched = true;
    }

    // Attempt 2: RVA (ImageBase + Addr) - PRIORITY per User Request ("Default
    // add ImageBase")
    if (!patched && imageBase != 0) {
      if (dbgFuncs->MemPatch(imageBase + addr, &newB, 1)) {
        Log("[PatchMgr] Line %d: Patched via RVA (%p + %p -> %p)\n", lineNum,
            (void *)imageBase, (void *)addr, (void *)(imageBase + addr));
        patched = true;
      }
    }

    // Attempt 3: File Offset -> VA (Fallback)
    // Only used if RVA failed (e.g. address wasn't a valid RVA or memory not
    // mapped there)
    if (!patched && dbgFuncs->FileOffsetToVa && mainModName[0] != 0) {
      duint va = dbgFuncs->FileOffsetToVa(mainModName, addr);
      if (va != 0 && dbgFuncs->MemPatch(va, &newB, 1)) {
        Log("[PatchMgr] Line %d: Patched via FileOffset (%p -> %p)\n", lineNum,
            (void *)addr, (void *)va);
        patched = true;
      }
    }

    if (patched) {
      successCount++;
    } else {
      duint vaAttempt = (dbgFuncs->FileOffsetToVa && mainModName[0])
                            ? dbgFuncs->FileOffsetToVa(mainModName, addr)
                            : 0;
      Log("[PatchMgr] Line %d: FAILED %p. Tried Raw, RVA(%p), "
          "OffsetToVa(%p)\n",
          lineNum, (void *)addr, (void *)(imageBase + addr), (void *)vaAttempt);
      failCount++;
    }
  }
  fclose(fp);

  GuiUpdateAllViews();

  char msg[256];
  sprintf(msg, "Import complete (ImageBase: %p).\nSuccess: %d\nFailed: %d",
          (void *)imageBase, successCount, failCount);
  MessageBoxA(hPatchWindow, msg, "Patch Import", MB_ICONINFORMATION);

  return successCount > 0;
}

bool ExportPatches(const char *filepath) {
  FILE *fp = fopen(filepath, "w");
  if (!fp)
    return false;
  fprintf(fp, "# x32dbg Patch Export (Filtered)\n# Format: "
              "Address:OldByte->NewByte\n\n");

  // Use g_Patches which contains the currently visible/filtered patches
  for (const auto &p : g_Patches) {
    // Each PatchInfo is a contiguous block
    for (size_t k = 0; k < p.oldBytes.size(); ++k) {
      duint currentAddr = p.address + k;
      unsigned char oldB = p.oldBytes[k];
      unsigned char newB =
          (k < p.newBytes.size()) ? p.newBytes[k] : 0; // Should match size
      fprintf(fp, "%p:%02X->%02X\n", (void *)currentAddr, oldB, newB);
    }
  }

  fclose(fp);
  return true;
}
