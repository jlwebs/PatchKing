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
#include <thread>
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
#define ID_MENU_EXPORT_CSV 2012

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
#define ID_CHK_REGEX 1007
#define ID_CHK_FOLLOW_MOVE 1008
#define ID_STATIC_STATUS 1009
#define ID_CHK_FOLLOW_ABOVE 1010
#define ID_EDIT_FOLLOW_LINES 1011
#define ID_STATIC_FOLLOW_LABEL 1012
#define ID_CHK_PRO_ANALYZE 1013
#define ID_CHK_FLATTEN_LINE 1014

WNDPROC oldListWndProc = NULL;
HFONT g_hBoldFont = NULL;

HWND hChkRegex = NULL;
HWND hChkFollowMove = NULL;
HWND hChkFollowAbove = NULL;
HWND hEditFollowLines = NULL;
HWND hStaticFollowLabel = NULL;
HWND hChkProAnalyze = NULL;
HWND hChkFlattenLine = NULL;
HWND hStaticStatus = NULL;

// Persistent Settings
// Global State
bool g_bProAnalyze = true;
bool g_bFlattenLine = false; // New Flatten Option
static int g_nFollowLines = 3;

// Forward Declarations
void RefreshPatchList();
void ApplyFilter();
bool ApplyPatch(const PatchInfo &patch);
bool RestorePatch(const PatchInfo &patch);
void ShowContextMenu(HWND hwnd, POINT pt);
void UpdateStatus();

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
// Finalized Solution: Official SDK Demands (OSD)
duint FindCorrectOldHead(duint patchAddr,
                         const std::vector<unsigned char> &oldBytes,
                         bool useProAnalyze, int lines) {
  const DBGFUNCTIONS *funcs = DbgFunctions();
  if (!funcs)
    return patchAddr;

  if (useProAnalyze) {
    // --- ProAnalyze Logic: Sync Back & Scan Forward ---
    duint target = patchAddr;
    char buf[256];

    // 1. Establish Sync Point (Backtrack)
    if (lines >= 4) {
      duint base = patchAddr - 0xE;
      sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)base);
      target = DbgValFromString(buf);
      int backSteps = lines - 4;
      for (int k = 0; k < backSteps; k++) {
        sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)target);
        target = DbgValFromString(buf);
      }
    } else {
      for (int i = 0; i < lines; i++) {
        sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)target);
        target = DbgValFromString(buf);
      }
    }

    // Log("[PatchMgr][ProAnalyze] Target 0x%llX Backtracked to SyncPoint
    // 0x%llX\n", (unsigned long long)patchAddr, (unsigned long long)target);

    // 2. Scan Forward to find True Head
    duint scanCur = target;
    for (int i = 0; i < 50; i++) { // Max 50 checks
      BASIC_INSTRUCTION_INFO instr;
      unsigned char data[16];
      memset(&instr, 0, sizeof(instr));
      if (DbgMemRead(scanCur, data, 16) &&
          DbgFunctions()->DisasmFast(data, scanCur, &instr)) {
        duint next = scanCur + instr.size;
        // Check if patchAddr is INSIDE this instruction
        if (scanCur <= patchAddr && patchAddr < next) {
          if (scanCur != patchAddr) {
            // Log("[PatchMgr][ProAnalyze] FIXED: Patch 0x%llX -> TrueHead
            // 0x%llX\n", (unsigned long long)patchAddr, (unsigned long
            // long)scanCur);
          }
          return scanCur; // Found the true head
        }
        scanCur = next;
        if (scanCur > patchAddr) {
          // Log("[PatchMgr][ProAnalyze] Failed: Overshot 0x%llX at 0x%llX\n",
          // (unsigned long long)patchAddr, (unsigned long long)scanCur);
          break; // Overshot
        }
      } else {
        scanCur++;
      }
    }
    // Fallback to old logic if ProAnalyze fails (unlikely)
  }

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

// Helper to get formatted disassembly for the "NEW" state
// We use GuiGetDisassembly to match the rich text in the CPU view.
static void GetRichDisassembly(duint addr, std::string &outDisasm) {
  char text[GUI_MAX_DISASSEMBLY_SIZE] = "";
  if (GuiGetDisassembly(addr, text)) {
    outDisasm = text;
  } else {
    // Fallback if GUI function fails
    DISASM_INSTR dInstr;
    DbgDisasmAt(addr, &dInstr);
    outDisasm = dInstr.instruction;
  }
}

// Helper to resolve symbols in the "Old" raw disassembly string.
// DisasmFast returns raw hex (e.g. "call 0x401000" or "mov eax, [0x402000]").
// We parse these hex strings and try to resolve them to labels to match "Rich"
// display.
static void EnhanceOldDisassembly(std::string &text) {
  // 1. Look for brackets [0xADDR] or [ADDR]
  size_t startBracket = 0;
  while ((startBracket = text.find('[', startBracket)) != std::string::npos) {
    size_t endBracket = text.find(']', startBracket);
    if (endBracket == std::string::npos)
      break;

    // Extract content
    std::string content =
        text.substr(startBracket + 1, endBracket - startBracket - 1);

    // Check if content is hex address
    // DisasmFast often uses 0x prefix, or just hex
    duint addr = 0;
    bool isHex = false;
    try {
      size_t idx = 0;
      if (content.rfind("0x", 0) == 0) // Starts with 0x?
        addr = (duint)std::stoull(content.substr(2), &idx, 16);
      else
        addr = (duint)std::stoull(content, &idx, 16);

      if (idx > 0)
        isHex = true;
    } catch (...) {
    }

    if (isHex && addr > 0x1000) { // Filter small numbers
      char label[MAX_COMMENT_SIZE] = {0};
      if (DbgGetLabelAt(addr, SEG_DEFAULT, label)) {
        // Replace [0x40...] with [<&Label>]
        std::string replacement = "[<";
        if (label[0] == '&')
          replacement = "["; // Label already has &? usually not.
        // x64dbg convention: <symbol>
        replacement += label;
        replacement += ">]";

        text.replace(startBracket, endBracket - startBracket + 1, replacement);
        startBracket += replacement.length();
        continue;
      }
    }
    startBracket = endBracket + 1;
  }

  // 2. Look for immediate calls/jumps "call 0xADDR"
  // Heuristic: "call " or "jmp " followed by hex
  const char *prefixes[] = {"call ", "jmp ", "ja ", "je ", "jnz ", "jz "};
  for (const char *prefix : prefixes) {
    size_t pos = 0;
    while ((pos = text.find(prefix, pos)) != std::string::npos) {
      size_t addrStart = pos + strlen(prefix);
      // Skip 0x if present
      if (addrStart + 2 < text.length() && text.substr(addrStart, 2) == "0x") {
        addrStart += 2;
      }

      // Pars hex
      size_t addrEnd = addrStart;
      while (addrEnd < text.length() && isxdigit(text[addrEnd])) {
        addrEnd++;
      }

      if (addrEnd > addrStart) {
        std::string hexStr = text.substr(addrStart, addrEnd - addrStart);
        duint addr = 0;
        try {
          addr = (duint)std::stoull(hexStr, nullptr, 16);
        } catch (...) {
        }

        if (addr > 0x1000) {
          char label[MAX_COMMENT_SIZE] = {0};
          if (DbgGetLabelAt(addr, SEG_DEFAULT, label)) {
            // Replace ADDR with <Label>
            std::string replacement = "<";
            replacement += label;
            replacement += ">";

            // We might need to replace the whole 0xADDR part
            // Check if we skipped 0x
            size_t replaceStart = pos + strlen(prefix);
            text.replace(replaceStart, addrEnd - replaceStart, replacement);
            pos = replaceStart + replacement.length();
            continue;
          }
        }
      }
      pos = addrEnd;
    }
  }
}

// Helper function to resolve details (disassembly, comments) for a patch group.
// Designed to be run in parallel.
// Helper function to resolve details (disassembly, comments) for a patch group.
// Designed to be run in parallel.
static void ResolvePatchDetails(PatchInfo &p, bool fastMode, bool useProAnalyze,
                                int lines) {
  const DBGFUNCTIONS *funcs = DbgFunctions();
  p.head = FindCorrectOldHead(p.address, p.oldBytes, useProAnalyze, lines);
  BASIC_INSTRUCTION_INFO bInfo;
  DISASM_INSTR dInstr;

  // Disassemble NEW
  if (fastMode) {
    DbgDisasmAt(p.head, &dInstr);
    p.disasm = dInstr.instruction;
  } else {
    GetRichDisassembly(p.head, p.disasm);
    // We still need dInstr for operand info later
    DbgDisasmAt(p.head, &dInstr);
  }

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
    if (!fastMode) {
      EnhanceOldDisassembly(p.oldDisasm);
    }
  }

  // Skip expensive comment/label lookups in fast mode
  if (fastMode) {
    return;
  }

  char comment[MAX_COMMENT_SIZE] = "";
  bool found = false;

  // 1. Try Comment at HEAD (User or Auto if supported)
  // Use DbgGetCommentAt checking for both user and potentially auto comments
  if (DbgGetCommentAt(p.head, comment)) {
    // If it starts with \1, it's auto. x64dbg conventions.
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
      char mne[64];
      strncpy(mne, dInstr.instruction, 63);
      bool isBranch = false;
      if (dInstr.instruction[0] == 'j' || dInstr.instruction[0] == 'J')
        isBranch = true;
      if (_strnicmp(dInstr.instruction, "call", 4) == 0)
        isBranch = true;
      if (_strnicmp(dInstr.instruction, "loop", 4) == 0)
        isBranch = true;

      if (!isBranch && DbgGetStringAt(targetAddr, info)) {
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

  // Phase 1: Grouping (Linear Scan)
  DWORD tStartGroup = GetTickCount();
  // We just collect the raw bytes and addresses here. Expensive lookups are
  // delayed. Reserve mainly to avoid reallocations
  g_AllPatches.reserve(dbgPatches.size());

  PatchInfo current;
  current.address = dbgPatches[0].addr;
  current.moduleName = dbgPatches[0].mod;
  current.oldBytes.push_back(dbgPatches[0].oldbyte);
  current.newBytes.push_back(dbgPatches[0].newbyte);
  current.active = true;

  for (size_t i = 1; i < dbgPatches.size(); ++i) {
    const auto &dp = dbgPatches[i];
    if (strcmp(dp.mod, current.moduleName.c_str()) == 0 &&
        dp.addr == current.address + current.oldBytes.size()) {
      current.oldBytes.push_back(dp.oldbyte);
      current.newBytes.push_back(dp.newbyte);
    } else {
      g_AllPatches.push_back(current);

      current.address = dp.addr;
      current.moduleName = dp.mod;
      current.oldBytes.clear();
      current.newBytes.clear();
      current.oldBytes.push_back(dp.oldbyte);
      current.newBytes.push_back(dp.newbyte);
      current.oldDisasm.clear();
      current.disasm.clear();
      current.comment.clear(); // Ensure clear
      current.active = true;
    }
  }
  // Push last one
  g_AllPatches.push_back(current);

  DWORD tEndGroup = GetTickCount();
  Log("[PatchMgr] Grouping %d raw patches into %d items took %d ms\n",
      dbgPatches.size(), g_AllPatches.size(), tEndGroup - tStartGroup);

  // Phase 1.5: Flattening (Optional)
  if (g_bFlattenLine) {
    DWORD tFlatStart = GetTickCount();
    std::vector<PatchInfo> expanded;
    expanded.reserve(g_AllPatches.size() * 2);

    for (const auto &p : g_AllPatches) {
      size_t totalBytes = p.oldBytes.size();
      // Safety: Should match newBytes size
      if (p.newBytes.size() != totalBytes) {
        expanded.push_back(p);
        continue;
      }

      size_t processed = 0;
      duint currentAddr = p.address;

      while (processed < totalBytes) {
        PatchInfo chunk = p;
        chunk.address = currentAddr;
        chunk.oldBytes.clear();
        chunk.newBytes.clear();
        chunk.oldDisasm.clear();
        chunk.disasm.clear();
        chunk.comment.clear(); // Clear comments for sub-lines

        // 1. Determine instruction length from NEW bytes (patched state)
        // We simulate the instruction stream as per user request
        unsigned char tempBuf[16] = {0};
        size_t remaining = totalBytes - processed;
        size_t copyLen = (remaining > 16) ? 16 : remaining;

        for (size_t k = 0; k < copyLen; k++) {
          tempBuf[k] = p.newBytes[processed + k];
        }

        BASIC_INSTRUCTION_INFO bInfo;
        memset(&bInfo, 0, sizeof(bInfo));
        // Use DisasmFast on buffer. Addr is for relative calc.
        if (funcs && funcs->DisasmFast) {
          funcs->DisasmFast(tempBuf, currentAddr, &bInfo);
        } else {
          bInfo.size = 1; // Fallback
        }

        int instrLen = bInfo.size;
        if (instrLen <= 0 || instrLen > 15)
          instrLen = 1;

        // Users logic: "Classic tail byte + 1" implies linear sweep
        // If patch is 5 bytes NOP, matches 1 byte NOP.
        // If patch is 5 bytes Long Instr, matches 5 bytes.

        size_t take =
            (remaining < (size_t)instrLen) ? remaining : (size_t)instrLen;

        for (size_t k = 0; k < take; k++) {
          chunk.oldBytes.push_back(p.oldBytes[processed + k]);
          chunk.newBytes.push_back(p.newBytes[processed + k]);
        }

        expanded.push_back(chunk);
        currentAddr += take;
        processed += take;
      }
    }
    g_AllPatches = std::move(expanded);
    Log("[PatchMgr] Flattened to %d items in %d ms\n", g_AllPatches.size(),
        GetTickCount() - tFlatStart);
  }

  // Phase 2: Parallel Processing
  // Process disassembly and comments in parallel threads.
  unsigned int nThreads = std::thread::hardware_concurrency();
  if (nThreads == 0)
    nThreads = 2;
  // Cap at 8 to prevent potential API contention overload (experimental)
  if (nThreads > 8)
    nThreads = 8;

  // If patch count is small, force single thread to avoid overhead
  if (g_AllPatches.size() < 100)
    nThreads = 1;

  bool fastMode = g_AllPatches.size() > 100000;
  if (fastMode) {
    Log("[PatchMgr] Large patch set detected (%d). Enabling Fast Mode "
        "(skipping rich symbols/comments).\n",
        g_AllPatches.size());
  }

  Log("[PatchMgr] Starting parallel resolution with %d threads...\n", nThreads);
  DWORD tStartParallel = GetTickCount();

  std::vector<std::thread> workers;
  size_t total = g_AllPatches.size();
  size_t chunk_size = (total + nThreads - 1) / nThreads;

  // Read UI state from GLOBALS (Persistent & Thread Safe)
  bool useProAnalyze = g_bProAnalyze;
  int followLines = g_nFollowLines;

  // FORCE MAIN THREAD EXECUTION FOR PRO ANALYZE
  // x64dbg SDK 'DbgValFromString' (dis.prev) is NOT thread-safe for background
  // threads. We must run linear on the main thread to ensure "ProAnalyze"
  // works.
  if (useProAnalyze) {
    Log("[PatchMgr][ProAnalyze] >>> Starting Synchronous Scan on %d items "
        "(Lines: %d) <<<\n",
        total, followLines);
    DWORD tProStart = GetTickCount();

    for (size_t i = 0; i < total; ++i) {
      ResolvePatchDetails(g_AllPatches[i], fastMode, true, followLines);
    }

    Log("[PatchMgr][ProAnalyze] <<< Finished Scan in %d ms >>>\n",
        GetTickCount() - tProStart);
  } else {
    Log("[PatchMgr] Starting Parallel Scan (ProAnalyze OFF)...\n");
    for (unsigned int t = 0; t < nThreads; ++t) {
      workers.emplace_back(
          [t, chunk_size, total, fastMode, useProAnalyze, followLines]() {
            DWORD tThreadStart = GetTickCount();
            size_t start = t * chunk_size;
            size_t end = (std::min)(start + chunk_size, total);
            int count = 0;

            for (size_t i = start; i < end; ++i) {
              ResolvePatchDetails(g_AllPatches[i], fastMode, useProAnalyze,
                                  followLines);
              count++;
            }
            Log("[PatchMgr] Thread %d finished: %d items in %d ms (Avg: %.2f "
                "ms/item)\n",
                t, count, GetTickCount() - tThreadStart,
                count > 0 ? (float)(GetTickCount() - tThreadStart) / count : 0);
          });
    }

    for (auto &w : workers) {
      if (w.joinable())
        w.join();
    }
  }

  DWORD tEndParallel = GetTickCount();
  Log("[PatchMgr] Parallel resolution took total %d ms\n",
      tEndParallel - tStartParallel);

  // After sync, apply current filter to update g_Patches
  ApplyFilter();
}

// Helper for case-insensitive search
static bool StringContains(const std::string &haystack,
                           const std::string &needle) {
  if (needle.empty())
    return true;
  auto it = std::search(haystack.begin(), haystack.end(), needle.begin(),
                        needle.end(), [](char ch1, char ch2) {
                          return std::toupper(ch1) == std::toupper(ch2);
                        });
  return (it != haystack.end());
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
  bool useRegex =
      (hChkRegex && SendMessage(hChkRegex, BM_GETCHECK, 0, 0) == BST_CHECKED);

  std::string fOld = filterBufOld;
  std::string fNew = filterBufNew;

  // Optimization: If no filter, just copy
  if (fOld.empty() && fNew.empty()) {
    g_Patches = g_AllPatches;
    return;
  }

  // Use multi-threading for filtering if we have many items
  unsigned int nThreads = std::thread::hardware_concurrency();
  if (nThreads == 0)
    nThreads = 2;
  if (g_AllPatches.size() < 1000)
    nThreads = 1; // Small threshold

  std::vector<std::vector<PatchInfo>> threadResults(nThreads);
  std::vector<std::thread> workers;

  size_t total = g_AllPatches.size();
  size_t chunk_size = (total + nThreads - 1) / nThreads;

  // Capture variables needed
  for (unsigned int t = 0; t < nThreads; ++t) {
    workers.emplace_back([t, chunk_size, total, &threadResults, fOld, fNew,
                          invOld, invNew, useRegex]() {
      size_t start = t * chunk_size;
      size_t end = (std::min)(start + chunk_size, total);

      try {
        // Pre-compile regex if needed
        std::regex reOld;
        std::regex reNew;
        if (useRegex) {
          if (!fOld.empty())
            reOld.assign(fOld, std::regex::icase);
          if (!fNew.empty())
            reNew.assign(fNew, std::regex::icase);
        }

        threadResults[t].reserve((end - start) / 2); // heuristic reserve

        for (size_t i = start; i < end; ++i) {
          const auto &p = g_AllPatches[i];
          bool matchOld = false;
          bool matchNew = false;

          if (useRegex) {
            if (fOld.empty())
              matchOld = true; // Handle empty regex case logic carefully
            else
              matchOld = std::regex_search(p.oldDisasm, reOld) ||
                         std::regex_search(p.comment, reOld);

            if (fNew.empty())
              matchNew = true;
            else
              matchNew = std::regex_search(p.disasm, reNew);
          } else {
            // Fast String Search
            if (fOld.empty())
              matchOld = true;
            else
              matchOld = StringContains(p.oldDisasm, fOld) ||
                         StringContains(p.comment, fOld);

            if (fNew.empty())
              matchNew = true;
            else
              matchNew = StringContains(p.disasm, fNew);
          }

          bool passOld = true;
          if (!fOld.empty()) {
            passOld = invOld ? !matchOld : matchOld;
          }

          bool passNew = true;
          if (!fNew.empty()) {
            passNew = invNew ? !matchNew : matchNew;
          }

          if (passOld && passNew) {
            threadResults[t].push_back(p);
          }
        }
      } catch (...) {
        // Regex error or other
      }
    });
  }

  for (auto &w : workers) {
    if (w.joinable())
      w.join();
  }

  // Merge results
  g_Patches.clear();
  size_t totalFiltered = 0;
  for (const auto &res : threadResults)
    totalFiltered += res.size();
  g_Patches.reserve(totalFiltered);

  for (const auto &res : threadResults) {
    g_Patches.insert(g_Patches.end(), res.begin(), res.end());
  }
}

// Only refreshes the ListView using g_Patches (which should be already
// filtered)
void UpdateListView() {
  if (!hList)
    return;

  // Virtual List View: Set Item Count
  ListView_SetItemCountEx(hList, g_Patches.size(),
                          LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
  InvalidateRect(hList, NULL, TRUE);
  UpdateStatus();
}

void UpdateStatus() {
  if (!hStaticStatus)
    return;

  size_t total = g_Patches.size();
  if (total == 0) {
    SetWindowText(hStaticStatus, "Items: 0");
    return;
  }

  // Optimization: If too many patches, skip expensive memory scan
  if (total > 5000) {
    char buf[64];
    snprintf(buf, sizeof(buf), "Items: %d (Scan Skipped > 5000)", (int)total);
    SetWindowText(hStaticStatus, buf);
    return;
  }

  // Run in background thread to avoid UI lag even for 5000 items
  std::thread([total]() {
    int countOld = 0;
    int countNew = 0;
    // Use a local copy or be careful with concurrency.
    // g_Patches might change?
    // Unsafe to access g_Patches in thread if it changes.
    // But for status update usually we are idle.
    // Better to just run on UI thread if < 2000, or simple detached check.

    // Let's run on main thread but with limit 2000.
    // 2000 memory reads takes ~20-50ms. Acceptable.
  }).detach();

  // Re-implementation: Synchronous for safety but capped count
  int countOld = 0;
  int countNew = 0;

  // Check up to 2000 items strictly to avoid lag
  size_t limit = (total < 2000) ? total : 2000;

  for (size_t i = 0; i < limit; ++i) {
    if (IsMemoryMatching(g_Patches[i].address, g_Patches[i].oldBytes))
      countOld++;
    else if (IsMemoryMatching(g_Patches[i].address, g_Patches[i].newBytes))
      countNew++;
  }

  char buf[128];
  if (limit < total)
    snprintf(buf, sizeof(buf), "Items: %d (Old: %d, New: %d) [Partial Scan]",
             (int)total, countOld, countNew);
  else
    snprintf(buf, sizeof(buf), "Items: %d (Old: %d, New: %d)", (int)total,
             countOld, countNew);

  SetWindowText(hStaticStatus, buf);
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
bool ExportTableToCSV(const char *filepath);
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

  AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
  AppendMenu(hMenu, MF_STRING, ID_MENU_EXPORT_CSV, "Export Table To CSV");

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
    int statusHeight = 30; // Status Bar Height
    int chkWidth = 70;
    int spacing = 25;

    int totalWidth = rc.right;
    int halfWidth = totalWidth / 2;

    // Y coordinates
    int bottomY = rc.bottom - statusHeight;
    int filterY = bottomY - editHeight;

    // --- Row 2 (Bottom): Status Area ---
    // --- Row 2 (Bottom): Status Area ---
    // [Regex (60)][Follow+Move (90)][Follow Above (90)][StatusText (Rest)]
    int regexWidth = 60;
    int followWidth = 140;
    int followAboveWidth = 140;

    hChkRegex = CreateWindow(
        "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 0, bottomY,
        regexWidth, statusHeight, hwnd, (HMENU)ID_CHK_REGEX, hInst, NULL);
    SendMessage(hChkRegex, BM_SETCHECK, BST_CHECKED, 0);

    hChkFollowMove = CreateWindow(
        "BUTTON", "Auto Next", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        regexWidth + spacing, bottomY, followWidth, statusHeight, hwnd,
        (HMENU)ID_CHK_FOLLOW_MOVE, hInst, NULL);

    hChkFollowAbove = CreateWindow(
        "BUTTON", "Follow", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        regexWidth + spacing + followWidth + spacing, bottomY, 80, statusHeight,
        hwnd, (HMENU)ID_CHK_FOLLOW_ABOVE, hInst, NULL);

    // Edit box for number of lines
    hEditFollowLines = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "3",
        WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_CENTER,
        regexWidth + spacing + followWidth + spacing + 80 + 10, bottomY + 2, 30,
        statusHeight - 4, hwnd, (HMENU)ID_EDIT_FOLLOW_LINES, hInst, NULL);
    SendMessage(hEditFollowLines, EM_LIMITTEXT, 2, 0); // Limit to 2 chars

    // "Above" Label
    hStaticFollowLabel = CreateWindow(
        "STATIC", "Above", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 + 10,
        bottomY, 80, statusHeight, hwnd, (HMENU)ID_STATIC_FOLLOW_LABEL, hInst,
        NULL);

    // "ProAnalyze" Checkbox
    hChkProAnalyze = CreateWindow("BUTTON", "ProAnalyze",
                                  WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                  regexWidth + spacing + followWidth + spacing +
                                      80 + 10 + 30 + 10 + 80 + spacing,
                                  bottomY, 180, statusHeight, hwnd,
                                  (HMENU)ID_CHK_PRO_ANALYZE, hInst, NULL);

    hChkFlattenLine = CreateWindow(
        "BUTTON", "Flatten", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 + 10 + 80 +
            spacing + 180 + spacing,
        bottomY, 80, statusHeight, hwnd, (HMENU)ID_CHK_FLATTEN_LINE, hInst,
        NULL);

    // Restore persistent state
    SendMessage(hChkProAnalyze, BM_SETCHECK,
                g_bProAnalyze ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(hChkFlattenLine, BM_SETCHECK,
                g_bFlattenLine ? BST_CHECKED : BST_UNCHECKED, 0);
    SetDlgItemInt(hwnd, ID_EDIT_FOLLOW_LINES, g_nFollowLines, FALSE);

    int statusX = regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 +
                  10 + 80 + spacing + 180 + spacing + 80 +
                  spacing; // Adjusted statusX for new checkbox
    hStaticStatus = CreateWindow(
        "STATIC", "Items: 0", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE | SS_RIGHT,
        statusX, bottomY, totalWidth - statusX, statusHeight, hwnd,
        (HMENU)ID_STATIC_STATUS, hInst, NULL);

    // --- Row 1: Filters ---

    // Left Group: [Filter Edit Old][Gap][Inv Checkbox]
    // 1. Filter Edit Old

    hFilterEditOld = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0,
        filterY, halfWidth - chkWidth - spacing, editHeight, hwnd,
        (HMENU)IDC_EDIT_FILTER_OLD, hInst, NULL);
    SendMessage(hFilterEditOld, EM_SETCUEBANNER, FALSE,
                (LPARAM)L"Filter Old...");

    // 2. Inverse Checkbox Old
    hChkInverseOld =
        CreateWindow("BUTTON", "Inv", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                     halfWidth - chkWidth, filterY, chkWidth, editHeight, hwnd,
                     (HMENU)ID_CHK_INVERSE_OLD, hInst, NULL);

    // Right Group: [Filter Edit New][Gap][Inv Checkbox]
    // 3. Filter Edit New
    hFilterEditNew = CreateWindowEx(
        WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        halfWidth, filterY, halfWidth - chkWidth - spacing, editHeight, hwnd,
        (HMENU)IDC_EDIT_FILTER_NEW, hInst, NULL);
    SendMessage(hFilterEditNew, EM_SETCUEBANNER, FALSE,
                (LPARAM)L"Filter New...");

    // 4. Inverse Checkbox New
    hChkInverseNew =
        CreateWindow("BUTTON", "Inv", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                     rc.right - chkWidth, filterY, chkWidth, editHeight, hwnd,
                     (HMENU)ID_CHK_INVERSE_NEW, hInst, NULL);

    hList = CreateWindowEx(0, WC_LISTVIEW, "",
                           WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL |
                               LVS_OWNERDATA | LVS_SHOWSELALWAYS,
                           0, 0, rc.right, filterY, hwnd,
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
    int statusHeight = 30;
    int regexWidth = 60;
    int followWidth = 140;
    int followAboveWidth = 140;
    int chkWidth = 70;
    int spacing = 25;
    int totalWidth = rc.right;
    int halfWidth = totalWidth / 2;

    if (hList && hFilterEditOld && hFilterEditNew && hChkInverseOld &&
        hChkInverseNew && hChkRegex && hChkFollowMove && hChkFollowAbove &&
        hStaticStatus) {

      // Status Row Y
      int bottomY = rc.bottom - statusHeight;
      // Filter Row Y
      int filterY = bottomY - editHeight;

      // List View Height = filterY
      SetWindowPos(hList, NULL, 0, 0, rc.right, filterY, SWP_NOZORDER);

      // Row 2: Status Area [Regex][Follow][FollowAbove][Status]
      SetWindowPos(hChkRegex, NULL, 0, bottomY, regexWidth, statusHeight,
                   SWP_NOZORDER);
      SetWindowPos(hChkFollowMove, NULL, regexWidth + spacing, bottomY,
                   followWidth, statusHeight, SWP_NOZORDER);

      SetWindowPos(hChkFollowAbove, NULL,
                   regexWidth + spacing + followWidth + spacing, bottomY, 80,
                   statusHeight, SWP_NOZORDER);

      SetWindowPos(hEditFollowLines, NULL,
                   regexWidth + spacing + followWidth + spacing + 80 + 10,
                   bottomY + 2, 30, statusHeight - 4, SWP_NOZORDER);

      SetWindowPos(hStaticFollowLabel, NULL,
                   regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 +
                       10,
                   bottomY, 80, statusHeight, SWP_NOZORDER);

      SetWindowPos(hChkProAnalyze, NULL,
                   regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 +
                       10 + 80 + spacing,
                   bottomY, 180, statusHeight, SWP_NOZORDER);

      SetWindowPos(hChkFlattenLine, NULL,
                   regexWidth + spacing + followWidth + spacing + 80 + 10 + 30 +
                       10 + 80 + spacing + 180 + spacing,
                   bottomY, 80, statusHeight, SWP_NOZORDER);

      int statusX = regexWidth + spacing + followWidth + spacing + 80 + 10 +
                    30 + 10 + 80 + spacing + 180 + spacing + 80 + spacing;
      SetWindowPos(hStaticStatus, NULL, statusX, bottomY, totalWidth - statusX,
                   statusHeight, SWP_NOZORDER);

      // Row 1: Filters
      // Left Group: [Filter Edit Old][Gap][Inv Checkbox]
      SetWindowPos(hFilterEditOld, NULL, 0, filterY,
                   halfWidth - chkWidth - spacing, editHeight, SWP_NOZORDER);
      SetWindowPos(hChkInverseOld, NULL, halfWidth - chkWidth, filterY,
                   chkWidth, editHeight, SWP_NOZORDER);

      // Right Group: [Filter Edit New][Gap][Inv Checkbox]
      SetWindowPos(hFilterEditNew, NULL, halfWidth, filterY,
                   halfWidth - chkWidth - spacing, editHeight, SWP_NOZORDER);
      SetWindowPos(hChkInverseNew, NULL, rc.right - chkWidth, filterY, chkWidth,
                   editHeight, SWP_NOZORDER);
    }
    break;
  }
  case WM_NOTIFY: {
    LPNMHDR pnmh = (LPNMHDR)lParam;
    if (pnmh->idFrom == IDC_LIST_PATCHES) {
      switch (pnmh->code) {
      case LVN_GETDISPINFO: {
        NMLVDISPINFO *pDispInfo = (NMLVDISPINFO *)lParam;
        if (pDispInfo->item.mask & LVIF_TEXT) {
          int iItem = pDispInfo->item.iItem;
          if (iItem >= 0 && iItem < (int)g_Patches.size()) {
            const auto &patch = g_Patches[iItem];
            switch (pDispInfo->item.iSubItem) {
            case 0: // Address
              snprintf(pDispInfo->item.pszText, pDispInfo->item.cchTextMax,
                       "%08X", (unsigned int)patch.address);
              break;
            case 1: // Old Bytes
            {
              std::string s = BytesToHex(patch.oldBytes);
              strncpy(pDispInfo->item.pszText, s.c_str(),
                      pDispInfo->item.cchTextMax);
            } break;
            case 2: // New Bytes
            {
              std::string s = BytesToHex(patch.newBytes);
              strncpy(pDispInfo->item.pszText, s.c_str(),
                      pDispInfo->item.cchTextMax);
            } break;
            case 3: // Old Disasm
              strncpy(pDispInfo->item.pszText, patch.oldDisasm.c_str(),
                      pDispInfo->item.cchTextMax);
              break;
            case 4: // New Disasm
              strncpy(pDispInfo->item.pszText, patch.disasm.c_str(),
                      pDispInfo->item.cchTextMax);
              break;
            case 5: // Comment
              strncpy(pDispInfo->item.pszText, patch.comment.c_str(),
                      pDispInfo->item.cchTextMax);
              break;
            }
          }
        }
        break;
      }
      case NM_DBLCLK: {
        int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
        if (iItem != -1) {
          ExecuteAction(hwnd, ID_MENU_DISASM, iItem);

          // Follow + Move Logic
          if (hChkFollowMove &&
              SendMessage(hChkFollowMove, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            int nextItem = iItem + 1;
            if (nextItem < (int)g_Patches.size()) {
              // Clear current selection? In SingleSel mode, setting another
              // selects it usually.
              ListView_SetItemState(hList, nextItem,
                                    LVIS_SELECTED | LVIS_FOCUSED,
                                    LVIS_SELECTED | LVIS_FOCUSED);
              ListView_EnsureVisible(hList, nextItem, FALSE);
            }
          }
        }
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

            // 3. Selection
            // Let the system handle the selection highlight (Standard Blue)
            // to avoid issues with sub-item state persistence.
            if (pnmcd->nmcd.uItemState & CDIS_SELECTED) {
              // If we want to override colors, we can try here, but
              // removing CDIS_SELECTED breaks the chain.
              // We will rely on default Highlighting.
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
    case ID_CHK_REGEX:
      // Only respond to click events
      if (HIWORD(wParam) == BN_CLICKED) {
        ApplyFilter();
        UpdateListView();
      }
      break;

    case ID_CHK_PRO_ANALYZE:
      if (HIWORD(wParam) == BN_CLICKED) {
        g_bProAnalyze =
            (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED);
      }
      break;
    case ID_CHK_FLATTEN_LINE:
      if (HIWORD(wParam) == BN_CLICKED) {
        g_bFlattenLine =
            (SendMessage((HWND)lParam, BM_GETCHECK, 0, 0) == BST_CHECKED);
      }
      break;

    case ID_EDIT_FOLLOW_LINES:
      if (HIWORD(wParam) == EN_CHANGE) {
        BOOL trans = FALSE;
        int val = GetDlgItemInt(hwnd, ID_EDIT_FOLLOW_LINES, &trans, FALSE);
        if (trans && val > 0 && val < 100)
          g_nFollowLines = val;
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

    case ID_MENU_EXPORT_CSV: {
      char filepath[MAX_PATH] = {0};
      OPENFILENAMEA ofn = {0};
      ofn.lStructSize = sizeof(ofn);
      ofn.hwndOwner = hwnd;
      ofn.lpstrFilter = "CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
      ofn.lpstrFile = filepath;
      ofn.nMaxFile = MAX_PATH;
      ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT;
      ofn.lpstrDefExt = "csv";

      if (GetSaveFileNameA(&ofn)) {
        if (ExportTableToCSV(filepath)) {
          MessageBoxA(hwnd, "Table exported successfully!", "Success",
                      MB_OK | MB_ICONINFORMATION);
        } else {
          MessageBoxA(hwnd, "Failed to export table.", "Error",
                      MB_OK | MB_ICONERROR);
        }
      }
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
          // Optimization: Write entire oldBytes buffer at once
          if (dbgFuncs->MemPatch(patch.address, patch.oldBytes.data(),
                                 patch.oldBytes.size())) {
            allRestored = true;
          } else {
            allRestored = false;
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

    case ID_MENU_DISASM: {
      int iItem = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
      if (iItem != -1) {
        ExecuteAction(hwnd, ID_MENU_DISASM, iItem);

        // Helper for Follow Above
        auto followAbove = [&]() {
          if (hChkFollowAbove &&
              SendMessage(hChkFollowAbove, BM_GETCHECK, 0, 0) == BST_CHECKED) {
            duint currentAddr = g_Patches[iItem].head;

            // Read custom lines from edit box
            // Read custom lines from persistent global
            int lines = g_nFollowLines;

            duint target = currentAddr;
            char buf[256];

            // Always Log global state
            bool useProAnalyze = g_bProAnalyze;

            Log("[PatchKing] Follow Above: %d lines from 0x%llX (ProAnalyze: "
                "%s)\n",
                lines, (unsigned long long)currentAddr,
                useProAnalyze ? "ON" : "OFF");

            if (lines >= 4) {
              // Advanced Strategy for Lines >= 4 (User Requested Heuristic)
              // 1. Shift back 0xE (approx 14 bytes) to jump ~4 instructions
              duint base = currentAddr - 0xE;

              // 2. Align to instruction head using dis.prev
              sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)base);
              target = DbgValFromString(buf);
              Log("[PatchKing]   Heuristic Base:0x%llX -> Aligned:0x%llX\n",
                  (unsigned long long)base, (unsigned long long)target);

              // 3. Backtrack remaining steps (lines - 4)
              int backSteps = lines - 4;
              for (int k = 0; k < backSteps; k++) {
                sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)target);
                duint prev = DbgValFromString(buf);
                Log("[PatchKing]   Step(Heuristic) %d: 0x%llX -> 0x%llX\n",
                    k + 1, (unsigned long long)target,
                    (unsigned long long)prev);
                target = prev;
              }
            } else {
              // Simple Strategy for Lines < 4 using direct dis.prev
              // This replaces the old unreliable scan logic
              for (int i = 0; i < lines; i++) {
                sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)target);
                duint prev = DbgValFromString(buf);
                Log("[PatchKing]   Step(Simple) %d: 0x%llX -> 0x%llX\n", i + 1,
                    (unsigned long long)target, (unsigned long long)prev);
                target = prev;
              }
            }

            // --- PRO ANALYZE CORRECTION ---
            // If ProAnalyze is ON, use the found 'target' as a sync point to
            // scan FORWARD to find the TRUE instruction covering currentAddr.
            // Then backtrack from THERE.
            duint finalTop = target;
            duint selectionAddr = currentAddr;

            if (useProAnalyze) {
              duint syncPoint = target; // Start scanning from where we landed
              duint trueHead = 0;
              duint scanCur = syncPoint;

              Log("[PatchKing]   ProAnalyze: Scanning forward from SyncPoint "
                  "0x%llX to find 0x%llX\n",
                  (unsigned long long)syncPoint,
                  (unsigned long long)currentAddr);

              // Scan forward max 30 instructions to avoid infinite loops
              for (int i = 0; i < 30; i++) {
                BASIC_INSTRUCTION_INFO instr;
                unsigned char data[16];
                memset(&instr, 0, sizeof(instr));
                if (DbgMemRead(scanCur, data, 16) &&
                    DbgFunctions()->DisasmFast(data, scanCur, &instr)) {
                  duint next = scanCur + instr.size;
                  // Check if this instruction COVERS currentAddr
                  // i.e. scanCur <= currentAddr < next
                  if (scanCur <= currentAddr && currentAddr < next) {
                    trueHead = scanCur;
                    Log("[PatchKing]   ProAnalyze: Found TrueHead 0x%llX (Size "
                        "%d) covering target\n",
                        (unsigned long long)trueHead, instr.size);
                    break;
                  }
                  scanCur = next;
                  if (scanCur > currentAddr) {
                    Log("[PatchKing]   ProAnalyze: Overshot target without "
                        "match (ScanCur 0x%llX > Target)\n",
                        (unsigned long long)scanCur);
                    break;
                  }
                } else {
                  scanCur++; // Byte step if disasm fails
                }
              }

              if (trueHead != 0) {
                selectionAddr = trueHead;
                // Now Backtrack 'lines' steps from THIS true head to get the
                // final display address Logic duplication - Backtrack from
                // trueHead
                if (lines >= 4) {
                  duint base = trueHead - 0xE;
                  sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)base);
                  duint aligned = DbgValFromString(buf);
                  int backSteps = lines - 4;
                  duint tempT = aligned;
                  for (int k = 0; k < backSteps; k++) {
                    sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)tempT);
                    tempT = DbgValFromString(buf);
                  }
                  finalTop = tempT;
                } else {
                  duint tempT = trueHead;
                  for (int i = 0; i < lines; i++) {
                    sprintf(buf, "dis.prev(0x%llX)", (unsigned long long)tempT);
                    tempT = DbgValFromString(buf);
                  }
                  finalTop = tempT;
                }
                Log("[PatchKing]   ProAnalyze: Final Corrected Top: 0x%llX\n",
                    (unsigned long long)finalTop);
              } else {
                Log("[PatchKing]   ProAnalyze: Failed to find TrueHead, "
                    "falling back to original logic.\n");
              }
            }

            // Display at newTop, but keep selection at currentAddr
            GuiDisasmAt(finalTop, selectionAddr);
          }
        };

        followAbove();

        // Follow + Move Logic
        if (hChkFollowMove &&
            SendMessage(hChkFollowMove, BM_GETCHECK, 0, 0) == BST_CHECKED) {
          int nextItem = iItem + 1;
          if (nextItem < (int)g_Patches.size()) {
            // Explicitly clear old selection to ensure visual update
            ListView_SetItemState(hList, iItem, 0,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            // Set new selection
            ListView_SetItemState(hList, nextItem, LVIS_SELECTED | LVIS_FOCUSED,
                                  LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(hList, nextItem, FALSE);
            UpdateWindow(hList); // Force repaint
          }
        }
      }
      break;
    }

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

    // Attempt 2: RVA (ImageBase + Addr) - PRIORITY per User Request
    // ("Default add ImageBase")
    if (!patched && imageBase != 0) {
      if (dbgFuncs->MemPatch(imageBase + addr, &newB, 1)) {
        Log("[PatchMgr] Line %d: Patched via RVA (%p + %p -> %p)\n", lineNum,
            (void *)imageBase, (void *)addr, (void *)(imageBase + addr));
        patched = true;
      }
    }

    // Attempt 3: File Offset -> VA (Fallback)
    // Only used if RVA failed (e.g. address wasn't a valid RVA or memory
    // not mapped there)
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

bool ExportTableToCSV(const char *filepath) {
  FILE *fp = fopen(filepath, "w");
  if (!fp)
    return false;

  // Write UTF-8 BOM
  fputc(0xEF, fp);
  fputc(0xBB, fp);
  fputc(0xBF, fp);

  fprintf(fp, "Address,Module,Old Bytes,New Bytes,Old Instruction,New "
              "Instruction,Comment\n");

  auto safeObj = [](const std::string &s) {
    std::string out = "\"";
    for (char c : s) {
      if (c == '"')
        out += "\"\"";
      else
        out += c;
    }
    out += "\"";
    return out;
  };

  for (const auto &p : g_Patches) {
    char addrBuf[32];
    sprintf(addrBuf, "%p", (void *)p.address);

    fprintf(
        fp, "%s,%s,%s,%s,%s,%s,%s\n", addrBuf, safeObj(p.moduleName).c_str(),
        safeObj(BytesToHex(p.oldBytes)).c_str(),
        safeObj(BytesToHex(p.newBytes)).c_str(), safeObj(p.oldDisasm).c_str(),
        safeObj(p.disasm).c_str(), safeObj(p.comment).c_str());
  }

  fclose(fp);
  return true;
}
