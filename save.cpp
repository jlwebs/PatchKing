#include "PatchWindow.h"
#include "pluginmain.h"

#include "pluginsdk/_scriptapi_module.h"
#include <cctype>
#include <cstdio>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

extern "C" __declspec(dllimport) void GuiUpdateAllViews();

// Helper: Log to x64dbg log
static void Log(const char *format, ...) {
  char buffer[1024];
  va_list args;
  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  _plugin_logputs(buffer);
}

static std::string BytesToHex(const std::vector<unsigned char> &bytes) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    if (i > 0)
      ss << " ";
    ss << std::setw(2) << (int)bytes[i];
  }
  return ss.str();
}

bool ImportAndApplyPatches(HWND hwnd, const char *filepath) {
  FILE *fp = fopen(filepath, "r");
  if (!fp) {
    MessageBoxA(hwnd, "Failed to open file!", "Error", MB_ICONERROR);
    return false;
  }

  const DBGFUNCTIONS *dbgFuncs = DbgFunctions();
  if (!dbgFuncs || !dbgFuncs->MemPatch) {
    fclose(fp);
    MessageBoxA(hwnd, "Debugger not ready (MemPatch unavailable).", "Error",
                MB_ICONERROR);
    return false;
  }

  // Strategy A: Robust ImageBase Resolution (Default to Main)
  duint mainBase = Script::Module::GetMainModuleBase();
  if (mainBase == 0 && dbgFuncs->ValFromString) {
    dbgFuncs->ValFromString("imagebase", &mainBase);
  }

  duint currentBase = mainBase; // Default base
  char currentModName[MAX_MODULE_SIZE] = {0};

  // Initialize currentModName with main module
  if (mainBase != 0 && dbgFuncs->ModNameFromAddr) {
    dbgFuncs->ModNameFromAddr(mainBase, currentModName, false);
    Log("[PatchMgr] Default Module: %s (Base: %p)\n", currentModName,
        (void *)mainBase);
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

    if (line.empty() || line[0] == '#' || line[0] == ';')
      continue;

    // Handle Module Switch (>Target.dll)
    if (line[0] == '>') {
      std::string modName = line.substr(1);
      // Trim again just in case
      while (!modName.empty() && (isspace((unsigned char)modName.back())))
        modName.pop_back();
      while (!modName.empty() && (isspace((unsigned char)modName.front())))
        modName.erase(0, 1);

      if (!modName.empty()) {
        // Resolve new base
        if (dbgFuncs->ModBaseFromName) {
          currentBase = dbgFuncs->ModBaseFromName(modName.c_str());
        } else {
          currentBase = 0;
        }

        if (currentBase == 0) {
          Log("[PatchMgr] Line %d: Warning: Module '%s' not found. Patches may "
              "fail.\n",
              lineNum, modName.c_str());
        } else {
          Log("[PatchMgr] Switch to Module: %s (Base: %p)\n", modName.c_str(),
              (void *)currentBase);
        }
        strncpy(currentModName, modName.c_str(), MAX_MODULE_SIZE - 1);
      }
      continue;
    }

    // Parse
    size_t col = line.find(':');
    size_t arr = line.find("->");

    duint addr = 0;
    unsigned char oldB = 0;
    unsigned char newB = 0;
    bool hasOld = false;
    bool validParse = false;

    try {
      if (col != std::string::npos && arr != std::string::npos && arr > col) {
        // Format: Address:Old->New
        addr = (duint)std::stoull(line.substr(0, col), nullptr, 16);
        oldB = (unsigned char)std::stoul(line.substr(col + 1, arr - (col + 1)),
                                         nullptr, 16);
        newB = (unsigned char)std::stoul(line.substr(arr + 2), nullptr, 16);
        hasOld = true;
        validParse = true;
      } else if (col != std::string::npos) {
        // Format: Address:New
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

    // Determine Target Address
    // If currentBase is set (via >Module or default Main), treat addr as RVA.
    // If user didn't provide >Module, we used default Main.
    // This matches user requirement "1337 uses relative address".

    duint targetVA = 0;

    // Priority: RVA
    if (currentBase != 0) {
      targetVA = currentBase + addr;
    } else {
      // Fallback to raw if no base found
      targetVA = addr;
    }

    // "For 1337 format check if matches"
    if (hasOld) {
      unsigned char memByte = 0;
      if (DbgMemRead(targetVA, &memByte, 1)) {
        if (memByte != oldB) {
          Log("[PatchMgr] Line %d: Check Verification Failed at %p! File: "
              "%02X, Memory: %02X. Skipping.\n",
              lineNum, (void *)targetVA, oldB, memByte);
          failCount++;
          continue;
        }
      } else {
        Log("[PatchMgr] Line %d: Memory Read Failed at %p. Skipping.\n",
            lineNum, (void *)targetVA);
        failCount++;
        continue;
      }
    }

    bool patched = false;

    // Apply
    if (dbgFuncs->MemPatch(targetVA, &newB, 1)) {
      Log("[PatchMgr] Line %d: Patched %p\n", lineNum, (void *)targetVA);
      patched = true;
    }

    // Fallback: File Offset (Only if RVA failed or confusing? Usually RVA
    // covers it)
    if (!patched && dbgFuncs->FileOffsetToVa && currentModName[0] != 0) {
      // Treat 'addr' as file offset?
      // User said "1337 uses relative address".
      // But maybe old logic supported offset.
      // If we failed via RVA, maybe try FileOffset?
      // Let's keep it simple: If RVA valid, trust it.
    }

    if (patched) {
      successCount++;
    } else {
      Log("[PatchMgr] Line %d: FAILED to patch %p.\n", lineNum,
          (void *)targetVA);
      failCount++;
    }
  }
  fclose(fp);

  GuiUpdateAllViews();

  char msg[256];
  sprintf(msg, "Import complete (Base: %p).\nSuccess: %d\nFailed: %d",
          (void *)currentBase, successCount, failCount);
  MessageBoxA(hwnd, msg, "Patch Import", MB_ICONINFORMATION);

  return successCount > 0;
}

bool ExportPatches(const char *filepath, bool asPatchKingFormat) {
  FILE *fp = fopen(filepath, "w");
  if (!fp)
    return false;

  if (asPatchKingFormat) {
    fprintf(fp,
            "# PatchKing plugin proprietary export format, ignores old bytes "
            "(Patch King v1.0)\n");
    fprintf(fp, "# Format: Address:NewByte\n\n");
  } else {
    // 1337 Compatible
    fprintf(fp, "# PatchKing plugin exported compatible format (Patch King "
                "v1.0)\n");
    fprintf(fp, "# Format: >Target.dll\\RVA:OldByte->NewByte\n\n");
  }

  const DBGFUNCTIONS *dbg = DbgFunctions();
  std::string lastModule = "";

  // Use g_Patches which contains the currently visible/filtered patches
  for (const auto &p : g_Patches) {

    // Check module switch for 1337 format
    if (!asPatchKingFormat) {
      if (p.moduleName != lastModule) {
        fprintf(fp, ">%s\n", p.moduleName.c_str());
        lastModule = p.moduleName;
      }
    }

    // Each PatchInfo is a contiguous block
    for (size_t k = 0; k < p.oldBytes.size(); ++k) {
      duint currentAddr = p.address + k;
      unsigned char oldB = p.oldBytes[k];
      unsigned char newB =
          (k < p.newBytes.size()) ? p.newBytes[k] : 0; // Should match size

      if (asPatchKingFormat) {
        // Proprietary format: Address:NewByte (Absolute)
        fprintf(fp, "%p:%02X\n", (void *)currentAddr, newB);
      } else {
        // Compatible format: RVA:OldByte->NewByte
        // Calculate RVA
        duint base = 0;
        if (dbg && dbg->ModBaseFromAddr) {
          base = dbg->ModBaseFromAddr(currentAddr);
        }
        duint rva = currentAddr - base;

        fprintf(fp, "%llX:%02X->%02X\n", (unsigned long long)rva, oldB, newB);
      }
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
