#pragma once
#include "pluginsdk/_plugin_types.h" // For duint (if not using pluginmain.h to avoid full include)
#include <string>
#include <vector>

// Standard Patch Structure
struct PatchInfo {
  duint address;
  duint head; // Instruction start address
  std::vector<unsigned char> oldBytes;
  std::vector<unsigned char> newBytes;
  std::string comment;   // User comment
  std::string oldDisasm; // Disassembly BEFORE patch
  std::string disasm;    // Disassembly AFTER patch
  bool active;
  std::string moduleName;
};

// Global Patch List
extern std::vector<PatchInfo> g_Patches;

void OpenPatchWindow();
void ClosePatchWindow();
void RefreshPatchList();
bool LoadPatchesFromFile(const char *filepath);
void SavePatchesToFile(const char *filepath);
