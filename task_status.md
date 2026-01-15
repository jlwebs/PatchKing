# Current Task: x32dbg Patch Plugin Development

## Objective
Create a native C++ plugin for x32dbg that replicates the functionality of the "Patches" window (similar to OllyDbg), enabling dynamic patching, breakpoint management, and disassembler integration.

## # [DEPRECATED / 已废弃] Patch Manager Task Status
> **Final Solution**: [SOLUTION_SUMMARY.md](./SOLUTION_SUMMARY.md)

### Completed
1.  **Project Initialization**:
    *   Created `PatchPlugin` directory in `d:/GitHub/patch-manager-master/`.
    *   Copied `pluginsdk` from `ClawSearch` project.
    *   Created core source files.
    *   Created `PatchPlugin.vcxproj`.

2.  **Build System**:
    *   Updated `PlatformToolset` to `v143` (VS2022).
    *   **Fixed Compilation Issues**:
        *   Resolved "header dependency hell" by forcing `windows.h` include before SDK headers in `_plugin_types.h` and `pluginmain.h`.
        *   Fixed include order in `_plugin_types.h` (`bridgemain.h` must be before `_dbgfunctions.h` to define `duint` and `MAX_MODULE_SIZE`).
        *   Defined `PLUG_EXPORT` correctly in `pluginmain.h` to fix linkage errors.
    *   Successfully built `x64\Debug\PatchPlugin.dp64`.
    *   **Successfully built `Debug\PatchPlugin.dp32` (32-bit version).**

### Blocking Issues
*   None. (Compilation succeeded).

### Next Steps
1.  **Verify Load (32-bit Priority)** (User Action):
    *   Copy `Debug\PatchPlugin.dp32` to `x64dbg\release\x32\plugins`.
    *   Launch **x32dbg** and verify "Patches..." menu item exists and opens a MessageBox.
    *   (Optional) Copy `x64\Debug\PatchPlugin.dp64` to `x64dbg\release\x64\plugins` for 64-bit verification.
2.  **UI Implementation**:
    *   **Implemented Basic Window**: Created `PatchWindow.cpp` using Win32 API.
    *   **Features**: Non-modal window, ListView with columns (Address, Old Bytes, New Bytes, Comment), Setup `DllMain` for instance handle.
    *   **Status**: Compiles successfully (32-bit). Export name fixed (`extern "C"`). Verified menu loads.

3.  **UI Functionality**:
    *   Added Context Menu ("Refresh", "Follow in Disassembler", "Delete Patch").
    *   Implemented `GuiDisasmAt` call.
    *   **Pending**: Implement actual Patch data structures and loading logic.

3.  **Patch Logic**:
    *   Implemented `LoadPatchesFromFile` parsing "Address:Old->New" format.
    *   Added "Load Patch File..." menu option.
## 当前状态 (Current Status)

### ✅ 已完成 (Completed)
1.  **32-bit 编译成功** - Win32 平台编译通过
2.  **UI 实现完成** - ListView 显示补丁列表
3.  **列显示**:
    *   Address - 补丁地址（十六进制）
    *   Old Bytes - 原始字节码（十六进制）
    *   New Bytes - 修改后字节码（十六进制）
    *   **Disassembly** - 反汇编指令 + 自动注释（如 `push 无壳旧版.0080EF5A`）
4.  **菜单功能完整**:
    *   Refresh - 从 x32dbg 内部补丁列表同步
    *   Follow in Disassembler - 跳转到反汇编窗口
    *   Enable/Disable Patch - 应用/还原补丁
    *   Delete Patch - 删除补丁项
5.  **核心功能实现**:
    *   `SyncPatchesFromDebugger()` - 通过 `DbgFunctions()->PatchEnum()` 同步
    *   `DbgDisasmAt()` - 获取反汇编文本（包含自动注释）
    *   `ApplyPatch()` / `RestorePatch()` - 使用 `DbgFunctions()->MemPatch()` 修改内存
    *   自动分组连续补丁
    *   双击跳转到反汇编窗口

### 🎯 核心设计理念
**完全仿照 OllyDbg Patches 窗口**：
- 打开窗口时自动从调试器同步所有现存补丁（红色标记的修改）
- 显示格式：地址 | 旧字节 | 新字节 | **反汇编（含自动注释）**
- 自动注释包括：字符串引用、函数名、模块名+偏移等
- 右键菜单支持启用/禁用补丁
- 连续字节自动分组显示

### 📋 待实现功能 (Pending)
1.  **保存补丁到文件** - 导出功能
2.  **快捷键支持** - 空格键切换补丁状态
3.  **持久化** - 自动保存/加载补丁列表
    *   Port patch loading logic from C#.
    *   Implement `GuiDisasmAt`, `DbgMemWrite`, `SetBreakpoint` calls using the SDK.

## File Context
*   `pluginmain.h`: Central header. Currently experimenting with include order here.
*   `PatchPlugin.vcxproj`: Build configuration.
*   `build_log.txt`: Contains failure logs (C4430, C3646 errors indicating missing type specifiers).

# Compile Commands (Reference)
*   **32-bit**: `& "D:\Program Files\Microsoft Visual Studio\2022\Community\MsBuild\Current\Bin\MSBuild.exe" "PatchPlugin.vcxproj" /p:Configuration=Debug /p:Platform=Win32`
*   **64-bit**: `& "D:\Program Files\Microsoft Visual Studio\2022\Community\MsBuild\Current\Bin\MSBuild.exe" "PatchPlugin.vcxproj" /p:Configuration=Debug /p:Platform=x64`
