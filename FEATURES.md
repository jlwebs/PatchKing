# [DEPRECATED / 已废弃] Patch Manager Features
> **Final Solution**: [SOLUTION_SUMMARY.md](./SOLUTION_SUMMARY.md)

## ✅ 已实现功能

### 列显示（完全仿照 OD）
- [x] **Address** - 补丁地址（十六进制，80px）
- [x] **Old Bytes** - 原始字节码（120px）
- [x] **New Bytes** - 修改后字节码（120px）
- [x] **Old** - 修改前的反汇编指令（250px）
- [x] **New** - 修改后的反汇编指令（250px）
- [x] **Comment** - 用户注释（200px）

### 快捷键（完全仿照 OD）
- [x] `Enter` - 反汇编窗口中跟随
- [x] `Plus` (+) - 跟随下一个补丁
- [x] `Minus` (-) - 跟随上一个补丁
- [x] `Space` - 应用补丁
- [x] `Shift+Space` - 还原补丁
- [x] `Del` - 删除记录
- [x] `F5` - 刷新列表
- [x] `Ctrl+O` - 导入补丁文件
- [x] `Ctrl+S` - 导出补丁文件

### 右键菜单
- [x] Import Patch File... (Ctrl+O)
- [x] Export Patch File... (Ctrl+S)
- [x] Refresh (F5)
- [x] Follow in Disassembler (Enter)
- [x] Apply Patch (Space)
- [x] Restore Patch (Shift+Space)
- [x] Delete Patch (Del)

### 导入/导出功能
- [x] **导入补丁** - 读取文件并**自动应用**到内存
- [x] **导出补丁** - 使用 x32dbg 的 `PatchFile` API 导出
- [x] 支持格式：`Address:OldByte->NewByte`
- [x] 导入后自动刷新显示

### 核心逻辑
- [x] 自动同步 x32dbg 内部补丁列表
- [x] 连续字节自动分组
- [x] 使用 `DbgFunctions()->MemPatch()` 应用补丁
- [x] 使用 `DbgDisasmAt()` 获取反汇编文本（含自动注释）
- [x] 显示修改前后的反汇编对比

## 📋 待实现功能
- [ ] 删除模块中的所有记录
- [ ] F2 - 切换断点
- [ ] Shift+F2 - 条件断点
- [ ] Shift+F4 - 条件记录断点
- [ ] 用户注释编辑功能

## 🎯 使用说明

### 列布局
```
| Address | Old Bytes | New Bytes | Old           | New           | Comment |
|---------|-----------|-----------|---------------|---------------|---------|
| 401006  | 83 c2...  | 90 90...  | add edx,0x10  | nop           |         |
| 40100C  | 56        | 90        | push esi      | nop           |         |
```

### 导入补丁并应用
1. 右键 → Import Patch File... (或 Ctrl+O)
2. 选择补丁文件（格式：`00401000:90->EB`）
3. 插件自动应用所有补丁到内存
4. 自动刷新显示

### 导出补丁
1. 右键 → Export Patch File... (或 Ctrl+S)
2. 选择保存位置
3. 使用 x32dbg 原生格式导出

### 快捷键操作
- 按 `Space` 应用选中的补丁
- 按 `Shift+Space` 还原补丁
- 按 `+/-` 在补丁列表中导航
- 按 `Enter` 跳转到反汇编窗口
