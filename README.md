# AntiDebugTimeline

AntiDebugTimeline 是一个 Windows 反调试机制学习与实验项目，面向 CTF、逆向工程教学和授权安全研究场景。仓库用于复现和分析 Windows 常见反调试检测手段，并在自写测试程序中验证 DLL 注入、Hook、Patch 等运行时行为修改方法的效果。

> 本项目仅用于本地实验环境和授权安全研究。不面向第三方软件绕过，不用于规避商业软件保护，不包含恶意载荷。

## 项目目标

- 理解常见 Windows 反调试检测点
- 复现反调试逻辑的触发条件
- 分析检测 API 和底层结构之间的关系
- 使用 DLL 注入方式验证运行时行为修改
- 总结逆向分析时的识别特征和局限性

## 项目结构

```text
AntiDebugTimeline.sln        Visual Studio 解决方案
源.cpp                       Controller GUI 主程序
Shared/                      Controller 和 Agent 共享配置常量
Agent/                       注入目标进程的 DLL，负责检测、日志和绕过
Sample/                      自动循环触发反调试检查的测试程序
Demos/                       反调试技术演示集合
  AntiDebugDemo.cpp          聚合菜单式 demo，可直接作为 VS 项目构建
  individual/                单项 demo 源码，作为参考保留，不参与 VS 项目编译
```

## 方案项目

| 项目 | 类型 | 作用 |
| --- | --- | --- |
| Controller | Windows GUI exe | 枚举进程、选择 Agent、写入配置、注入 DLL、查看 JSONL 日志 |
| Agent | DLL | Hook 常见反调试 API / NT API，清理 PEB 和堆调试标志，输出检测日志 |
| Sample | Console exe | 周期性触发多种反调试检查，适合验证 Agent 是否生效 |
| AntiDebugDemo | Console exe | 菜单式演示 IsDebuggerPresent、PEB、NtQuery、窗口检测、父进程、时间差等技术 |

## 支持的检测/绕过点

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess`
  - `ProcessDebugPort`
  - `ProcessDebugObjectHandle`
  - `ProcessDebugFlags`
- PEB `BeingDebugged`
- PEB `NtGlobalFlag`
- 进程堆 `Flags` / `ForceFlags`
- `OutputDebugStringA/W`
- `NtSetInformationThread(ThreadHideFromDebugger)`
- `GetThreadContext` 调试寄存器清理

`Demos/AntiDebugDemo.cpp` 额外包含窗口类检测、父进程检测、`DebugBreak`、RDTSC/QPC/GetTickCount 时间差检测等演示代码。

## 构建

推荐使用 Visual Studio 2022：

1. 打开 `AntiDebugTimeline.sln`
2. 选择 `Debug|x64` 或 `Release|x64`
3. 构建整个解决方案

也可以在 Developer PowerShell / Developer Command Prompt 中使用 MSBuild：

```bat
msbuild AntiDebugTimeline.sln /p:Configuration=Debug /p:Platform=x64
```

如果只想单独构建 demo，可进入 `Demos` 目录运行：

```bat
build.bat
```

## 使用流程

1. 构建 `Agent`、`Controller`、`Sample`。
2. 启动 `Controller.exe`。
3. 在 Controller 中确认 `Agent.dll` 路径。
4. 选择一个已运行进程后点击 `Inject`，或选择目标 exe 后点击 `Launch+inject paused`。
5. 在右侧勾选需要检测/绕过的功能。
6. 查看 Controller 下方日志窗口，或打开 `Agent` 同目录下的 `logs/AntiDebugTimeline.jsonl`。

`Launch+inject paused` 适合需要在程序早期注入的样例：Controller 会以挂起模式创建目标进程，注入 Agent，短暂运行后再次挂起，方便再附加调试器观察。

## 日志与配置

Controller 会在 `Agent.dll` 同目录写入：

- `AntiDebugTimeline.ini`：当前检测和绕过 mask。
- `logs/AntiDebugTimeline.jsonl`：Agent 输出的逐行 JSON 日志。

常见日志事件包括：

- `agent_loaded`
- `hook_installed` / `hook_failed`
- `peb_observed` / `peb_cleaned`
- `heap_flags_summary`
- API 调用记录，如 `IsDebuggerPresent`、`NtQueryInformationProcess`

## 注意事项

- Controller、Agent、目标进程位数需要匹配，建议统一使用 x64。
- `NtSetInformationThread(ThreadHideFromDebugger)`、`DebugBreak` 等 demo 会影响调试体验，运行前注意菜单提示。
- `Demos/individual` 下每个文件都有独立 `main()`，因此在 VS 项目中作为参考文件保留，不直接编译。
