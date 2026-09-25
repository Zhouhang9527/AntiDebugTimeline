# AntiDebugTimeline

> Windows Anti-Debugging Research & Runtime Analysis Lab

AntiDebugTimeline 是一个用于学习 **Windows 反调试机制、逆向分析和运行时行为研究** 的实验项目。

项目通过自建测试程序、DLL 注入、Hook 和运行时 Patch 等方式，复现常见反调试检测流程，并记录不同检测方式的原理、触发条件以及实验结果。

本项目仅用于本地实验环境、CTF 和授权安全研究。

---

## Features

- Windows Anti-Debug 技术复现
- DLL 注入与运行时分析
- API Hook 实验
- PEB / NT API / Heap Debug Flag 分析
- 调试环境检测研究
- JSONL 实验日志记录

---

## Architecture

```text
AntiDebugTimeline
│
├── Controller
│   └── GUI 控制端
│       ├── 进程管理
│       ├── DLL 注入
│       └── 日志查看
│
├── Agent
│   └── 注入 DLL
│       ├── Hook API
│       ├── 修改运行状态
│       └── 输出分析日志
│
├── Sample
│   └── 测试目标程序
│
└── Demos
    └── 单项反调试技术演示
```

---

## Research Topics

### Debugger Detection

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess`
  - `ProcessDebugPort`
  - `ProcessDebugObjectHandle`
  - `ProcessDebugFlags`

### Environment Analysis

- PEB `BeingDebugged`
- PEB `NtGlobalFlag`
- Heap Debug Flags
- Parent Process Detection
- Window Class Detection

### Runtime Behavior Analysis

- API Hook
- DLL Injection
- Runtime Patch
- Thread Debug Protection Analysis

---

## Build

Environment:

- Visual Studio 2022
- Windows SDK
- x64

Build:

```bat
msbuild AntiDebugTimeline.sln /p:Configuration=Debug /p:Platform=x64
```

或者直接使用 Visual Studio 打开解决方案构建。

---

## Workflow

```text
Target Process
      |
      v
Controller
      |
      v
Inject Agent.dll
      |
      v
Hook / Analyze Runtime Behavior
      |
      v
Generate JSONL Logs
```

---

## Purpose

该项目用于帮助理解：

- 软件如何检测调试环境
- 逆向分析中常见的反调试技术
- 用户态 Hook 与运行时修改原理
- Windows 安全机制与限制

持续记录逆向分析学习过程。
