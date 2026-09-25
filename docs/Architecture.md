# Architecture

## Overview

AntiDebugTimeline consists of three main components:

```
Controller
    |
    | DLL Injection
    v
Agent.dll
    |
    +-- API Hook
    +-- PEB Analysis
    +-- NT API Analysis
    +-- Runtime Logging
```

## Controller

Responsibilities:

- Enumerate target processes
- Configure analysis options
- Inject Agent.dll
- Monitor logs

## Agent

Agent runs inside the target process.

Responsibilities:

- Install runtime hooks
- Analyze anti-debug checks
- Modify experimental behavior
- Generate JSONL logs

## Shared Configuration

Controller and Agent share feature flags through `AntiDebugConfig.h`.

This keeps detection options consistent between the controller and injected module.
