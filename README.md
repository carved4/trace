# trace

a windows x64 stack tracer written in go. given a process name or pid, it suspends each thread, captures the cpu context, and walks the call stack and prints resolved module+symbol+offset frames for every thread.

adapted from [stacktracer](https://github.com/whokilleddb/stacktracer) by whokilleddb. the original used dbghelp (`StackWalk64`, `SymFromAddrW`, etc.). this version reimplements everything manually with no dbghelp :3 and no symbol engine, also no kernel32 imports.


## how it works

- process and thread handles opened via `NtOpenProcess` / `NtOpenThread`; threads suspended with `NtSuspendThread` and resumed on defer
- cpu context captured with `NtGetContextThread` into a manually 16-byte aligned buffer (required by the mr windows)
- loaded modules enumerated by reading the target process's peb module list via `NtQueryInformationProcess` + `NtReadVirtualMemory`
- each module's pe headers parsed remotely to extract the `.pdata` exception directory (`RUNTIME_FUNCTION` table, pe32+ layout assumed since we only target x64 processes)
- x64 unwind codes (`UWOP_*`) interpreted to unwind each frame, following chained unwind info where present
- for leaf frames (no unwind record) or unknown modules, rsp is scanned upward to find the next valid return address in a known module
- addresses resolved to `module!symbol+offset` by walking pe export tables directly in the target process, using the closest export at or before the rva


## usage

```
trace [flags]

flags:
  --pid   uint32   target process id
  --name  string   process name, partial match (e.g. spotify, Spotify.exe)
  --tid   uint32   specific thread id to trace (default: all threads)
```

### examples

```
# trace all threads in notepad
trace --name notepad

# trace all threads by pid
trace --pid 1234

# trace a single thread
trace --pid 1234 --tid 5678
```

## building

requires go 1.21+

```
go build -o trace.exe .
```

## credits

- original tool: [stacktracer](https://github.com/whokilleddb/stacktracer) by whokilleddb