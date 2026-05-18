# runShellcode - PopCalcShellcode

Windows x64 position-independent shellcode that resolves `WinExec` from `kernel32.dll` at runtime and launches `calc.exe`. The core shellcode is **205 bytes** (no null bytes, with lightweight string obfuscation to reduce trivial static signatures). The C loader embeds it with a **7-byte epilogue** so the `CreateThread` routine returns cleanly, for a total embedded payload of **212 bytes**.

## Overview

| Property | Value |
|----------|-------|
| Architecture | x64 (Windows) |
| Core shellcode size (from NASM) | 205 bytes |
| Embedded payload size (in `runShellcode.c`) | 212 bytes (205 + 7-byte clean-return epilogue) |
| Position independent | Yes |
| API resolution | PEB walk → `kernel32.dll` export table |
| Target API | `WinExec("calc.exe", SW_SHOWNORMAL)` |
| Null bytes | Avoided in shellcode bytes |
| Thread-safe exit | Yes (epilogue unwinds stack + `ret`s with `eax = 0`) |

### Execution flow

```
TEB (gs:[0x60]) ─► PEB
                    └► PEB.Ldr (PEB_LDR_DATA, +0x18)
                          └► InMemoryOrderModuleList (+0x20)
                                ├─ Flink 1: <exe>
                                ├─ Flink 2: ntdll.dll
                                └─ Flink 3: kernel32.dll ─► DllBase (+0x20 from list link)
                                                             └► PE Export Directory
                                                                 ├─ AddressTable
                                                                 ├─ NamePointerTable
                                                                 └─ OrdinalTable
                                                                     └► Match "WinExec"
                                                                         └► WinExec("calc.exe", 1)
```

1. **Locate `kernel32.dll`** - From `gs:[0x60]` (PEB), read `PEB.Ldr` at `+0x18`, then walk `InMemoryOrderModuleList` (offset `+0x20` in `PEB_LDR_DATA`) three `Flink`s to reach `kernel32.dll`. `DllBase` is read from `+0x20` relative to the entry's `InMemoryOrderLinks` field.
2. **Parse exports** - Resolve `e_lfanew` (`+0x3C`), then the Export Directory pointers: `AddressTable` (`+0x1C`), `NamePointerTable` (`+0x20`), `OrdinalTable` (`+0x24`).
3. **Resolve `WinExec`** - Stack-based API name lookup via `repe cmpsb` against export names (`getapiaddr` / `resolveaddr` labels).
4. **Invoke** - Reconstruct `calc.exe` on the stack via `NOT`, set `uCmdShow = 1`, reserve `0x20` shadow space, call `WinExec`.

### OPSEC-oriented details

- API and command strings are built with `NOT` / `SHR` instead of embedding plain `WinExec` or `calc.exe` literals.
- Register tricks (e.g. `mul rdi`, `add cx, 0x88ff` + `shr`) avoid nulls in common instruction encodings.
- `sub rsp, 0x20` before `WinExec` accounts for stack clobbering when the call is proxied internally (e.g. to `CreateProcessA`).

## Repository layout

| File | Purpose |
|------|---------|
| `popcalcshellcode-asm.x64.asm` | NASM source for the shellcode |
| `runShellcode.c` | Minimal loader: `VirtualAlloc (RW)` → copy → `VirtualProtect (RX)` → `CreateThread` → `WaitForSingleObject` |
| `README.md` | This document |
| `LICENSE` | MIT License |

## Prerequisites

**Assemble / extract shellcode (Linux / WSL / Kali):**

- [NASM](https://www.nasm.us/)
- `objdump` (binutils)

**Run the loader (Windows x64):**

- MSVC (`cl`) or MinGW-w64 (`x86_64-w64-mingw32-gcc`)

## Build shellcode from assembly

From the repository root:

```bash
nasm -f win64 popcalcshellcode-asm.x64.asm -o popcalcshellcode-asm.x64.o
```

Extract escaped bytes for embedding in C (adjust the object path if needed):

```bash
for i in $(objdump -D popcalcshellcode-asm.x64.o | grep "^ " | cut -f2); do echo -n "\x$i"; done
```

Verify the resulting byte count:

```bash
for i in $(objdump -D popcalcshellcode-asm.x64.o | grep "^ " | cut -f2); do echo -n "\x$i"; done \
  | wc -c | awk '{print $1/4}'
```

> Each `\xNN` is 4 characters on disk, so dividing the byte count by 4 yields the actual shellcode length. Expected: **205** for the core shellcode only. The C loader appends a 7-byte clean-return epilogue, so the embedded `payload_len` in `runShellcode.c` is **212**.

After any change to the assembly:

1. Replace the first string literal in `runShellcode.c`'s `payload[]` with the new extracted bytes.
2. Leave the second string literal (`"\x48\x83\xc4\x38\x31\xc0\xc3"`) - the clean-return epilogue - unchanged unless the ASM's stack delta also changes.
3. Set `payload_len = <extracted bytes> + 7`.

## Run the loader

Compile on Windows x64.

**MSVC:**

From an **x64 Native Tools Command Prompt for VS**:

```cmd
cl runShellcode.c
runShellcode.exe
```

**MinGW (cross-compile or on Windows):**

```bash
x86_64-w64-mingw32-gcc runShellcode.c -o runShellcode.exe
```

**Expected behavior:**

1. Prints `Starting program...`.
2. Allocates an RW buffer with `VirtualAlloc`, copies the shellcode in.
3. Flips the buffer to `PAGE_EXECUTE_READ` via `VirtualProtect` (RW → RX, avoiding RWX).
4. Spawns the shellcode in a new thread with `CreateThread` and blocks on `WaitForSingleObject(th, INFINITE)`.
5. `calc.exe` opens. The shellcode's appended epilogue unwinds the stack and `ret`s, the thread exits with code `0`, `WaitForSingleObject` returns, and the loader prints `Ending program...`.

> Without the epilogue, `WinExec` would return into garbage on the stack, the thread would access-violate, and `WaitForSingleObject` would either hang or terminate uncleanly - so the second print line would not be reliable.

The loader pattern is adapted from [@sektor7net](https://twitter.com/sektor7net).

## Embedded shellcode and clean-return epilogue

`runShellcode.c` ships with the current 205-byte blob plus a 7-byte epilogue, pre-embedded as two adjacent string literals (C concatenates them at compile time):

```c
unsigned char payload[] =
  "\x48\x31\xff\x48\xf7\xe7..."   // 205 bytes of core shellcode
  "\x48\x83\xc4\x38\x31\xc0\xc3"; // 7-byte clean-return epilogue
unsigned int payload_len = 212;
```

The epilogue disassembles to:

```nasm
add rsp, 0x38   ; unwind 0x20 shadow space + 3 stack-resident qwords (see below)
xor eax, eax    ; thread exit code = 0
ret             ; return to the LPTHREAD_START_ROUTINE shim
```

### Stack-unwind math (`0x38`)

By the time control reaches the epilogue, the following bytes are still on the stack from the WinExec call sequence in `popcalcshellcode-asm.x64.asm`:

| Source | Size | Notes |
|--------|------|-------|
| Leftover encoded `WinExec` qword | `0x08` | Pushed before `call getapiaddr`; the helper never pops the string itself |
| `push rax` (null terminator for `calc.exe`) | `0x08` | |
| `push rax` (`"calc.exe"` qword) | `0x08` | |
| `sub rsp, 0x20` (Win64 shadow space) | `0x20` | Required by Win64 ABI for `WinExec` |
| **Total** | **`0x38`** | Matches `add rsp, 0x38` in the epilogue |

If you modify the assembly's stack usage, recompute the epilogue's `add rsp, ...` delta accordingly and reassemble - the simplest way is to fold the epilogue back into the `.asm` file and re-extract.

## MITRE ATT&CK (simulation context)

Only techniques that actually describe behavior in this repository are listed:

| Technique | ID | Behavior in this repo |
|-----------|-----|------------------------|
| Reflective Code Loading | [T1620](https://attack.mitre.org/techniques/T1620/) | Raw shellcode loaded into memory and executed in the current process (`VirtualAlloc` → `VirtualProtect` → `CreateThread`) without touching `LoadLibrary` |
| Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | Shellcode invokes `WinExec` (kernel32) resolved at runtime; loader uses `VirtualAlloc` / `VirtualProtect` / `CreateThread` |
| Dynamic API Resolution | [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | PEB walk + manual export-table parsing to resolve `WinExec` without imports |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Strings `WinExec` and `calc.exe` built on the stack via `NOT` / `SHR`, not stored as cleartext |

## References

- Shellcode runner pattern: [sektor7net](https://twitter.com/sektor7net)
- PEB / export-table techniques: standard MalDev and shellcode development material
- [PEB_LDR_DATA structure (Microsoft Docs)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data)
- [`WinExec` (Microsoft Docs)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)

## License

Released under the [MIT License](LICENSE). Copyright (c) 2026 Manuel Diaz.

The software is provided "as is", without warranty of any kind. See `LICENSE` for the full text.
