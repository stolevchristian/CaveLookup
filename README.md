# CaveLookup

A simple but useful code-cave enumerator for external process memory analysis.

## Overview

CaveLookup is a Windows tool that scans executable memory regions of a target process to find code caves — contiguous blocks of null bytes that can potentially be used for code injection, hooking, or other reverse engineering purposes.

## Features

- Enumerate all executable memory regions in a target process
- Identify code caves (contiguous null byte sequences) of configurable minimum size
- Display memory protection flags in human-readable format
- Filter by memory type (image, private, mapped)

## Requirements

- Windows OS
- Visual Studio or MinGW with C++17 support
- Administrator privileges (for accessing protected processes)

## Example Output

```
Found cave at 0x7ff6a0045d19 [permission: PAGE_EXECUTE_READWRITE]
Found cave at 0x7ff6a0048000 [permission: PAGE_EXECUTE_READWRITE]
```

## Notes
- `PAGE_EXECUTE_READWRITE` regions are particularly interesting as they allow both code execution and modification
- Adjust `MIN_CAVE_SIZE` based on your needs (common values: 32 bytes for small hooks, 4096+ for larger payloads)

## Dependencies

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
```

## License

MIT License

## Disclaimer

This tool is intended for legitimate reverse engineering, security research, and educational purposes only. Always ensure you have proper authorization before analyzing software you do not own.
