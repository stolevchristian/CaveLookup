#include <iostream>

#include "Memory/Memory.h"

Memory m_man;

struct MemoryRegion {
    uintptr_t base;
    size_t size;
    DWORD protect;
};

std::vector<MemoryRegion> GetExecutableRegions(HANDLE hProcess) {
    std::vector<MemoryRegion> regions;

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;

    while (VirtualQueryEx(hProcess, (void*)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            regions.push_back({
                (uintptr_t)mbi.BaseAddress,
                mbi.RegionSize,
                mbi.Protect
                });
        }

        address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

        if (address < (uintptr_t)mbi.BaseAddress) break;
    }

    return regions;
}

std::string ProtectToString(DWORD protect) {
    std::string result;

    switch (protect & 0xFF) {
    case PAGE_NOACCESS:          result = "PAGE_NOACCESS"; break;
    case PAGE_READONLY:          result = "PAGE_READONLY"; break;
    case PAGE_READWRITE:         result = "PAGE_READWRITE"; break;
    case PAGE_WRITECOPY:         result = "PAGE_WRITECOPY"; break;
    case PAGE_EXECUTE:           result = "PAGE_EXECUTE"; break;
    case PAGE_EXECUTE_READ:      result = "PAGE_EXECUTE_READ"; break;
    case PAGE_EXECUTE_READWRITE: result = "PAGE_EXECUTE_READWRITE"; break;
    case PAGE_EXECUTE_WRITECOPY: result = "PAGE_EXECUTE_WRITECOPY"; break;
    default:                     result = "UNKNOWN"; break;
    }

    if (protect & PAGE_GUARD)        result += " | PAGE_GUARD";
    if (protect & PAGE_NOCACHE)      result += " | PAGE_NOCACHE";
    if (protect & PAGE_WRITECOMBINE) result += " | PAGE_WRITECOMBINE";

    return result;
}

std::wstring GetModuleNameFromAddress(HANDLE hProcess, uintptr_t address) {
    HMODULE modules[1024];
    DWORD needed;

    if (EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        for (size_t i = 0; i < needed / sizeof(HMODULE); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, modules[i], &modInfo, sizeof(modInfo))) {
                uintptr_t modBase = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t modEnd = modBase + modInfo.SizeOfImage;

                if (address >= modBase && address < modEnd) {
                    wchar_t name[MAX_PATH];
                    if (GetModuleBaseNameW(hProcess, modules[i], name, MAX_PATH)) {
                        return name;
                    }
                }
            }
        }
    }
    return L"<unknown>";
}

int main()
{
    if (!m_man.AttachProcess("GameProcess.exe"))
    {
        std::cout << "Failed to attach to process." << std::endl;
        return 0;
    }

    std::cout << "Process ID: " << m_man.m_dwPID << std::endl;
    std::cout << "Base: " << std::hex << m_man.m_gClientBaseAddr << std::endl;

    auto exec_regions = GetExecutableRegions(m_man.m_hProcess);
    for (const auto& region : exec_regions)
    {
        // Enable for debug info
        /*std::wcout << std::hex
            << L"0x" << region.base
            << L" " << ProtectToString(region.protect).c_str()
            << L" 0x" << region.size
            << std::endl;*/

        std::vector<uint8_t> bytes = m_man.ReadBytes(region.base, region.size);
        const int MIN_CAVE_SIZE = 0x1000; // Full page code cave why not?

        for (size_t i = 0; i < bytes.size() - MIN_CAVE_SIZE; i++)
        {
            if (bytes[i] == 0x00)
            {
                bool found = true;
                for (size_t j = 1; j < MIN_CAVE_SIZE; j++)
                {
                    if (bytes[i + j] != 0x00)
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    printf("Found cave at %p [permission: %s]\n", (void*)(region.base + i), ProtectToString(region.protect).c_str());
                    i += MIN_CAVE_SIZE - 1;
                }
            }
        }
    }
}