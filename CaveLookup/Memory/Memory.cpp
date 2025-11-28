#include "Memory.h"


DWORD GetProcessIdByName(const std::string& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, std::wstring(processName.begin(), processName.end()).c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pid;
}

bool Memory::AttachProcess(const std::string& processName)
{
    std::uint32_t pID = GetProcessIdByName(processName);

    if (!pID) {
        MessageBoxA(nullptr, "Please open the target process.", "Initialize Failed", MB_TOPMOST | MB_ICONERROR | MB_OK);
        return false;
    }
    this->m_dwPID = pID;

    this->m_hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->m_dwPID);

    if (!this->m_hProcess) {
        MessageBoxA(nullptr, "Failed to get process handle", "Init Error", MB_TOPMOST | MB_ICONERROR | MB_OK);
        return false;
    }

    m_gClientBaseAddr = this->GetModuleBase(this->GetModuleName());
    if (!m_gClientBaseAddr)
        return false;

    return true;
}

void Memory::DetachProcess()
{
    CloseHandle(m_hProcess);
}

char* Memory::GetModuleName()
{
    char pModule[128]{};
    GetModuleBaseNameA(this->m_hProcess, nullptr, pModule, sizeof(pModule));

    return pModule;
}

uintptr_t Memory::FindPattern(const std::vector<uint8_t>& read_data, const std::vector<uint8_t>& bytes, uintptr_t regionBase, int offset, int extra)
{
    if (bytes.size() > read_data.size()) return 0;

    for (size_t i = 0; i < read_data.size() - bytes.size(); ++i)
    {
        bool patternMatch = true;
        for (size_t j = 0; j < bytes.size(); ++j)
        {
            if (bytes[j] != 0 && read_data[i + j] != bytes[j])
            {
                patternMatch = false;
                break;
            }
        }

        if (patternMatch) {
            uintptr_t patternAddress = regionBase + i;  // Use the actual region base
            int32_t of;
            ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(patternAddress + offset), &of, sizeof(of), nullptr);
            return patternAddress + of + extra;
        }
    }

    return 0;  // Not found
}

MODULEINFO Memory::GetModuleInfo(const std::string moduleName)
{
    DWORD cb;
    HMODULE hMods[256]{};
    MODULEINFO modInfo{};

    if (EnumProcessModules(m_hProcess, hMods, sizeof(hMods), &cb))
    {
        for (unsigned int i = 0; i < (cb / sizeof(HMODULE)); i++)
        {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(m_hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
            {
                if (moduleName == szModName) {
                    GetModuleInformation(m_hProcess, hMods[i], &modInfo, sizeof(modInfo));
                    break;
                }
            }
        }
    }

    return modInfo;
}

uintptr_t Memory::GetModuleBase(const std::string moduleName)
{
    MODULEENTRY32 entry{};
    entry.dwSize = sizeof(MODULEENTRY32);
    const auto snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwPID);

    while (Module32Next(snapShot, &entry))
    {
        if (!moduleName.compare(entry.szModule))
        {
            CloseHandle(snapShot);
            return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
        }
    }

    if (snapShot)
        CloseHandle(snapShot);

    return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
}

MODULEENTRY32 Memory::GetModule(const std::string moduleName)
{
    MODULEENTRY32 entry{};
    entry.dwSize = sizeof(MODULEENTRY32);
    const auto snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwPID);

    while (Module32Next(snapShot, &entry))
    {
        if (!moduleName.compare(entry.szModule))
        {
            CloseHandle(snapShot);
            return entry;
        }
    }

    if (snapShot)
        CloseHandle(snapShot);

    return entry;
}


PROCESSENTRY32 Memory::GetProcess(const std::string processName)
{
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);
    const auto snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    while (Process32Next(snapShot, &entry))
    {
        if (!processName.compare(entry.szExeFile))
        {
            CloseHandle(snapShot);
            return entry;
        }
    }

    CloseHandle(snapShot);

    return PROCESSENTRY32();
}