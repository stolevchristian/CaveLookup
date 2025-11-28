#pragma once
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <Psapi.h>
#include <sstream>

enum InitMode
{
	WINDOW_TITLE,
	WINDOW_CLASS,
	PROCESS_NAME
};

using tNtReadVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
using tNtWriteVirtualMemory = NTSTATUS(WINAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);

class Memory
{
private:

	uintptr_t GetModuleBase(const std::string moduleName);
	MODULEENTRY32 GetModule(const std::string moduleName);
	PROCESSENTRY32 GetProcess(const std::string processName);

	tNtReadVirtualMemory rvm = reinterpret_cast<tNtReadVirtualMemory>(
		GetProcAddress(LoadLibraryA("ntdll.dll"), "NtReadVirtualMemory")
		);
	tNtWriteVirtualMemory wvm = reinterpret_cast<tNtWriteVirtualMemory>(
		GetProcAddress(LoadLibraryA("ntdll.dll"), "NtWriteVirtualMemory")
		);

public:
	DWORD m_dwPID;
	HANDLE m_hProcess;
	uintptr_t m_gClientBaseAddr;

	bool AttachProcess(const std::string& processName);
	void DetachProcess();

	char* GetModuleName();
	MODULEINFO GetModuleInfo(const std::string moduleName);
	uintptr_t FindPattern(const std::vector<uint8_t>& read_data, const std::vector<uint8_t>& bytes, uintptr_t regionBase, int offset, int extra);


	template <typename T>
	constexpr const T Read(const uintptr_t& address) const noexcept
	{
		T value{};
		rvm(m_hProcess, reinterpret_cast<LPVOID>(address), &value, sizeof(T), NULL);
		return value;
	}
	template <typename T>
	constexpr void Write(const uintptr_t& address, const T& value) const noexcept
	{
		wvm(m_hProcess, reinterpret_cast<void*>(address), (PVOID)&value, sizeof(T), NULL);
	}
	uintptr_t ReadChain(uintptr_t address, const std::vector<uintptr_t>& offsets)
	{
		uintptr_t result = Read<uintptr_t>(address + offsets.at(0));
		for (int i = 1; i < offsets.size(); i++)
			result = Read<uintptr_t>(result + offsets.at(i));

		return result;
	}
	bool ReadString(const uintptr_t address, LPVOID buffer, SIZE_T size) const noexcept
	{
		return !!::ReadProcessMemory(m_hProcess, (void*)(address), buffer, size, nullptr);
	}
	std::string ReadStringA(const uintptr_t address) const noexcept
	{
		char vOut[MAX_PATH]{};
		ReadProcessMemory(m_hProcess, (void*)(address), vOut, sizeof(vOut), nullptr);

		return std::string(vOut);
	}
	std::vector<uint8_t> ReadBytes(uintptr_t address, size_t size)
	{
		std::vector<uint8_t> buffer(size);
		ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(address), buffer.data(), size, nullptr);
		return buffer;
	}
};