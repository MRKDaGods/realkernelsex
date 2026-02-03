#include "mem.h"
#include "ntfuncs.h"

namespace mrk {

	PVOID mrk::GetKernelModuleBase(PCSTR moduleName) {
		ULONG infoSize = 0;

		NTSTATUS status = ZwQuerySystemInformation(
			SystemModuleInformation,
			NULL,
			0,
			&infoSize
		);

		// Ignore STATUS_INFO_LENGTH_MISMATCH
		if (infoSize == 0) {
			DRV_LOG("Failed to query system information size infoSize=%lu", infoSize);
			return NULL;
		}

		DRV_LOG("infoSize=%lu", infoSize);

		PRTL_PROCESS_MODULES moduleInfo = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, infoSize, 'eliF');
		if (!moduleInfo) {
			DRV_LOG("Failed to allocate module information");
			return NULL;
		}

		status = ZwQuerySystemInformation(
			SystemModuleInformation,
			moduleInfo,
			infoSize,
			&infoSize
		);

		if (!NT_SUCCESS(status)) {
			DRV_LOG("Failed to query system information status=0x%X", status);
			ExFreePoolWithTag(moduleInfo, 'eliF');
			return NULL;
		}

		for (unsigned i = 0; i < moduleInfo->ModulesCount; i++) {
			PRTL_PROCESS_MODULE_INFORMATION mod = &moduleInfo->Modules[i];
			PCSTR modName = (PCSTR)(mod->Name + mod->NameOffset);

			if (!strcmp(modName, moduleName)) {
				ExFreePoolWithTag(moduleInfo, 'eliF');
				return mod->ImageBaseAddress;
			}
		}

		ExFreePoolWithTag(moduleInfo, 'eliF');
		return NULL;
	}

	PVOID mrk::GetKernelBase() {
		return GetKernelModuleBase("ntoskrnl.exe");
	}

	PVOID GetKernelProcAddress(PVOID moduleBase, PCSTR functionName) {
		if (!moduleBase || !functionName) {
			return NULL;
		}

		PIMAGE_DOS_HEADER_K dosHeader = (PIMAGE_DOS_HEADER_K)moduleBase;
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return NULL;
		}

		PIMAGE_NT_HEADERS_K ntHeaders = (PIMAGE_NT_HEADERS_K)((ULONG_PTR)moduleBase + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			return NULL;
		}

		DWORD rva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (rva == 0) {
			DRV_LOG("ERROR: No export directory found");
			return NULL;
		}

		PIMAGE_EXPORT_DIRECTORY_K dir = (PIMAGE_EXPORT_DIRECTORY_K)((ULONG_PTR)moduleBase + rva);

		PULONG names = (PULONG)((ULONG_PTR)moduleBase + dir->AddressOfNames);
		PUSHORT ordinals = (PUSHORT)((ULONG_PTR)moduleBase + dir->AddressOfNameOrdinals);
		PULONG functions = (PULONG)((ULONG_PTR)moduleBase + dir->AddressOfFunctions);

		for (unsigned i = 0; i < dir->NumberOfNames; i++) {
			PCSTR name = (PCSTR)((ULONG_PTR)moduleBase + names[i]);
			if (!strcmp(name, functionName)) {
				USHORT ordinal = ordinals[i];
				return (PVOID)((ULONG_PTR)moduleBase + functions[ordinal]);
			}
		}

		return NULL;
	}

} // namespace mrk
