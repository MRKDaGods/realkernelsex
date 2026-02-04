#include "mem.h"
#include "ntfuncs.h"

namespace mrk {

	PVOID GetKernelModuleBase(PCSTR moduleName) {
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

		PVOID exportAddr = NULL;
		if (NT_SUCCESS(status)) {
			for (unsigned i = 0; i < moduleInfo->ModulesCount; i++) {
				PRTL_PROCESS_MODULE_INFORMATION mod = &moduleInfo->Modules[i];
				PCSTR modName = (PCSTR)(mod->Name + mod->NameOffset);

				if (!strcmp(modName, moduleName)) {
					exportAddr = mod->ImageBaseAddress;
					break;
				}
			}
		}
		else {
			DRV_LOG("Failed to query system information status=0x%X", status);
		}

		ExFreePoolWithTag(moduleInfo, 'eliF');
		return exportAddr;
	}

	PVOID GetKernelBase() {
		// ntoskrnl.exe is the first module anyway
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
			DRV_LOG("ERROR: No export directory found for module 0x%p", moduleBase);
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

	BOOLEAN WriteProtectedMemory(PVOID dst, PVOID src, SIZE_T length) {
		if (!dst || !src || length == 0) {
			return FALSE;
		}

		PMDL mdl = IoAllocateMdl(dst, length, FALSE, FALSE, NULL);
		if (!mdl) {
			DRV_LOG("ERROR: Failed to allocate mdl");
			return FALSE;
		}

		// Lock and map the pages
		MmBuildMdlForNonPagedPool(mdl);
		PVOID mapping = MmMapLockedPagesSpecifyCache(
			mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority
		);

		if (!mapping) {
			DRV_LOG("ERROR: Cannot map mdl");
			IoFreeMdl(mdl);
			return FALSE;
		}

		NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		if (NT_SUCCESS(status)) {
			RtlCopyMemory(mapping, src, length);
		}
		else {
			DRV_LOG("ERROR: Cannot change memory protection status=0x%X", status);
		}

		MmUnmapLockedPages(mapping, mdl);
		IoFreeMdl(mdl);

		return NT_SUCCESS(status);
	}

} // namespace mrk
