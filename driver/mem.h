#pragma once

#include "common.h"

namespace mrk {

	/// Retrieves base address of a kernel module by name
	PVOID GetKernelModuleBase(PCSTR moduleName);

	/// Retrieves base address of ntoskrnl.exe
	PVOID GetKernelBase();

	/// Retrieves address of a function in a kernel module by name
	PVOID GetKernelProcAddress(PVOID moduleBase, PCSTR functionName);

	/// Protected write using Mdl mapping
	BOOLEAN WriteProtectedMemory(PVOID dst, PVOID src, SIZE_T length);

} // namespace mrk
