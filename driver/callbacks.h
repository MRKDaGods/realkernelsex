#pragma once

#include "common.h"

namespace mrk {

	__declspec(noinline) NTSTATUS NTAPI HookWrapper(
		ULONG_PTR SystemInformationClassOrPtr,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

} // namespace mrk
