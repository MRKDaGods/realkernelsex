#pragma once

#include "common.h"
#include "ntstructs.h"

#define CUSTOM_SYS_INFO 0x69DEADFUL

namespace mrk {

	__declspec(noinline) NTSTATUS NTAPI HookWrapper(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	);

} // namespace mrk
