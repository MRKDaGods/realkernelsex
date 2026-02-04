#include "callbacks.h"
#include "hook.h"

namespace mrk {

	__declspec(noinline) NTSTATUS NTAPI HookWrapper(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	) {
		if (SystemInformationClass == CUSTOM_SYS_INFO) {
			// Our shit
			DRV_LOG("shofo shofolyyyy 3nehaaaa, RL=%llX", (ULONG_PTR)ReturnLength);
			return STATUS_SUCCESS;
		}

		DRV_LOG("HookWrapper passthrough SIC=%lu", SystemInformationClass);

		// Trampoline!
		PVOID trampoline = GetTrampoline();
		return ((decltype(&HookWrapper))(trampoline))(
			SystemInformationClass,
			SystemInformation,
			SystemInformationLength,
			ReturnLength
		);
	}

} // namespace mrk
