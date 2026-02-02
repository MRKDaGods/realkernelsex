#include "callbacks.h"

namespace mrk {

	__declspec(noinline) NTSTATUS NTAPI HookWrapper(
		ULONG_PTR SystemInformationClassOrPtr,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength
	) {
		return STATUS_NOT_IMPLEMENTED;
	}

} // namespace mrk