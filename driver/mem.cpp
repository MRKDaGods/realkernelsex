#include "mem.h"
#include "ntfuncs.h"

namespace mrk {
	
	PVOID mrk::GetKernelBase() {
		NTSTATUS status;
		ULONG infoSize = 0;

		status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &infoSize);
		return nullptr; // yarab ne5las
	}

} // namespace mrk
