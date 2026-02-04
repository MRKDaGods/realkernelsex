#pragma once

#include "common.h"

namespace mrk {

	/// Installs the hook targetting kernelFunction
	BOOLEAN InstallHook(PVOID kernelFunction);

	/// Uninstalls the current hook obv
	BOOLEAN UninstallHook();

	/// Trampoline!
	PVOID GetTrampoline();

} // namespace mrk
