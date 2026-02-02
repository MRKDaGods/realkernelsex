#pragma once

#include "common.h"

namespace mrk {

	/// Installs the hook targetting kernelFunction
	BOOLEAN InstallHook(PVOID kernelFunction);

} // namespace mrk