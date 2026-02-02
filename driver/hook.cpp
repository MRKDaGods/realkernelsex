#include "hook.h"

typedef struct _RUNTIME_CTX {
	BOOLEAN Active;			// Is the hook active
} RUNTIME_CTX;

static RUNTIME_CTX g_RuntimeCtx = { 0 };

namespace mrk {

	/// Internal implementation of InstallHook
	static BOOLEAN InstallHookInternal(PVOID kernelFunction) {
		DRV_LOG("Installing hook internal: kernelFunction=0x%p", kernelFunction);

		if (!kernelFunction) {
			DRV_LOG("ERROR: kernelFunction is null");
			return FALSE;
		}

		// Check if hook is already installed
		if (InterlockedCompareExchange(&g_RuntimeCtx.Active, TRUE, FALSE) != FALSE) {
			DRV_LOG("ERROR: Hook already installed");
			return FALSE;
		}

		return FALSE;
	}

	BOOLEAN InstallHook(PVOID kernelFunction) {
		DRV_LOG("Installing hook: kernelFunction=0x%p", kernelFunction);
		BOOLEAN result = InstallHookInternal(kernelFunction);
		DRV_LOG("Hook installation result: %s", result ? "SUCCESS" : "FAILURE");
		return result;
	}

} // namespace mrk