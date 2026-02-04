#include "common.h"
#include "hook.h"
#include "callbacks.h"

extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT  driver_object,
	PUNICODE_STRING registry_path
) {
	DRV_LOG("DriverEntry");
	DRV_LOG("DriverObject: 0x%p", driver_object);
	DRV_LOG("RegistryPath: %wZ", registry_path);

	// Install hook
	DRV_LOG("Installing hook...");
	if (!mrk::InstallHook(&mrk::HookWrapper)) {
		DRV_LOG("Failed to install hook");
		return STATUS_UNSUCCESSFUL;
	}
	DRV_LOG("Hook installed successfully");

	DRV_LOG("DriverEntry complete");
	return STATUS_SUCCESS;
}
