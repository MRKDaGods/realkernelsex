#include "common.h"
#include "hook.h"
#include "callbacks.h"
#include "mem.h"
#include "ntfuncs.h"

void TestHooks() {
	// Test - NtQuerySystemInformation
	PVOID ntoskrnl = mrk::GetKernelBase();
	PVOID ntQuerySystemInformation = mrk::GetKernelProcAddress(ntoskrnl, "NtQuerySystemInformation");
	DRV_LOG("ntoskrnl=0x%p ntQuerySystemInformation=0x%p", ntoskrnl, ntQuerySystemInformation);

	DRV_LOG("Normal:");
	ULONG infoSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(
		SystemModuleInformation,
		NULL,
		0,
		&infoSize
	);
	DRV_LOG("Result: status=0x%08X infoSize=%lu", status, infoSize);

	DRV_LOG("Custom:");
	status = ((decltype(&mrk::HookWrapper)(ntQuerySystemInformation)))(
		(SYSTEM_INFORMATION_CLASS)CUSTOM_SYS_INFO,
		NULL,
		0,
		(PULONG)0xAF1F1
	);
	DRV_LOG("Result: status=0x%08X", status);
}

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

	DRV_LOG("Testing hooks...");
	TestHooks();

	// Uninstall hook
	DRV_LOG("Uninstalling hook...");
	if (!mrk::UninstallHook()) {
		DRV_LOG("Failed to uninstall hook");
		return STATUS_UNSUCCESSFUL;
	}
	DRV_LOG("Hook uninstalled successfully");

	DRV_LOG("DriverEntry complete");
	return STATUS_SUCCESS;
}
