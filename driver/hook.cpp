#include "hook.h"
#include "mem.h"
#include "utils.h"
#include "nmd_assembly.h"

static const UCHAR g_HookShellcode[] = {
	0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,					// jmp QWORD PTR [rip]
	0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAF, 0x1F		// 0xAABBCCDDEEFFAF1F
};

#define HOOK_SHELLCODE_SIZE sizeof(g_HookShellcode)

typedef struct _RUNTIME_CTX {
	LONG Active;		// Is the hook active
	UCHAR OriginalBytes[HOOK_SHELLCODE_SIZE + NMD_X86_MAXIMUM_INSTRUCTION_LENGTH];
	SIZE_T OriginalBytesLength;
} RUNTIME_CTX;

static RUNTIME_CTX g_RuntimeCtx = {};

namespace mrk {

	/// Jump at address to target
	static void CreateJump(PVOID address, PVOID target, BOOLEAN protectedWrite = FALSE) {
		// Clone shellcode
		UCHAR shellcode[HOOK_SHELLCODE_SIZE];
		RtlCopyMemory(shellcode, g_HookShellcode, HOOK_SHELLCODE_SIZE);

		// Copy target
		RtlCopyMemory(shellcode + 6, &target, sizeof(PVOID));

		// Write to address
		if (protectedWrite) {
			WriteProtectedMemory(address, shellcode, sizeof(shellcode));
		}
		else {
			RtlCopyMemory(address, shellcode, sizeof(shellcode));
		}
	}

	/// Pads with NOPs
	static void Pad(PVOID address, SIZE_T length, BOOLEAN protectedWrite = FALSE) {
		UCHAR padShellcode[NMD_X86_MAXIMUM_INSTRUCTION_LENGTH];
		memset(padShellcode, 0x90, sizeof(padShellcode));

		if (protectedWrite) {
			WriteProtectedMemory(address, padShellcode, length);
		}
		else {
			RtlCopyMemory(address, padShellcode, length);
		}

		/*for (SIZE_T i = 0; i < length; i++) {
			*(PUCHAR)((ULONG_PTR)address + i) = 0x90;
		}*/
	}

	/// Minimum number of bytes we need to copy for the hook
	static SIZE_T CalculateHookSize(PVOID function) {
		if (!function) return 0;

		SIZE_T offset = 0;
		while (offset < HOOK_SHELLCODE_SIZE) {
			SIZE_T instructionSize = nmd_x86_ldisasm(
				(PVOID)((ULONG_PTR)function + offset),
				NMD_X86_MAXIMUM_INSTRUCTION_LENGTH,
				NMD_X86_MODE_64
			);

			// No more instructions and we havent reached our hook threshold
			if (instructionSize == 0) {
				DRV_LOG("ERROR: Function too small to hook, funcsz=%lld", offset);
				return 0;
			}

			offset += instructionSize;
		}

		return offset;
	}

	static PVOID GetHookTarget() {
		PVOID kernelBase = GetKernelBase();
		DRV_LOG("Kernel base address: 0x%p", kernelBase);
		if (!kernelBase) return NULL;

		/*
		[kernelsex] +0x0: MOV [RSP+10H],RBX
		[kernelsex] +0x5: PUSH RDI
		[kernelsex] +0x6: SUB RSP,30H
		[kernelsex] +0xA: MOV RDI,RDX
		[kernelsex] +0xD: LEA EAX,[RCX-8]
		*/

		PVOID ntQuerySystemInfo = GetKernelProcAddress(kernelBase, "NtQuerySystemInformation");
		DRV_LOG("NtQuerySystemInformation address: 0x%p", ntQuerySystemInfo);

		return ntQuerySystemInfo;
	}

	static BOOLEAN DisableHook(PVOID hookTarget) {
		if (InterlockedCompareExchange(&g_RuntimeCtx.Active, 0, 1) != 1) {
			DRV_LOG("ERROR: Hook not active");
			return FALSE;
		}

		// Restore original bytes
		DRV_LOG("Restoring original bytes (length=%lld)", g_RuntimeCtx.OriginalBytesLength);
		WriteProtectedMemory(hookTarget, g_RuntimeCtx.OriginalBytes, g_RuntimeCtx.OriginalBytesLength);

		return TRUE;
	}

	/// Internal implementation of InstallHook
	static BOOLEAN InstallHookInternal(PVOID kernelFunction) {
		DRV_LOG("Installing hook internal: kernelFunction=0x%p", kernelFunction);

		if (!kernelFunction) {
			DRV_LOG("ERROR: kernelFunction is null");
			return FALSE;
		}

		// Check if hook is already installed
		if (InterlockedCompareExchange(&g_RuntimeCtx.Active, 1, 0) != 0) {
			DRV_LOG("ERROR: Hook already installed");
			return FALSE;
		}

		PVOID hookTarget = GetHookTarget();
		if (!hookTarget) {
			DRV_LOG("ERROR: Cannot get hook target");
			InterlockedExchange(&g_RuntimeCtx.Active, 0);
			return FALSE;
		}

		SIZE_T minHookSize = CalculateHookSize(hookTarget);
		DRV_LOG("Min hook size: %lld bytes", minHookSize);

		PrintDisassembly(hookTarget, minHookSize);

		DRV_LOG("Copying original bytes...");
		g_RuntimeCtx.OriginalBytesLength = minHookSize;
		RtlCopyMemory(g_RuntimeCtx.OriginalBytes, hookTarget, minHookSize);

		// Jump to our function
		// jmp [rip]
		DRV_LOG("Creating jump...");
		CreateJump(hookTarget, kernelFunction, TRUE);

		// Pad diff
		SIZE_T padLength = minHookSize - HOOK_SHELLCODE_SIZE;
		if (padLength > 0) {
			DRV_LOG("Padding with %lld bytes", padLength);
			Pad(
				(PVOID)((ULONG_PTR)hookTarget + HOOK_SHELLCODE_SIZE),
				padLength,
				TRUE
			);
		}

		// Print new disassembly
		//PrintDisassembly(hookTarget, HOOK_SHELLCODE_SIZE);

		// Restore for my sanity
		DRV_LOG("Disabling hook...");
		if (!DisableHook(hookTarget)) {
			DRV_LOG("ERROR: Failed to disable hook");
			return false;
		}
		DRV_LOG("Hook disabled successfully");

		return TRUE;
	}

	BOOLEAN InstallHook(PVOID kernelFunction) {
		DRV_LOG("Installing hook: kernelFunction=0x%p", kernelFunction);
		BOOLEAN result = InstallHookInternal(kernelFunction);
		DRV_LOG("Hook installation result: %s", result ? "SUCCESS" : "FAILURE");
		return result;
	}

} // namespace mrk
