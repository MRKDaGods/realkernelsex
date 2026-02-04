#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <Ntstrsafe.h>

// Logging macros
#define DRV_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[kernelsex] " fmt "\n", ##__VA_ARGS__)
#define DRV_LOG_ENTER(func) DRV_LOG(">>> ENTER: %s", func)
#define DRV_LOG_EXIT(func, status) DRV_LOG("<<< EXIT: %s (Status: 0x%08X)", func, status)
