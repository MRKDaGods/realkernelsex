#pragma once

#include "common.h"

typedef USHORT WORD;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	PVOID Section;
	PVOID MappedBaseAddress;
	PVOID ImageBaseAddress;
	ULONG ImageSize;
	ULONG Flags;
	WORD LoadOrderIndex;
	WORD InitOrderIndex;
	WORD LoadCount;
	WORD NameOffset;
	UCHAR Name[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG ModulesCount;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define IMAGE_DOS_SIGNATURE 0x5A4D // MZ
typedef struct _IMAGE_DOS_HEADER_K {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER_K, * PIMAGE_DOS_HEADER_K;

typedef struct _IMAGE_FILE_HEADER_K {
	WORD Machine;
	WORD NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD SizeOfOptionalHeader;
	WORD Characteristics;
} IMAGE_FILE_HEADER_K, * PIMAGE_FILE_HEADER_K;

typedef struct _IMAGE_DATA_DIRECTORY_K {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY_K, * PIMAGE_DATA_DIRECTORY_K;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef struct _IMAGE_OPTIONAL_HEADER_K {
	WORD Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	ULONGLONG ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY_K DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER_K, * PIMAGE_OPTIONAL_HEADER_K;

#define IMAGE_NT_SIGNATURE 0x00004550
typedef struct _IMAGE_NT_HEADERS_K {
	DWORD Signature;
	IMAGE_FILE_HEADER_K FileHeader;
	IMAGE_OPTIONAL_HEADER_K OptionalHeader;
} IMAGE_NT_HEADERS_K, * PIMAGE_NT_HEADERS_K;

#pragma pack(push, 4)
typedef struct _IMAGE_EXPORT_DIRECTORY_K {
	ULONG Characteristics;
	ULONG TimeDateStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	ULONG Name;
	ULONG Base;
	ULONG NumberOfFunctions;
	ULONG NumberOfNames;
	ULONG AddressOfFunctions;
	ULONG AddressOfNames;
	ULONG AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY_K, * PIMAGE_EXPORT_DIRECTORY_K;
#pragma pack(pop)