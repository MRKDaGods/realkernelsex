#include "utils.h"

#define NMD_ASSEMBLY_IMPLEMENTATION
#include "nmd_assembly.h"

namespace mrk {

	void PrintDisassembly(PVOID start, SIZE_T length) { // move to utils
		DRV_LOG("Disassembly at 0x%p (Length=%lld):", start, length);

		nmd_x86_instruction instruction;
		CHAR formattedInstruction[128];

		SIZE_T offset = 0;
		while (offset < length) {
			ULONG_PTR instructionAddr = (ULONG_PTR)start + offset;
			if (!nmd_x86_decode(
				(PVOID)instructionAddr,
				NMD_X86_MAXIMUM_INSTRUCTION_LENGTH,
				&instruction,
				NMD_X86_MODE_64,
				NMD_X86_DECODER_FLAGS_MINIMAL
			)) {
				DRV_LOG("Invalid instruction at offset %zX", offset);
				return;
			}

			nmd_x86_format(
				&instruction,
				formattedInstruction,
				instructionAddr,
				NMD_X86_FORMAT_FLAGS_DEFAULT | NMD_X86_FORMAT_FLAGS_UPPERCASE
			);
			DRV_LOG("+0x%zX: %s", offset, formattedInstruction);

			offset += instruction.length;
		}
	}

} // namespace mrk
