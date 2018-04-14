/**
 * @file include/retdec/capstone2llvmir/tricore/tricore.h
 * @brief TriCore implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H
#define RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H

#include <array>
#include <tuple>
#include <utility>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
// #include "retdec/capstone2llvmir/x86/x86_defs.h"

namespace retdec {
namespace capstone2llvmir {
	class Capstone2LlvmIrTranslatorTricore : public Capstone2LlvmIrTranslator
{
	// Constructor, destructor.
	//
	public:
		Capstone2LlvmIrTranslatorTricore(
				llvm::Module* m,
				cs_mode basic = CS_MODE_32,
				cs_mode extra = CS_MODE_LITTLE_ENDIAN);
		virtual ~Capstone2LlvmIrTranslatorTricore();

	// Public pure virtual methods that must be implemented in concrete classes.
	//
	public:
		virtual bool isAllowedBasicMode(cs_mode m) override;
		virtual bool isAllowedExtraMode(cs_mode m) override;
		virtual void modifyBasicMode(cs_mode m) override;
		virtual void modifyExtraMode(cs_mode m) override;
		virtual uint32_t getArchByteSize() override;
		virtual uint32_t getArchBitSize() override;
		
	// Protected pure virtual methods that must be implemented in concrete
	// classes.
	//
	protected:
		virtual void initializeArchSpecific() override;
		virtual void initializeRegNameMap() override;
		virtual void initializeRegTypeMap() override;
		virtual void generateEnvironmentArchSpecific() override;
		virtual void generateDataLayout() override;
		virtual void generateRegisters() override;

		virtual void translateInstruction(
				cs_insn* i,
				llvm::IRBuilder<>& irb) override;
	
};
	

} // namespace capstone2llvmir
} // namespace retdec

#endif