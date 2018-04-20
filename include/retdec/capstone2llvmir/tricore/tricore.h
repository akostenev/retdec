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
#include "retdec/capstone2llvmir/tricore/tricore_defs.h"

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

		/**
		* Override translate, for tricore2capstone
		*/
		virtual Capstone2LlvmIrTranslator::TranslationResult translate(
			const std::vector<uint8_t>& bytes,
			retdec::utils::Address a,
			llvm::IRBuilder<>& irb,
			bool stopOnBranch = false);

	protected:
		virtual void translateInstruction(
			cs_insn* i,
			llvm::IRBuilder<>& irb) override;

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

	protected:
		llvm::IntegerType* getDefaultType();
		llvm::Value* getCurrentPc(cs_insn* i);
		llvm::Value* getNextInsnAddress(cs_insn* i);
		llvm::Value* getNextNextInsnAddress(cs_insn* i);

		llvm::Value* loadRegister(
			uint32_t r,
			llvm::IRBuilder<>& irb);
		llvm::Value* loadOp(
			cs_tricore_op& op,
			llvm::IRBuilder<>& irb,
			llvm::Type* ty = nullptr);
		llvm::Value* loadOpUnary(
			cs_tricore* mi,
			llvm::IRBuilder<>& irb);
		std::pair<llvm::Value*, llvm::Value*> loadOpBinary(
			cs_tricore* mi,
			llvm::IRBuilder<>& irb,
			eOpConv ct = eOpConv::NOTHING);

	protected:
		static std::map<
			std::size_t,
			void (Capstone2LlvmIrTranslatorTricore::*)(cs_insn* i, llvm::IRBuilder<>&)> _i2fm;


		// These are used to save lines needed to declare locale operands in
		// each translation function.
		// In C++17, we could use Structured Bindings:
		// auto [ op0, op1 ] = loadOpBinary();
		llvm::Value* op0 = nullptr;
		llvm::Value* op1 = nullptr;
		llvm::Value* op2 = nullptr;
		llvm::Value* op3 = nullptr;

		// TODO: This is a hack, sometimes we need cs_insn deep in helper
		// methods like @c loadRegister() where it is hard to propagate it.
		cs_insn* _insn = nullptr;

	protected:
		void translateJ(cs_insn* i, llvm::IRBuilder<>& irb);
};


} // namespace capstone2llvmir
} // namespace retdec

#endif
