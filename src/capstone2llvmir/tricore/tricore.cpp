#include "retdec/capstone2llvmir/tricore/tricore.h"

#include <iostream>

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorTricore::Capstone2LlvmIrTranslatorTricore(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator(CS_ARCH_ALL, basic, extra, m)
{
	initializeRegNameMap();
	initializeRegTypeMap();
	initializeArchSpecific();

	generateEnvironment();
}

Capstone2LlvmIrTranslatorTricore::~Capstone2LlvmIrTranslatorTricore()
{
	// Nothing specific to TriCore.
}

Capstone2LlvmIrTranslator::TranslationResult Capstone2LlvmIrTranslatorTricore::translate(
		const std::vector<uint8_t>& bytes,
		retdec::utils::Address a,
		llvm::IRBuilder<>& irb,
		bool stopOnBranch) {
	TranslationResult res;

	/**
	 * Build tricore2capstone (light)
	 */
	for (auto it = std::begin(bytes), end = std::end(bytes); it != end; ) {
		cs_insn i;
		i.id = (*it); // op1
		i.address = a;

		if ((*it) & 1) { // 32-Bit instruction
			i.size = 4;
			i.bytes[0] = *it++;
			i.bytes[1] = *it++;
			i.bytes[2] = *it++;
			i.bytes[3] = *it++;
		} else { // 16-bit instruction
			i.size = 2;
			i.bytes[0] = *it++;
			i.bytes[1] = *it++;
		}

		// and translate it
		translateInstruction(&i, irb);
	}

	return res;
}

void Capstone2LlvmIrTranslatorTricore::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
// 	for (unsigned int j = 0; j < i->size; j++) {
// 		std::cout << "translateInstruction byte " << j << " " << std::hex << static_cast<int>(i->bytes[j]) << std::endl;
// 	}

// 	_insn = i;

	auto fIt = _i2fm.find(i->id);
	if (fIt != _i2fm.end() && fIt->second != nullptr)
	{
		auto f = fIt->second;
		(this->*f)(i, irb);
	}
	else
	{
// 		std::stringstream msg;
// 		msg << "Translation of unhandled instruction: " << i->id << std::endl;
// 		throw Capstone2LlvmIrError(msg.str());

// 		std::cout << "Translation of unhandled instruction: " << i->id << std::endl;
	}
}

llvm::IntegerType* Capstone2LlvmIrTranslatorTricore::getDefaultType()
{
	return llvm::Type::getInt32Ty(_module->getContext());
}


llvm::Value* Capstone2LlvmIrTranslatorTricore::loadRegister(
		uint32_t r,
		llvm::IRBuilder<>& irb)
{
	if (r == TRICORE_REG_INVALID)
	{
		return nullptr;
	}

	if (r == TRICORE_REG_PC)
	{
		return getCurrentPc(_insn);
	}

	//TODO
// 	if (r == MIPS_REG_ZERO)
// 	{
// 		return llvm::ConstantInt::getSigned(
// 			getDefaultType(),
// 			0);
// 	}
//
// 	if (cs_insn_group(_handle, _insn, MIPS_GRP_NOTFP64BIT)
// 			&& MIPS_REG_F0 <= r
// 			&& r <= MIPS_REG_F31)
// 	{
// 		r = singlePrecisionToDoublePrecisionFpRegister(r);
// 	}

	auto* llvmReg = getRegister(r);
	if (llvmReg == nullptr)
	{
		throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
	}
	return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOp(
		cs_tricore_op& op,
		llvm::IRBuilder<>& irb,
		llvm::Type* ty)
{
	switch (op.type)
	{
		case TRICORE_OP_REG:
		{
			return loadRegister(op.reg, irb);
		}
		case TRICORE_OP_IMM:
		{
			// TODO: Maybe this will cause problems.
			// In 32-bit MIPS, imms are 16 bits (always?).
			// What if number will be negative on 16 bits, but because we
			// take it here and create 32 bit, it loses it negativity?
			// The same in 64-bit MIPS.
			// However, maybe it will be ok, because cs_mips_op.imm is signed
			// int64_t, so if Capstone interprets it ok for us, then we probably
			// do not need to bother with it.
			return llvm::ConstantInt::getSigned(getDefaultType(), op.imm);
		}
		case TRICORE_OP_MEM:
		{
			auto* baseR = loadRegister(op.mem.base, irb);
			auto* t = getDefaultType();
			llvm::Value* disp = llvm::ConstantInt::getSigned(t, op.mem.disp);

			llvm::Value* addr = nullptr;
			if (baseR == nullptr)
			{
				addr = disp;
			}
			else
			{
				if (op.mem.disp == 0)
				{
					addr = baseR;
				}
				else
				{
					disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
					addr = irb.CreateAdd(baseR, disp);
				}
			}

			auto* lty = ty ? ty : t;
			auto* pt = llvm::PointerType::get(lty, 0);
			addr = irb.CreateIntToPtr(addr, pt);
			return irb.CreateLoad(addr);
		}
		case TRICORE_OP_INVALID:
		default:
		{
			assert(false && "should not be possible");
			return nullptr;
		}
	}
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOpUnary(
		cs_tricore* mi,
		llvm::IRBuilder<>& irb)
{
	if (mi->op_count != 1)
	{
		throw Capstone2LlvmIrError("This is not a unary instruction.");
	}

	return loadOp(mi->operands[0], irb);
}

std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOpBinary(
		cs_tricore* mi,
		llvm::IRBuilder<>& irb,
		eOpConv ct)
{
	if (mi->op_count != 2)
	{
		throw Capstone2LlvmIrError("This is not a binary instruction.");
	}

	auto* op0 = loadOp(mi->operands[0], irb);
	auto* op1 = loadOp(mi->operands[1], irb);
	if (op0 == nullptr || op1 == nullptr)
	{
		throw Capstone2LlvmIrError("Operands loading failed.");
	}

	if (op0->getType() != op1->getType())
	{
		switch (ct)
		{
			case eOpConv::SECOND_SEXT:
			{
				op1 = irb.CreateSExtOrTrunc(op1, op0->getType());
				break;
			}
			case eOpConv::SECOND_ZEXT:
			{
				op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
				break;
			}
			case eOpConv::NOTHING:
			{
				break;
			}
			default:
			case eOpConv::THROW:
			{
				throw Capstone2LlvmIrError("Binary operands' types not equal.");
			}
		}
	}

	return std::make_pair(op0, op1);
}


llvm::Value* Capstone2LlvmIrTranslatorTricore::getCurrentPc(cs_insn* i)
{
	return getNextInsnAddress(i);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getNextInsnAddress(cs_insn* i)
{
	return llvm::ConstantInt::get(
		getDefaultType(),
		i->address + i->size);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getNextNextInsnAddress(cs_insn* i)
{
	return llvm::ConstantInt::get(llvm::Type::getInt32Ty(_module->getContext()),
		i->address + (2 * i->size));
}





bool Capstone2LlvmIrTranslatorTricore::isAllowedBasicMode(cs_mode m)
{
	return m == CS_MODE_THUMB; // there is no CS_MODE_TRICORE...
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
}

void Capstone2LlvmIrTranslatorTricore::modifyBasicMode(cs_mode m)
{
	// unsupported
}

void Capstone2LlvmIrTranslatorTricore::modifyExtraMode(cs_mode m)
{
	// unsupported
}

void Capstone2LlvmIrTranslatorTricore::generateEnvironmentArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorTricore::generateDataLayout()
{
	/**
	 * @src http://llvm.org/docs/LangRef.html#data-layout
	 * e little endian
	 * m:e ELF mangling
	 * p:32:32 32 bit pointer
	 * TODO floting point registers? f32 f64 f80 f128?
	 * n:32 native integer widths
	 * S:64 @src Tricore 1.6 Vol 1: 2.2.1 Table 2-1
	 */
	_module->setDataLayout("e-m:e-p:32:32-n32-S64");
}

uint32_t Capstone2LlvmIrTranslatorTricore::getArchByteSize()
{
	return 4;
}

uint32_t Capstone2LlvmIrTranslatorTricore::getArchBitSize()
{
	return getArchByteSize() * 8;
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::generateRegisters()
{
	createRegister(TRICORE_REG_PC, _regLt);
	createRegister(TRICORE_REG_PSW, _regLt);
	createRegister(TRICORE_REG_PCXI, _regLt);
	createRegister(TRICORE_REG_ISP, _regLt);
	createRegister(TRICORE_REG_SYSCON, _regLt);
	createRegister(TRICORE_REG_CPU_ID, _regLt);
	createRegister(TRICORE_REG_COMPAT, _regLt);

	createRegister(TRICORE_REG_D_0, _regLt);
	createRegister(TRICORE_REG_D_1, _regLt);
	createRegister(TRICORE_REG_D_2, _regLt);
	createRegister(TRICORE_REG_D_3, _regLt);
	createRegister(TRICORE_REG_D_4, _regLt);
	createRegister(TRICORE_REG_D_5, _regLt);
	createRegister(TRICORE_REG_D_6, _regLt);
	createRegister(TRICORE_REG_D_7, _regLt);
	createRegister(TRICORE_REG_D_8, _regLt);
	createRegister(TRICORE_REG_D_9, _regLt);
	createRegister(TRICORE_REG_D_10, _regLt);
	createRegister(TRICORE_REG_D_11, _regLt);
	createRegister(TRICORE_REG_D_12, _regLt);
	createRegister(TRICORE_REG_D_13, _regLt);
	createRegister(TRICORE_REG_D_14, _regLt);
	createRegister(TRICORE_REG_D_15, _regLt);

	createRegister(TRICORE_REG_A_0, _regLt);
	createRegister(TRICORE_REG_A_1, _regLt);
	createRegister(TRICORE_REG_A_2, _regLt);
	createRegister(TRICORE_REG_A_3, _regLt);
	createRegister(TRICORE_REG_A_4, _regLt);
	createRegister(TRICORE_REG_A_5, _regLt);
	createRegister(TRICORE_REG_A_6, _regLt);
	createRegister(TRICORE_REG_A_7, _regLt);
	createRegister(TRICORE_REG_A_8, _regLt);
	createRegister(TRICORE_REG_A_9, _regLt);
	createRegister(TRICORE_REG_A_10, _regLt);
	createRegister(TRICORE_REG_A_11, _regLt);
	createRegister(TRICORE_REG_A_12, _regLt);
	createRegister(TRICORE_REG_A_13, _regLt);
	createRegister(TRICORE_REG_A_14, _regLt);
	createRegister(TRICORE_REG_A_15, _regLt);
}




} // namespace capstone2llvmir
} // namespace retdec
