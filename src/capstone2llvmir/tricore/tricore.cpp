/**
 * @file src/capstone2llvmir/x86/x86.cpp
 * @brief TriCore implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iomanip>
#include <iostream>

#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorTricore::Capstone2LlvmIrTranslatorTricore(
		llvm::Module* m,
		cs_mode basic,
		cs_mode extra)
		:
		Capstone2LlvmIrTranslator(CS_ARCH_ALL, basic, extra, m)
// 		,
// 		_origBasicMode(basic),
// 		_reg2parentMap(X86_REG_ENDING, X86_REG_INVALID)
{
	// This needs to be called from concrete's class ctor, not abstract's
	// class ctor, so that virtual table is properly initialized.
// 	initialize();
	
	generateEnvironment();
}

Capstone2LlvmIrTranslatorTricore::~Capstone2LlvmIrTranslatorTricore()
{
	// Nothing specific to x86.
}

/** //TODO
 * x86 is special. When this returns @c true, mode can be used to initialize
 * x86 translator, but it does not have to be possible to modify translator
 * with this mode later. See @c modifyBasicMode().
 */
bool Capstone2LlvmIrTranslatorTricore::isAllowedBasicMode(cs_mode m)
{
// 	return m == CS_MODE_16 || m == CS_MODE_32 || m == CS_MODE_64;
	return m == CS_MODE_THUMB;
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedExtraMode(cs_mode m)
{
	return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
}


/** //TODO
 * x86 allows to change basic mode only to modes lower than the original
 * initialization mode an back to original mode (CS_MODE_16 < CS_MODE_32
 * < CS_MODE_64). This is because the original mode is used to initialize
 * module's environment with registers and other specific features. It is
 * possible to simulate lower modes in environments created for higher modes
 * (e.g. get ax register from eax), but not the other way around (e.g. get
 * rax from eax).bytes
 */
void Capstone2LlvmIrTranslatorTricore::modifyBasicMode(cs_mode m)
{
	return;
// 	if (!isAllowedBasicMode(m))
// 	{
// 		throw Capstone2LlvmIrModeError(
// 				_arch,
// 				m,
// 				Capstone2LlvmIrModeError::eType::BASIC_MODE);
// 	}
// 
// 	if ((_origBasicMode == CS_MODE_16)
// 			|| (_origBasicMode == CS_MODE_32 && m == CS_MODE_64))
// 	{
// 		throw Capstone2LlvmIrModeError(
// 				_arch,
// 				m,
// 				Capstone2LlvmIrModeError::eType::BASIC_MODE_CHANGE);
// 	}
// 
// 	if (cs_option(_handle, CS_OPT_MODE, m + _extraMode) != CS_ERR_OK)
// 	{
// 		throw CapstoneError(cs_errno(_handle));
// 	}
// 
// 	_basicMode = m;
}

/** TODO
 * It does not really make sense to change extra mode (little <-> big endian)
 * for x86 architecture, but it should not crash or anything, so whatever.
 */
void Capstone2LlvmIrTranslatorTricore::modifyExtraMode(cs_mode m)
{
// 	return;
// 	if (!isAllowedExtraMode(m))
// 	{
// 		throw Capstone2LlvmIrModeError(
// 				_arch,
// 				m,
// 				Capstone2LlvmIrModeError::eType::EXTRA_MODE);
// 	}
// 
// 	if (cs_option(_handle, CS_OPT_MODE, m + _basicMode) != CS_ERR_OK)
// 	{
// 		throw CapstoneError(cs_errno(_handle));
// 	}
// 
// 	_extraMode = m;
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::generateEnvironmentArchSpecific()
{
	return;
// 	generateX87RegLoadStoreFunctions();
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::generateDataLayout()
{
	return;
// 	switch (_origBasicMode)
// 	{
// 		case CS_MODE_16:
// 		{
// 			_module->setDataLayout("e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"); // clang -m16
// 			break;
// 		}
// 		case CS_MODE_32:
// 		{
// 			_module->setDataLayout("e-m:e-p:32:32-f64:32:64-f80:32-n8:16:32-S128"); // clang -m32
// 			break;
// 		}
// 		case CS_MODE_64:
// 		{
// 			_module->setDataLayout("e-m:e-i64:64-f80:128-n8:16:32:64-S128"); // clang
// 			break;
// 		}
// 		default:
// 		{
// 			throw Capstone2LlvmIrError("Unhandled mode in getStackPointerRegister().");
// 			break;
// 		}
// 	}
}

uint32_t Capstone2LlvmIrTranslatorTricore::getArchByteSize()
{
	return 4;
// 	switch (_origBasicMode)
// 	{
// 		case CS_MODE_16: return 2;
// 		case CS_MODE_32: return 4;
// 		case CS_MODE_64: return 8;
// 		default:
// 		{
// 			throw Capstone2LlvmIrError("Unhandled mode in getArchByteSize().");
// 			break;
// 		}
// 	}
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
// 	generateRegistersCommon();
// 
// 	switch (_origBasicMode)
// 	{
// 		case CS_MODE_16: generateRegisters16(); break;
// 		case CS_MODE_32: generateRegisters32(); break;
// 		case CS_MODE_64: generateRegisters64(); break;
// 		default:
// 		{
// 			throw Capstone2LlvmIrError("Unhandled mode in generateRegisters().");
// 			break;
// 		}
// 	}
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::translateInstruction(
		cs_insn* i,
		llvm::IRBuilder<>& irb)
{
	std::cout << i->mnemonic << " " << i->op_str << std::endl;
	std::cout << i->bytes << std::endl;
	return;
// 	_insn = i;
// 
// 	cs_detail* d = i->detail;
// 	cs_x86* xi = &d->x86;
// 
// 	// At the moment, we want to notice these instruction and check if we
// 	// can translate them without any special handling.
// 	// There are more internals in cs_x86 (e.g. sib, sicp), but Capstone
// 	// uses them to interpret instruction operands and we do not have to do
// 	// it ourselves.
// 	// It is likely that the situation will be the same for these, but we
// 	// still want to manually check.
// 	//
// 
// 	// REP @ INS, OUTS, MOVS, LODS, STOS
// 	// REPE/REPZ @ CMPS, SCAS
// 	// REPNE/REPNZ @ CMPS, SCAS
// 	//
// 	// X86_PREFIX_REP == X86_PREFIX_REPE
// 	//
// 	static std::set<unsigned> handledReps =
// 	{
// 		// X86_PREFIX_REP
// 		X86_INS_OUTSB, X86_INS_OUTSD, X86_INS_OUTSW,
// 		X86_INS_INSB, X86_INS_INSD, X86_INS_INSW,
// 		X86_INS_STOSB, X86_INS_STOSD, X86_INS_STOSQ, X86_INS_STOSW,
// 		X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSD, X86_INS_MOVSQ,
// 		X86_INS_LODSB, X86_INS_LODSW, X86_INS_LODSD, X86_INS_LODSQ,
// 		// X86_PREFIX_REPE
// 		X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ,
// 		X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ
// 	};
// 	static std::set<unsigned> handledRepnes =
// 	{
// 		// X86_PREFIX_REPNE
// 		X86_INS_CMPSB, X86_INS_CMPSW, X86_INS_CMPSD, X86_INS_CMPSQ,
// 		X86_INS_SCASB, X86_INS_SCASW, X86_INS_SCASD, X86_INS_SCASQ,
// 		// BND prefix == X86_PREFIX_REPNE
// 		// Some total bullshit, ignore it for all of these instructions:
// 		X86_INS_CALL, X86_INS_LCALL, X86_INS_RET, X86_INS_JMP,
// 		X86_INS_JAE, X86_INS_JA, X86_INS_JBE, X86_INS_JB, X86_INS_JE, X86_INS_JGE,
// 		X86_INS_JG, X86_INS_JLE, X86_INS_JL, X86_INS_JNE, X86_INS_JNO,
// 		X86_INS_JNP, X86_INS_JNS, X86_INS_JO, X86_INS_JP, X86_INS_JS
// 	};
// 	if (xi->prefix[0])
// 	{
// 		if (xi->prefix[0] == X86_PREFIX_REP
// 				&& handledReps.find(i->id) == handledReps.end())
// 		{
// //std::cout << "prefix[0] == X86_PREFIX_REP @ " << std::hex << i->address << std::endl;
// //exit(1);
// //			assert(false && "rep prefix not handled");
// 			return;
// 		}
// 		else if (xi->prefix[0] == X86_PREFIX_REP)
// 		{
// 			// Nothing, REP should be handled.
// 		}
// 		else if (xi->prefix[0] == X86_PREFIX_REPNE
// 				&& handledRepnes.find(i->id) == handledRepnes.end())
// 		{
// //std::cout << "prefix[0] == X86_PREFIX_REPNE @ " << std::hex << i->address << std::endl;
// //std::cout << i->mnemonic << " " << i->op_str << std::endl;
// //exit(1);
// //			assert(false && "repne prefix not handled");
// 			return;
// 		}
// 		else if (xi->prefix[0] == X86_PREFIX_REPNE)
// 		{
// 			// Nothing, REPNE should be handled.
// 		}
// 		else if (xi->prefix[0] == X86_PREFIX_LOCK)
// 		{
// 			// Nothing, LOCK does not matter for decompilation.
// 		}
// 	}
// 
// //	assert(!xi->sse_cc);
// //	assert(!xi->avx_cc);
// //	assert(!xi->avx_sae);
// //	assert(!xi->avx_rm);
// 
// 	auto fIt = _i2fm.find(i->id);
// 	if (fIt != _i2fm.end() && fIt->second != nullptr)
// 	{
// 		auto f = fIt->second;
// //std::cout << std::hex << i->address << " @ " << i->mnemonic << " " << i->op_str << std::endl;
// 		(this->*f)(i, xi, irb);
// 	}
// 	else
// 	{
// 		bool silentSkip = true;
// 		for (unsigned j = 0; j < d->groups_count; ++j)
// 		{
// 			static std::set<uint8_t> ignoredGroups =
// 			{
// 					X86_GRP_3DNOW,
// 					X86_GRP_AES,
// 					X86_GRP_ADX,
// 					X86_GRP_AVX,
// 					X86_GRP_AVX2,
// 					X86_GRP_AVX512,
// 					X86_GRP_MMX,
// 					X86_GRP_SHA,
// 					X86_GRP_SSE1,
// 					X86_GRP_SSE2,
// 					X86_GRP_SSE3,
// 					X86_GRP_SSE41,
// 					X86_GRP_SSE42,
// 					X86_GRP_SSE4A,
// 					X86_GRP_SSSE3,
// 			};
// 			uint32_t g = d->groups[j];
// 			if (ignoredGroups.count(g))
// 			{
// 				silentSkip = true;
// 				break;
// 			}
// 		}
// 
// 		if (!silentSkip)
// 		{
// 			std::stringstream msg;
// 			msg << "Translation of unhandled instruction: " << i->id << " ("
// 					<< i->mnemonic << " " << i->op_str << ") @ " << std::hex
// 					<< i->address << "\n";
// //std::cout << msg.str() << std::endl;
// //exit(1);
// 			throw Capstone2LlvmIrError(msg.str());
// 		}
// 	}
}

} // namespace capstone2llvmir
} // namespace retdec