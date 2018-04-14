/**
 * @file src/capstone2llvmir/tricore/tricore_init.cpp
 * @brief Initializations for TriCore implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

/**
* TODO
*/
void Capstone2LlvmIrTranslatorTricore::initializeRegNameMap()
{
	return;
// 	std::map<uint32_t, std::string> r2n =
// 	{
// 			// x86_reg_rflags
// 			//
// 			{X86_REG_CF, "cf"},
// 			{X86_REG_PF, "pf"},
// 			{X86_REG_AF, "az"},
// 			{X86_REG_ZF, "zf"},
// 			{X86_REG_SF, "sf"},
// 			{X86_REG_TF, "tf"},
// 			{X86_REG_IF, "if"},
// 			{X86_REG_DF, "df"},
// 			{X86_REG_OF, "of"},
// 			{X86_REG_IOPL, "iopl"},
// 			{X86_REG_NT, "nt"},
// 			{X86_REG_RF, "rf"},
// 			{X86_REG_VM, "vm"},
// 			{X86_REG_AC, "ac"},
// 			{X86_REG_VIF, "vif"},
// 			{X86_REG_VIP, "vip"},
// 			{X86_REG_ID, "id"},
// 
// 			// x87_reg_status
// 			//
// 			{X87_REG_IE, "fpu_stat_IE"},
// 			{X87_REG_DE, "fpu_stat_DE"},
// 			{X87_REG_ZE, "fpu_stat_ZE"},
// 			{X87_REG_OE, "fpu_stat_OE"},
// 			{X87_REG_UE, "fpu_stat_UE"},
// 			{X87_REG_PE, "fpu_stat_PE"},
// 			{X87_REG_SF, "fpu_stat_SF"},
// 			{X87_REG_ES, "fpu_stat_ES"},
// 			{X87_REG_C0, "fpu_stat_C0"},
// 			{X87_REG_C1, "fpu_stat_C1"},
// 			{X87_REG_C2, "fpu_stat_C2"},
// 			{X87_REG_C3, "fpu_stat_C3"},
// 			{X87_REG_TOP, "fpu_stat_TOP"},
// 			{X87_REG_B, "fpu_stat_B"},
// 
// 			// x87_reg_control
// 			//
// 			{X87_REG_IM, "fpu_control_IM"},
// 			{X87_REG_DM, "fpu_control_DM"},
// 			{X87_REG_ZM, "fpu_control_ZM"},
// 			{X87_REG_OM, "fpu_control_OM"},
// 			{X87_REG_UM, "fpu_control_UM"},
// 			{X87_REG_PM, "fpu_control_PM"},
// 			{X87_REG_PC, "fpu_control_PC"},
// 			{X87_REG_RC, "fpu_control_RC"},
// 			{X87_REG_X, "fpu_control_X"},
// 
// 			// x87_reg_tag
// 			//
// 			{X87_REG_TAG0, "fpu_tag_0"},
// 			{X87_REG_TAG1, "fpu_tag_1"},
// 			{X87_REG_TAG2, "fpu_tag_2"},
// 			{X87_REG_TAG3, "fpu_tag_3"},
// 			{X87_REG_TAG4, "fpu_tag_4"},
// 			{X87_REG_TAG5, "fpu_tag_5"},
// 			{X87_REG_TAG6, "fpu_tag_6"},
// 			{X87_REG_TAG7, "fpu_tag_7"},
// 
// 			// FPU data registers
// 			// They are named as ST(X) in Capstone, which is not good for us.
// 			//
// 			{X86_REG_ST0, "st0"},
// 			{X86_REG_ST1, "st1"},
// 			{X86_REG_ST2, "st2"},
// 			{X86_REG_ST3, "st3"},
// 			{X86_REG_ST4, "st4"},
// 			{X86_REG_ST5, "st5"},
// 			{X86_REG_ST6, "st6"},
// 			{X86_REG_ST7, "st7"},
// 	};
// 
// 	_reg2name = std::move(r2n);
}
	
/**
* TODO
*/
void Capstone2LlvmIrTranslatorTricore::initializeRegTypeMap()
{
	return;
// 	auto* i1 = llvm::IntegerType::getInt1Ty(_module->getContext());
// 	auto* i2 = llvm::IntegerType::getIntNTy(_module->getContext(), 2);
// 	auto* i3 = llvm::IntegerType::getIntNTy(_module->getContext(), 3);
// 	auto* i8 = llvm::IntegerType::getInt8Ty(_module->getContext());
// 	auto* i16 = llvm::IntegerType::getInt16Ty(_module->getContext());
// 	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
// 	auto* i64 = llvm::IntegerType::getInt64Ty(_module->getContext());
// 	auto* fp80 = llvm::IntegerType::getX86_FP80Ty(_module->getContext());
// 
// 	auto* defTy = _origBasicMode == CS_MODE_64 ? i64 : i32;
// 
// 	std::map<uint32_t, llvm::Type*> r2t =
// 	{
// 			// x86_reg
// 			//
// 			{X86_REG_AH, i8},
// 			{X86_REG_AL, i8},
// 			{X86_REG_CH, i8},
// 			{X86_REG_CL, i8},
// 			{X86_REG_DH, i8},
// 			{X86_REG_DL, i8},
// 			{X86_REG_BH, i8},
// 			{X86_REG_BL, i8},
// 			{X86_REG_SPL, i8},
// 			{X86_REG_BPL, i8},
// 			{X86_REG_DIL, i8},
// 			{X86_REG_SIL, i8},
// 			{X86_REG_R8B, i8},
// 			{X86_REG_R9B, i8},
// 			{X86_REG_R10B, i8},
// 			{X86_REG_R11B, i8},
// 			{X86_REG_R12B, i8},
// 			{X86_REG_R13B, i8},
// 			{X86_REG_R14B, i8},
// 			{X86_REG_R15B, i8},
// 
// 			{X86_REG_AX, i16},
// 			{X86_REG_CX, i16},
// 			{X86_REG_DX, i16},
// 			{X86_REG_BP, i16},
// 			{X86_REG_BX, i16},
// 			{X86_REG_DI, i16},
// 			{X86_REG_SP, i16},
// 			{X86_REG_SI, i16},
// 			{X86_REG_SS, i16},
// 			{X86_REG_CS, i16},
// 			{X86_REG_DS, i16},
// 			{X86_REG_ES, i16},
// 			{X86_REG_FS, i16},
// 			{X86_REG_GS, i16},
// 			{X86_REG_R8W, i16},
// 			{X86_REG_R9W, i16},
// 			{X86_REG_R10W, i16},
// 			{X86_REG_R11W, i16},
// 			{X86_REG_R12W, i16},
// 			{X86_REG_R13W, i16},
// 			{X86_REG_R14W, i16},
// 			{X86_REG_R15W, i16},
// 			{X86_REG_IP, i16},
// 
// 			{X86_REG_EAX, i32},
// 			{X86_REG_EBP, i32},
// 			{X86_REG_EBX, i32},
// 			{X86_REG_ECX, i32},
// 			{X86_REG_EDI, i32},
// 			{X86_REG_EDX, i32},
// 			{X86_REG_ESI, i32},
// 			{X86_REG_ESP, i32},
// 			{X86_REG_R8D, i32},
// 			{X86_REG_R9D, i32},
// 			{X86_REG_R10D, i32},
// 			{X86_REG_R11D, i32},
// 			{X86_REG_R12D, i32},
// 			{X86_REG_R13D, i32},
// 			{X86_REG_R14D, i32},
// 			{X86_REG_R15D, i32},
// 			{X86_REG_EIP, i32},
// 			{X86_REG_EIZ, i32},
// 
// 			{X86_REG_RAX, i64},
// 			{X86_REG_RBP, i64},
// 			{X86_REG_RBX, i64},
// 			{X86_REG_RCX, i64},
// 			{X86_REG_RDI, i64},
// 			{X86_REG_RDX, i64},
// 			{X86_REG_RIP, i64},
// 			{X86_REG_RIZ, i64},
// 			{X86_REG_RSI, i64},
// 			{X86_REG_RSP, i64},
// 			{X86_REG_R8, i64},
// 			{X86_REG_R9, i64},
// 			{X86_REG_R10, i64},
// 			{X86_REG_R11, i64},
// 			{X86_REG_R12, i64},
// 			{X86_REG_R13, i64},
// 			{X86_REG_R14, i64},
// 			{X86_REG_R15, i64},
// 
// 			{X86_REG_ST0, fp80},
// 			{X86_REG_ST1, fp80},
// 			{X86_REG_ST2, fp80},
// 			{X86_REG_ST3, fp80},
// 			{X86_REG_ST4, fp80},
// 			{X86_REG_ST5, fp80},
// 			{X86_REG_ST6, fp80},
// 			{X86_REG_ST7, fp80},
// 
// 			{X86_REG_EFLAGS, defTy},
// 			{X86_REG_DR0, defTy},
// 			{X86_REG_DR1, defTy},
// 			{X86_REG_DR2, defTy},
// 			{X86_REG_DR3, defTy},
// 			{X86_REG_DR4, defTy},
// 			{X86_REG_DR5, defTy},
// 			{X86_REG_DR6, defTy},
// 			{X86_REG_DR7, defTy},
// 
// 			{X86_REG_CR0, defTy},
// 			{X86_REG_CR1, defTy},
// 			{X86_REG_CR2, defTy},
// 			{X86_REG_CR3, defTy},
// 			{X86_REG_CR4, defTy},
// 			{X86_REG_CR5, defTy},
// 			{X86_REG_CR6, defTy},
// 			{X86_REG_CR7, defTy},
// 			{X86_REG_CR8, defTy},
// 			{X86_REG_CR9, defTy},
// 			{X86_REG_CR10, defTy},
// 			{X86_REG_CR11, defTy},
// 			{X86_REG_CR12, defTy},
// 			{X86_REG_CR13, defTy},
// 			{X86_REG_CR14, defTy},
// 			{X86_REG_CR15, defTy},
// 
// 			// x86_reg_rflags
// 			//
// 			{X86_REG_CF, i1},
// 			{X86_REG_PF, i1},
// 			{X86_REG_AF, i1},
// 			{X86_REG_ZF, i1},
// 			{X86_REG_SF, i1},
// 			{X86_REG_TF, i1},
// 			{X86_REG_IF, i1},
// 			{X86_REG_DF, i1},
// 			{X86_REG_OF, i1},
// 			{X86_REG_IOPL, i2},
// 			{X86_REG_NT, i1},
// 			{X86_REG_RF, i1},
// 			{X86_REG_VM, i1},
// 			{X86_REG_AC, i1},
// 			{X86_REG_VIF, i1},
// 			{X86_REG_VIP, i1},
// 			{X86_REG_ID, i1},
// 
// 			// x87_reg_status
// 			//
// 			{X87_REG_IE, i1},
// 			{X87_REG_DE, i1},
// 			{X87_REG_ZE, i1},
// 			{X87_REG_OE, i1},
// 			{X87_REG_UE, i1},
// 			{X87_REG_PE, i1},
// 			{X87_REG_SF, i1},
// 			{X87_REG_ES, i1},
// 			{X87_REG_C0, i1},
// 			{X87_REG_C1, i1},
// 			{X87_REG_C2, i1},
// 			{X87_REG_C3, i1},
// 			{X87_REG_TOP, i3},
// 			{X87_REG_B, i1},
// 
// 			// x87_reg_control
// 			//
// 			{X87_REG_IM, i1},
// 			{X87_REG_DM, i1},
// 			{X87_REG_ZM, i1},
// 			{X87_REG_OM, i1},
// 			{X87_REG_UM, i1},
// 			{X87_REG_PM, i1},
// 			{X87_REG_PC, i2},
// 			{X87_REG_RC, i2},
// 			{X87_REG_X, i1},
// 
// 			// x87_reg_tag
// 			//
// 			{X87_REG_TAG0, i2},
// 			{X87_REG_TAG1, i2},
// 			{X87_REG_TAG2, i2},
// 			{X87_REG_TAG3, i2},
// 			{X87_REG_TAG4, i2},
// 			{X87_REG_TAG5, i2},
// 			{X87_REG_TAG6, i2},
// 			{X87_REG_TAG7, i2},
// 	};
// 
// 	_reg2type = std::move(r2t);
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::initializeArchSpecific()
{
	return;
// 	initializeRegistersParentMap();
}

} // namespace capstone2llvmir
} // namespace retdec