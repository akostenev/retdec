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

	std::map<uint32_t, std::string> r2n =
	{
		{TRICORE_REG_PC, "pc"},
		{TRICORE_REG_PSW, "psw"},
		{TRICORE_REG_PCXI, "pcxi"},
		{TRICORE_REG_ISP, "isp"},
		{TRICORE_REG_SYSCON, "syscon"},
		{TRICORE_REG_CPU_ID, "id"},
		{TRICORE_REG_COMPAT, "compat"},

		{TRICORE_REG_D_0, "d0"},
		{TRICORE_REG_D_1, "d1"},
		{TRICORE_REG_D_2, "d2"},
		{TRICORE_REG_D_3, "d3"},
		{TRICORE_REG_D_4, "d4"},
		{TRICORE_REG_D_5, "d5"},
		{TRICORE_REG_D_6, "d6"},
		{TRICORE_REG_D_7, "d7"},
		{TRICORE_REG_D_8, "d8"},
		{TRICORE_REG_D_9, "d9"},
		{TRICORE_REG_D_10, "d10"},
		{TRICORE_REG_D_11, "d11"},
		{TRICORE_REG_D_12, "d12"},
		{TRICORE_REG_D_13, "d13"},
		{TRICORE_REG_D_14, "d14"},
		{TRICORE_REG_D_15, "d15"},

		{TRICORE_REG_A_0, "a0"},
		{TRICORE_REG_A_1, "a1"},
		{TRICORE_REG_A_2, "a2"},
		{TRICORE_REG_A_3, "a3"},
		{TRICORE_REG_A_4, "a4"},
		{TRICORE_REG_A_5, "a5"},
		{TRICORE_REG_A_6, "a6"},
		{TRICORE_REG_A_7, "a7"},
		{TRICORE_REG_A_8, "a8"},
		{TRICORE_REG_A_9, "a9"},
		{TRICORE_REG_A_10, "a10"},
		{TRICORE_REG_A_11, "a11"},
		{TRICORE_REG_A_12, "a12"},
		{TRICORE_REG_A_13, "a13"},
		{TRICORE_REG_A_14, "a14"},
		{TRICORE_REG_A_15, "a15"},

		{TRICORE_REG_E_0, "e0"},
		{TRICORE_REG_E_2, "e2"},
		{TRICORE_REG_E_4, "e4"},
		{TRICORE_REG_E_6, "e6"},
		{TRICORE_REG_E_8, "e8"},
		{TRICORE_REG_E_10, "e10"},
		{TRICORE_REG_E_12, "e12"},
		{TRICORE_REG_E_14, "e14"},

		{TRICORE_REG_P_0, "p0"},
		{TRICORE_REG_P_2, "p2"},
		{TRICORE_REG_P_4, "p4"},
		{TRICORE_REG_P_6, "p6"},
		{TRICORE_REG_P_8, "p8"},
		{TRICORE_REG_P_10, "p10"},
		{TRICORE_REG_P_12, "p12"},
		{TRICORE_REG_P_14, "p14"},

		{TRICORE_REG_SP, "sp"},
		{TRICORE_REG_RA, "ra"},

		{TRICORE_REG_CF, "cf"},
		{TRICORE_REG_OF, "of"},
		{TRICORE_REG_SOF, "sof"},
		{TRICORE_REG_AOF, "aof"},
		{TRICORE_REG_SAOF, "saof"},
	};

	_reg2name = std::move(r2n);
}

/**
* TODO
*/
void Capstone2LlvmIrTranslatorTricore::initializeRegTypeMap()
{
	auto* i1 = llvm::IntegerType::getInt1Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* i64 = llvm::IntegerType::getInt64Ty(_module->getContext());

	std::map<uint32_t, llvm::Type*> r2t =
	{
		{TRICORE_REG_PC, i32},
		{TRICORE_REG_PSW, i32},
		{TRICORE_REG_PCXI, i32},
		{TRICORE_REG_ISP, i32},
		{TRICORE_REG_SYSCON, i32},
		{TRICORE_REG_CPU_ID, i32},
		{TRICORE_REG_COMPAT, i32},

		{TRICORE_REG_D_0, i32},
		{TRICORE_REG_D_1, i32},
		{TRICORE_REG_D_2, i32},
		{TRICORE_REG_D_3, i32},
		{TRICORE_REG_D_4, i32},
		{TRICORE_REG_D_5, i32},
		{TRICORE_REG_D_6, i32},
		{TRICORE_REG_D_7, i32},
		{TRICORE_REG_D_8, i32},
		{TRICORE_REG_D_9, i32},
		{TRICORE_REG_D_10, i32},
		{TRICORE_REG_D_11, i32},
		{TRICORE_REG_D_12, i32},
		{TRICORE_REG_D_13, i32},
		{TRICORE_REG_D_14, i32},
		{TRICORE_REG_D_15, i32},

		{TRICORE_REG_A_0, i32},
		{TRICORE_REG_A_1, i32},
		{TRICORE_REG_A_2, i32},
		{TRICORE_REG_A_3, i32},
		{TRICORE_REG_A_4, i32},
		{TRICORE_REG_A_5, i32},
		{TRICORE_REG_A_6, i32},
		{TRICORE_REG_A_7, i32},
		{TRICORE_REG_A_8, i32},
		{TRICORE_REG_A_9, i32},
		{TRICORE_REG_A_10, i32},
		{TRICORE_REG_A_11, i32},
		{TRICORE_REG_A_12, i32},
		{TRICORE_REG_A_13, i32},
		{TRICORE_REG_A_14, i32},
		{TRICORE_REG_A_15, i32},

		{TRICORE_REG_E_0, i64},
		{TRICORE_REG_E_2, i64},
		{TRICORE_REG_E_4, i64},
		{TRICORE_REG_E_6, i64},
		{TRICORE_REG_E_8, i64},
		{TRICORE_REG_E_10, i64},
		{TRICORE_REG_E_12, i64},
		{TRICORE_REG_E_14, i64},

		{TRICORE_REG_P_0, i64},
		{TRICORE_REG_P_2, i64},
		{TRICORE_REG_P_4, i64},
		{TRICORE_REG_P_6, i64},
		{TRICORE_REG_P_8, i64},
		{TRICORE_REG_P_10, i64},
		{TRICORE_REG_P_12, i64},
		{TRICORE_REG_P_14, i64},

		{TRICORE_REG_SP, i64},
		{TRICORE_REG_RA, i64},

		{TRICORE_REG_CF, i1},
		{TRICORE_REG_OF, i1},
		{TRICORE_REG_SOF, i1},
		{TRICORE_REG_AOF, i1},
		{TRICORE_REG_SAOF, i1},
	};

	_reg2type = std::move(r2t);
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::initializeArchSpecific()
{
	return; // nothing
}

std::map<
	std::size_t,
	void (Capstone2LlvmIrTranslatorTricore::*)(cs_insn* i, llvm::IRBuilder<>&)>
	Capstone2LlvmIrTranslatorTricore::_i2fm =
	{
// 		{TRICORE_INS_INVALID, nullptr}, // Same as TRICORE_INS_NOP

		{TRICORE_INS_J_24, &Capstone2LlvmIrTranslatorTricore::translateJ},
		{TRICORE_INS_J_8, &Capstone2LlvmIrTranslatorTricore::translateJ},
		{TRICORE_INS_JA, &Capstone2LlvmIrTranslatorTricore::translateJ},
		{TRICORE_INS_JEQ_15_c, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},

		{TRICORE_INS_LD_HD, &Capstone2LlvmIrTranslatorTricore::translateLd},

                {TRICORE_INS_NOP, &Capstone2LlvmIrTranslatorTricore::translateNop}

	};

} // namespace capstone2llvmir
} // namespace retdec
