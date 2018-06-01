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
        {TRICORE_REG_PSW, "psw"},
        {TRICORE_REG_PCXI_PCX, "pcxi_pcx"},
        {TRICORE_REG_PC, "pc"},
        {TRICORE_REG_SYSCON, "syscon"},
        {TRICORE_REG_CPU_ID, "cpuid"},
        {TRICORE_REG_BIV, "biv"},
        {TRICORE_REG_BTV, "btv"},
        {TRICORE_REG_ISP, "isp"},
        {TRICORE_REG_ICR, "icr"},
        {TRICORE_REG_FCX, "fcx"},
        {TRICORE_REG_LCX, "lcx"},
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
        {TRICORE_REG_PSW, i32},
        {TRICORE_REG_PCXI_PCX, i32},
        {TRICORE_REG_PC, i32},
        {TRICORE_REG_SYSCON, i32},
        {TRICORE_REG_CPU_ID, i32},
        {TRICORE_REG_BIV, i32},
        {TRICORE_REG_BTV, i32},
        {TRICORE_REG_ISP, i32},
        {TRICORE_REG_ICR, i32},
        {TRICORE_REG_FCX, i32},
        {TRICORE_REG_LCX, i32},
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

        {TRICORE_REG_CF, i1},
        {TRICORE_REG_OF, i1},
        {TRICORE_REG_SOF, i1},
        {TRICORE_REG_AOF, i1},
        {TRICORE_REG_SAOF, i1},
    };

    _reg2type = std::move(r2t);
}

void Capstone2LlvmIrTranslatorTricore::generateDataLayout() {
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

void Capstone2LlvmIrTranslatorTricore::generateRegisters() {
    createRegister(TRICORE_REG_PSW, _regLt);
    createRegister(TRICORE_REG_PCXI_PCX, _regLt);
    createRegister(TRICORE_REG_PC, _regLt);
    createRegister(TRICORE_REG_SYSCON, _regLt);
    createRegister(TRICORE_REG_CPU_ID, _regLt);
    createRegister(TRICORE_REG_BIV, _regLt);
    createRegister(TRICORE_REG_BTV, _regLt);
    createRegister(TRICORE_REG_ISP, _regLt);
    createRegister(TRICORE_REG_ICR, _regLt);
    createRegister(TRICORE_REG_FCX, _regLt);
    createRegister(TRICORE_REG_LCX, _regLt);
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

    createRegister(TRICORE_REG_E_0, _regLt);
    createRegister(TRICORE_REG_E_2, _regLt);
    createRegister(TRICORE_REG_E_4, _regLt);
    createRegister(TRICORE_REG_E_6, _regLt);
    createRegister(TRICORE_REG_E_8, _regLt);
    createRegister(TRICORE_REG_E_10, _regLt);
    createRegister(TRICORE_REG_E_12, _regLt);
    createRegister(TRICORE_REG_E_14, _regLt);

    createRegister(TRICORE_REG_P_0, _regLt);
    createRegister(TRICORE_REG_P_2, _regLt);
    createRegister(TRICORE_REG_P_4, _regLt);
    createRegister(TRICORE_REG_P_6, _regLt);
    createRegister(TRICORE_REG_P_8, _regLt);
    createRegister(TRICORE_REG_P_10, _regLt);
    createRegister(TRICORE_REG_P_12, _regLt);
    createRegister(TRICORE_REG_P_14, _regLt);
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
    void (Capstone2LlvmIrTranslatorTricore::*)(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>&)>
    Capstone2LlvmIrTranslatorTricore::_i2fm =
    {
        // TRICORE_INS_NOP, TRICORE_INS_RET
        {0x00, &Capstone2LlvmIrTranslatorTricore::translate00},

        {TRICORE_INS_0B, &Capstone2LlvmIrTranslatorTricore::translate0B},

        {TRICORE_INS_ADDA, &Capstone2LlvmIrTranslatorTricore::translateAdd},
        {TRICORE_INS_ADDI, &Capstone2LlvmIrTranslatorTricore::translateAdd},
        {TRICORE_INS_ADDD_c, &Capstone2LlvmIrTranslatorTricore::translateAdd},
        {TRICORE_INS_ADDDD, &Capstone2LlvmIrTranslatorTricore::translateAdd},
        {TRICORE_INS_ADDIH_A, &Capstone2LlvmIrTranslatorTricore::translateAdd},
        {TRICORE_INS_ADDSCA, &Capstone2LlvmIrTranslatorTricore::translateAdd},

        {TRICORE_INS_CADD, &Capstone2LlvmIrTranslatorTricore::translateCadd},

        {TRICORE_INS_ANDD15, &Capstone2LlvmIrTranslatorTricore::translateAnd},
        {TRICORE_INS_BIT_OPERATIONS1, &Capstone2LlvmIrTranslatorTricore::translateBitOperations1},
        {TRICORE_INS_BIT_OPERATIONS2, &Capstone2LlvmIrTranslatorTricore::translateBitOperations2},

        {TRICORE_INS_CALL16, &Capstone2LlvmIrTranslatorTricore::translateCall},
        {TRICORE_INS_CALL32, &Capstone2LlvmIrTranslatorTricore::translateCall},
        {TRICORE_INS_FCALL, &Capstone2LlvmIrTranslatorTricore::translateCall},

        {TRICORE_INS_CMP, &Capstone2LlvmIrTranslatorTricore::translateCmp},
        {TRICORE_INS_EQ16, &Capstone2LlvmIrTranslatorTricore::translateCmp},

        {TRICORE_INS_DIV, &Capstone2LlvmIrTranslatorTricore::translateDiv},
        {TRICORE_INS_DVSTEP, &Capstone2LlvmIrTranslatorTricore::translateDiv},

        {TRICORE_INS_EXTR, &Capstone2LlvmIrTranslatorTricore::translateExtr},

        {TRICORE_INS_ISYNC, &Capstone2LlvmIrTranslatorTricore::translateIgnore},

        {TRICORE_INS_INST, &Capstone2LlvmIrTranslatorTricore::translateInsertBit},

        {TRICORE_INS_J32, &Capstone2LlvmIrTranslatorTricore::translateJ},
        {TRICORE_INS_J16, &Capstone2LlvmIrTranslatorTricore::translateJ},
        {TRICORE_INS_JA, &Capstone2LlvmIrTranslatorTricore::translateJ},
        {TRICORE_INS_JIA, &Capstone2LlvmIrTranslatorTricore::translateJ},
        {TRICORE_INS_JL, &Capstone2LlvmIrTranslatorTricore::translateJl},
        {TRICORE_INS_JNEQ32, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JEQA, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JLTD, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JEQ_15_c, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JNZ_D15, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JNZT, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JZD, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JGEZD, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JLEZD, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JZ_D15, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JZA_16, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JNED15, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JZT_16, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JGTZ, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},
        {TRICORE_INS_JGE_U_r, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},

        {TRICORE_INS_LEA, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDB, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD16A, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDA, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD_BUD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDA_PINC, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDD_PINC, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD_HD_PINC, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD_BUD15, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD_HD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDW, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDW16, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDHW16_REL, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDHW16, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDB_REL, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LDA_OFF, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_LD09, &Capstone2LlvmIrTranslatorTricore::translateLoad09},

        {TRICORE_INS_CMOVD, &Capstone2LlvmIrTranslatorTricore::translateConditionalLoad},

        {TRICORE_INS_LOOP, &Capstone2LlvmIrTranslatorTricore::translateConditionalJ},

        {TRICORE_INS_MFCR, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MTCR, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVA, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVAA, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVAD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVDA, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVDD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVD, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVD15, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVD_C16, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVH, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVH_A, &Capstone2LlvmIrTranslatorTricore::translateLoad},
        {TRICORE_INS_MOVU, &Capstone2LlvmIrTranslatorTricore::translateLoad},

        {TRICORE_INS_MULD, &Capstone2LlvmIrTranslatorTricore::translateMul},
        {TRICORE_INS_MULD2, &Capstone2LlvmIrTranslatorTricore::translateMul},
        {TRICORE_INS_MULE, &Capstone2LlvmIrTranslatorTricore::translateMul},

        {TRICORE_INS_SHAD, &Capstone2LlvmIrTranslatorTricore::translateShift},
        {TRICORE_INS_SHD, &Capstone2LlvmIrTranslatorTricore::translateShift},

        {TRICORE_INS_ST, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STA, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STB, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STBA, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_ST_BA, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STD, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STHW, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STW, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STWA, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_STD15, &Capstone2LlvmIrTranslatorTricore::translateStore},
        {TRICORE_INS_ST89, &Capstone2LlvmIrTranslatorTricore::translateStore89},

        {TRICORE_INS_SUBA10, &Capstone2LlvmIrTranslatorTricore::translateSub},
        {TRICORE_INS_SUBD, &Capstone2LlvmIrTranslatorTricore::translateSub},
        {TRICORE_INS_SUBD15, &Capstone2LlvmIrTranslatorTricore::translateSub},
        {TRICORE_INS_SUBD1516, &Capstone2LlvmIrTranslatorTricore::translateSub},

        {TRICORE_INS_ORD, &Capstone2LlvmIrTranslatorTricore::translateBitOperationsD},
        {TRICORE_INS_ANDD, &Capstone2LlvmIrTranslatorTricore::translateBitOperationsD},

    };

} // namespace capstone2llvmir
} // namespace retdec
