#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_J_24:
        case TRICORE_INS_J_8:
            mi.operands[0] = mi.operands[0].imm * 2;
            break;
        case TRICORE_INS_JA: {
            std::bitset<64> disp24(mi.operands[0].imm);
            mi.operands[0].imm = ((bitRange<20, 23>(disp24) << 28) | (bitRange<0, 19>(disp24) << 1)).to_ulong();
            break;
        }
        default:
            throw Capstone2LlvmIrError("translateJ " + std::to_string(i->id));
    }

    op0 = loadOpUnary(&mi, irb);
    generateBranchFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_JEQ_15_c:
            mi.operands[2] = mi.operands[2].imm * 2;
            break;
        default:
            throw Capstone2LlvmIrError("translateConditionalJ " + std::to_string(i->id));
    }

    std::tie(op0, op1, op2) = loadOpTernary(&mi, irb);
    op1 = irb.CreateZExtOrTrunc(op1, op0->getType());

    llvm::Value* cond = nullptr;
    if (mi.operands[3].imm) { // TRICORE_INS_JNE_c
        cond = irb.CreateICmpNE(op0, op1);
    } else { // TRICORE_INS_JEQ_15_c
        cond = irb.CreateICmpEQ(op0, op1);
    }

    generateCondBranchFunctionCall(irb, cond, op2);
}

void Capstone2LlvmIrTranslatorTricore::translateLd(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            break;
        default:
            throw Capstone2LlvmIrError("translateLd " + std::to_string(i->id));
    }


    llvm::Type* ty = irb.getInt16Ty(); //half-word
    eOpConv ct = eOpConv::ZEXT_TRUNC; //zero_ext

    op1 = loadOpBinaryOp1(&mi, irb, ty);
    storeOp(mi.operands[0], op1, irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateNop(cs_insn* i, llvm::IRBuilder<>& irb) {
    if (i->id != TRICORE_INS_NOP) {
        throw Capstone2LlvmIrError("Should be 0x00 TRICORE NOP Instruction, but was " + std::to_string(i->id));
    }
}


} // namespace capstone2llvmir
} // namespace retdec
