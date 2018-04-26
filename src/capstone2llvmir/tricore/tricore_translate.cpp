#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateAdd(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch(i->id) {
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];

            break;
        default:
            throw Capstone2LlvmIrError("translateAdd " + std::to_string(i->id));
    }

    op1 = loadOp(mi.operands[1], irb);
    op2 = loadOp(mi.operands[2], irb);
    auto* add = irb.CreateAdd(op1, op2);
    storeOp(mi.operands[0], add, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_J_24:
        case TRICORE_INS_J_8:

            break;
        case TRICORE_INS_JA: {

            break;
        }
        default:
            throw Capstone2LlvmIrError("translateJ " + std::to_string(i->id));
    }

    op0 = loadOpUnary(&mi, irb);
    generateBranchFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateJal(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    storeRegister(TRICORE_REG_RA, getNextNextInsnAddress(i), irb);

    op0 = loadOpUnary(&mi, irb);
    generateCallFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    llvm::Value* cond = nullptr;
    llvm::Value* target = nullptr;
    switch (i->id) {
        case TRICORE_INS_JEQ_15_c:
        {
            std::tie(op0, op1, op2) = loadOpTernary(&mi, irb);
            op1 = irb.CreateZExtOrTrunc(op1, op0->getType());

            if (mi.op2) { // TRICORE_INS_JNE_c
                cond = irb.CreateICmpNE(op0, op1);
            } else { // TRICORE_INS_JEQ_15_c
                cond = irb.CreateICmpEQ(op0, op1);
            }
            target = op2;
            break;
        }
        case TRICORE_INS_JNZT:
        {
            op0 = loadOp(mi.operands[0], irb);
            op0 = irb.CreateAnd(op0, 1 << mi.brnN);

            if (mi.op2) { // eq A[a][n] == 1
                cond = irb.CreateICmpSGE(op0, llvm::ConstantInt::get(getDefaultType(), 1));
            } else {
                cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(getDefaultType(), 0));
            }
            target = loadOp(mi.operands[1], irb);
            break;
        }
        default:
            throw Capstone2LlvmIrError("translateConditionalJ " + std::to_string(i->id));
    }

    generateCondBranchFunctionCall(irb, cond, target);
}

void Capstone2LlvmIrTranslatorTricore::translateLea(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch(i->id) {
        case TRICORE_INS_LEA: // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
            break;
        default:
            throw Capstone2LlvmIrError("translateConditionalJ " + std::to_string(i->id));
    }

    op1 = loadOp(mi.operands[1], irb);
    op1 = irb.CreateAdd(op1, loadOp(mi.operands[2], irb)); //TODO check if use x86 loadOp(..., lea=true)
    storeOp(mi.operands[0], op1, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateLoad(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    llvm::Type* ty = nullptr;
    switch (i->id) {
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            ty = irb.getInt16Ty(); //half-word
            break;
        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
            ty = getDefaultType();
            break;
        default:
            throw Capstone2LlvmIrError("translateLoad " + std::to_string(i->id));
    }

    eOpConv ct = eOpConv::ZEXT_TRUNC; //zero_ext

    op1 = loadOpBinaryOp1(&mi, irb, ty);
    storeOp(mi.operands[0], op1, irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateLdAbs(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_LD_A:
            break;
        default:
            throw Capstone2LlvmIrError("translateLdAbs " + std::to_string(i->id));
    }

    op1 = loadOpBinaryOp1(&mi, irb);
    storeOp(mi.operands[0], op1, irb, eOpConv::NOTHING);
}

void Capstone2LlvmIrTranslatorTricore::translateNop(cs_insn* i, llvm::IRBuilder<>& irb) {
    if (i->id != TRICORE_INS_NOP) {
        throw Capstone2LlvmIrError("Should be 0x00 TRICORE NOP Instruction, but was " + std::to_string(i->id));
    }
}


} // namespace capstone2llvmir
} // namespace retdec
