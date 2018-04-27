#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateAdd(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    llvm::Value* add = nullptr;
    switch(i->id) {
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
            op1 = loadOp(mi.operands[1], irb);
            op2 = loadOp(mi.operands[2], irb);
            add = irb.CreateAdd(op1, op2);
            break;
        case TRICORE_INS_ADDD: //result = D[a] + sign_ext(const4); D[a] = result[31:0];
            op0 = loadOp(mi.operands[0], irb);
            op1 = loadOp(mi.operands[1], irb);
            add = irb.CreateAdd(op0, op1);
            break;
        default:
            assert(false);
    }

    storeOp(mi.operands[0], add, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations1(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    //all i->id == 0x8F

    std::tie(op1, op2) = loadOp1Op2(&mi, irb, eOpConv::SECOND_ZEXT);
    llvm::Value* o = nullptr;
    switch (mi.op2) {
        case 0x0A: // OR D[c] = D[a] | zero_ext(const9);
            o = irb.CreateOr(op1, op2);
            break;
        case 0x08: // D[c] = D[a] & zero_ext(const9);
            o = irb.CreateAnd(op1, op2);
            break;
        case 0x0C: // D[c] = D[a] ^ zero_ext(const9);
            o = irb.CreateXor(op1, op2);
            break;
        default:
            assert(false);
    }

    storeOp(mi.operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations2(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    //all i->id == 0x0F

    switch (mi.op2) {
        case 0x08: // D[c] = D[a] & D[b];
            break;

        default:
            assert(false);
    }

    std::tie(op1, op2) = loadOp1Op2(&mi, irb, eOpConv::SECOND_ZEXT);
    auto* o = irb.CreateAnd(op1, op2);
    storeOp(mi.operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_J_24: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_J_8: //PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0}; //TODO check 1’b0
            break;
        default:
            assert(false);
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
        case TRICORE_INS_JEQ_15_c: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
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
        case TRICORE_INS_JNZD: //if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        {
            op0 = loadOp(mi.operands[0], irb);
            op0 = irb.CreateAnd(op0, 1 << mi.brnN);

            cond = irb.CreateICmpNE(op0, llvm::ConstantInt::get(getDefaultType(), 0));
            cs_tricore_op d15 = cs_tricore_op(TRICORE_REG_D_15);
            target = loadOp(d15, irb);

            break;
        }
        case TRICORE_INS_JNZT: //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
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
        case TRICORE_INS_JZD: //if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        {
            op0 = loadOp(mi.operands[0], irb);
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(getDefaultType(), 0));
            target = loadOp(mi.operands[1], irb);
            break;
        }
        default:
            assert(false);
    }

    generateCondBranchFunctionCall(irb, cond, target);
}

void Capstone2LlvmIrTranslatorTricore::translateLea(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch(i->id) {
        case TRICORE_INS_LEA: // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
            break;
        default:
            assert(false);
    }

    op1 = loadOp(mi.operands[1], irb);
    op1 = irb.CreateAdd(op1, loadOp(mi.operands[2], irb)); //TODO check if use x86 loadOp(..., lea=true)
    storeOp(mi.operands[0], op1, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateLoad(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    llvm::Type* ty = getDefaultType();
    eOpConv ct = eOpConv::THROW;
    switch (i->id) {
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            ty = irb.getInt16Ty(); //half-word
            ct = eOpConv::SEXT_TRUNC;
            break;
        case TRICORE_INS_LD_BUD: // D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
            ty = irb.getInt8Ty(); //byte
            ct = eOpConv::ZEXT_TRUNC;
            break;
        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
        case TRICORE_INS_MTCR: // CR[const16] = D[a];
        case TRICORE_INS_MFCR: // D[c] = CR[const16];
        case TRICORE_INS_MOVU: // D[c] = zero_ext(const16);
            ct = eOpConv::ZEXT_TRUNC;
            break;
        case TRICORE_INS_MOVD_A: // D[a] = sign_ext(const4);
        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
            ct = eOpConv::SEXT_TRUNC;
            break;
        case TRICORE_INS_MOVAD: //A[a] = D[b];
        case TRICORE_INS_MOVDA: //D[a] = A[b];
            break;
        default:
            assert(false);
    }

    op1 = loadOpBinaryOp1(&mi, irb, ty);
    storeOp(mi.operands[0], op1, irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateLdAbs(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_LD_A:
            break;
        default:
            assert(false);
    }

    op1 = loadOpBinaryOp1(&mi, irb);
    storeOp(mi.operands[0], op1, irb, eOpConv::NOTHING);
}

void Capstone2LlvmIrTranslatorTricore::translateShift(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    std::tie(op0, op1) = loadOpBinary(&mi, irb);
    llvm::Value* o = nullptr;
    switch (i->id) {
        case TRICORE_INS_SHAD:
            o = irb.CreateShl(op0, op1);
            break;
        default:
            assert(false);
    }

    storeOp(mi.operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateStore(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    switch (i->id) {
        case TRICORE_INS_ST_A: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, word) = A[a];
            break;
        default:
            assert(false);
    }

    llvm::Type* ty = nullptr;
    switch (i->id) {
        case TRICORE_INS_ST_A: ty = irb.getInt32Ty(); break;
        default:
            assert(false);
    }

    op0 = loadOp(mi.operands[0], irb);
//     if (ty->isFloatingPointTy())
//     {
//             // This is not exact, in 64-bit mode, only lower 32-bits of FPR should
//             // be used -> truncate, not cast.
//             op0 = irb.CreateFPCast(op0, ty);
//     }
    if (ty->isIntegerTy()) {
        op0 = irb.CreateZExtOrTrunc(op0, ty);
    } else {
        assert(false && "unhandled type");
        return;
    }
    storeOp(mi.operands[1], op0, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateSub(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    std::tie(op0, op1) = loadOpBinary(&mi, irb);
    llvm::Value* o = nullptr;
    switch (i->id) {
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            o = irb.CreateSub(op0, op1);
            break;
        default:
            assert(false);
    }
    storeOp(mi.operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateNop(cs_insn* i, llvm::IRBuilder<>& irb) {
    // nothing
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperationsD(cs_insn* i, llvm::IRBuilder<>& irb) {
    cs_tricore mi(i);

    std::tie(op0, op1) = loadOpBinary(&mi, irb);
    llvm::Value* o = nullptr;
    switch (i->id) {
        case TRICORE_INS_ORD: //D[a] = D[a] | D[b];
            o = irb.CreateOr(op0, op1);
            break;
        case TRICORE_INS_ANDD:
            o = irb.CreateAnd(op0, op1);
            break;
        default:
            assert(false);
    }

    storeOp(mi.operands[0], o, irb);
}


} // namespace capstone2llvmir
} // namespace retdec
