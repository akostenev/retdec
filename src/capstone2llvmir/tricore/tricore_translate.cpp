#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateAdd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::Value* add = nullptr;
    switch(i->id) {
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            add = irb.CreateAdd(op1, op2);
            break;
        case TRICORE_INS_ADDA: //A[a] = A[a] + sign_ext(const4);
        case TRICORE_INS_ADDD: //result = D[a] + sign_ext(const4); D[a] = result[31:0];
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            add = irb.CreateAdd(op0, op1);
            break;
        default:
            assert(false);
    }

    storeOp(t->operands[0], add, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations1(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    //all i->id == 0x8F

    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);

    llvm::Value* o = nullptr;
    switch (t->op2) {
        case 0x00: // D[c] = (const9[5:0] >= 0) ? D[a] << const9[5:0] : D[a] >> (-const9[5:0]);
            if (t->operands[2].imm.value && 1 << 5) { // msb is set
                o = irb.CreateLShr(op1, op2); //TODO check -const9
            } else {
                o = irb.CreateShl(op1, op2);
            }

            break;
        case 0x0A: // OR D[c] = D[a] | zero_ext(const9);
            o = irb.CreateOr(op1, op2);
            break;
        case 0x08: // D[c] = D[a] & zero_ext(const9);
            o = irb.CreateAnd(op1, op2);
            break;
        case 0x0C: // D[c] = D[a] ^ zero_ext(const9);
            o = irb.CreateXor(op1, op2);
            break;
        case 0x0E: //D[c] = D[a] & ~zero_ext(const9);
            o = irb.CreateAnd(op1, irb.CreateNot(op2));
            break;
        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations2(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    //all i->id == 0x0F

    switch (t->op2) {
        case 0x08: // D[c] = D[a] & D[b];
            break;

        default:
            assert(false);
    }

    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);

    auto* o = irb.CreateAnd(op1, op2);
    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateExtr(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);
    switch (t->op2) {
        case 0x3: //D[c] = zero_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
        {
            auto* lshr = irb.CreateLShr(op1, op2); //(D[a] >> pos)
            auto* extr = irb.CreateAnd(lshr, (1 << t->operands[3].imm.value) - 1); //TODO check
            storeOp(t->operands[0], extr, irb);
            break;
        }
        default:
            assert(false);
    }

}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (i->id) {
        case TRICORE_INS_J_24: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_J_8: //PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0}; //TODO check 1’b0
            break;
        default:
            assert(false);
    }

    op0 = loadOp(t->operands[0], irb);
    generateBranchFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateJal(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    storeRegister(TRICORE_REG_RA, getNextNextInsnAddress(i), irb);

    op0 = loadOp(t->operands[0], irb);
    generateCallFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::Value* cond = nullptr;
    llvm::Value* target = nullptr;
    switch (i->id) {
        case TRICORE_INS_LOOP: //if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
        {
            op0 = loadOp(t->operands[0], irb);
            auto* sub = irb.CreateSub(op0, llvm::ConstantInt::get(op0->getType(), 1));
            storeRegister(t->operands[0].reg, sub, irb);

            cond = irb.CreateICmpNE(sub, llvm::ConstantInt::get(sub->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;
        }
        case TRICORE_INS_JEQ_A:
        {
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpEQ(op0, op1);
                    break;
                case 0x01:
                    cond = irb.CreateICmpNE(op0, op1);
                    break;
                default:
                    assert(false);
            }
            break;
        }
        case TRICORE_INS_JEQ_15_c: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
        {
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);

            op1 = irb.CreateSExtOrTrunc(op1, op0->getType());

            if (t->op2) { // TRICORE_INS_JNE_c
                cond = irb.CreateICmpNE(op0, op1);
            } else { // TRICORE_INS_JEQ_15_c
                cond = irb.CreateICmpEQ(op0, op1);
            }
            target = op2;
            break;
        }
        case TRICORE_INS_JNZ_D15: //if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        {
            auto* d15 = loadRegister(TRICORE_REG_D_15, irb);
            target = loadOp(t->operands[0], irb);
            cond = irb.CreateICmpNE(d15, llvm::ConstantInt::get(getType(), 0));
            break;
        }
        case TRICORE_INS_JZ_D15: // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
        {
            auto* d15 = loadRegister(TRICORE_REG_D_15, irb);
            target = loadOp(t->operands[0], irb);
            cond = irb.CreateICmpEQ(d15, llvm::ConstantInt::get(getType(), 0));
            break;
        }
        case TRICORE_INS_JNZT: //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
        {
            op0 = loadOp(t->operands[0], irb);
            op0 = irb.CreateAnd(op0, 1 << t->n);

            if (t->op2) { // eq A[a][n] == 1
                cond = irb.CreateICmpSGE(op0, llvm::ConstantInt::get(getType(), 1));
            } else {
                cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(getType(), 0));
            }
            target = loadOp(t->operands[1], irb);
            break;
        }
        case TRICORE_INS_JZD: //if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZA_16: //if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        {
            op0 = loadOp(t->operands[0], irb);
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;
        }
        default:
            assert(false);
    }

    generateCondBranchFunctionCall(irb, cond, target);
}

void Capstone2LlvmIrTranslatorTricore::translateLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    eOpConv ct = eOpConv::THROW;
    llvm::Value* pinc = nullptr;
    switch (i->id) {
        case TRICORE_INS_LEA: // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
        case TRICORE_INS_LDW: //EA = A[b] + sign_ext(off16); D[a] = M(EA, word);
        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
        case TRICORE_INS_MOVD_A: // D[a] = sign_ext(const4);
            ct = eOpConv::SEXT_TRUNC;
            break;
        case TRICORE_INS_LDA: //A[c] = M(A[15] + zero_ext(4 * off4), word);
        case TRICORE_INS_LD_BUD: // D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
        case TRICORE_INS_MOVA: // A[a] = zero_ext(const4);
        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
        case TRICORE_INS_MTCR: // CR[const16] = D[a];
        case TRICORE_INS_MFCR: // D[c] = CR[const16];
        case TRICORE_INS_MOVU: // D[c] = zero_ext(const16);
            ct = eOpConv::ZEXT_TRUNC;
            break;
        case TRICORE_INS_LDA_PINC: // A[c] = M(A[b], word); A[b] = A[b] + 4;
        case TRICORE_INS_LDD: // D[c] = M(A[b], word); A[b] = A[b] + 4;
            ct = eOpConv::ZEXT_TRUNC;
            pinc = llvm::ConstantInt::get(getType(), 4);
        case TRICORE_INS_LD_HD_PINC: // D[c] = sign_ext(M(A[b], half-word)); A[b] = A[b] + 2;
            ct = eOpConv::ZEXT_TRUNC;
            pinc = llvm::ConstantInt::get(getType(), 2);
            break;
        case TRICORE_INS_MOVAA: //A[a] = A[b];
        case TRICORE_INS_MOVAD: //A[a] = D[b];
        case TRICORE_INS_MOVDA: //D[a] = A[b];
        case TRICORE_INS_MOVDD: //D[a] = D[b];
            break;
        default:
            assert(false);
    }

    op1 = loadOp(t->operands[1], irb);
    storeOp(t->operands[0], op1, irb, ct);

    if (pinc) {
        auto* add = irb.CreateAdd(op1, pinc);
        storeRegister(t->operands[1].reg, add, irb);
    }
}


void Capstone2LlvmIrTranslatorTricore::translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch(t->op2) {
        case 0x05: // EA = A[b]; E[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
        {
//             auto* pt = llvm::PointerType::get(llvm::IntegerType::getInt64Ty(_module->getContext()), 0);
//             auto* ld = irb.CreateLoad(irb.CreateIntToPtr(op0, pt)); //E[a] = M(EA, doubleword)
//             storeRegister(t->operands[2].reg, ld, irb, eOpConv::SEXT_TRUNC);

            t->operands[2].extended = true;

            op0 = loadOp(t->operands[0], irb, getType());
            storeOp(t->operands[2], op0, irb, eOpConv::SEXT_TRUNC);

            storeOp(t->operands[0], irb.CreateAdd(op0, op1), irb, eOpConv::SEXT_TRUNC); //EA + sign_ext(off10)
            break;
        }
        case 0x20: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, byte));
        {
            auto* ea = irb.CreateAdd(loadOp(t->operands[0], irb), loadOp(t->operands[1], irb));

            auto* pt = llvm::PointerType::get(llvm::IntegerType::getInt8Ty(_module->getContext()), 0);
            auto* ld = irb.CreateLoad(irb.CreateIntToPtr(ea, pt)); //D[a] = M(EA, doubleword)
            storeOp(t->operands[2], ld, irb, eOpConv::SEXT_TRUNC);
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateLdAbs(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (i->id) {
        case TRICORE_INS_LD:
            break;
        default:
            assert(false);
    }

    op1 = loadOp(t->operands[1], irb);
    storeOp(t->operands[0], op1, irb, eOpConv::NOTHING);
}

void Capstone2LlvmIrTranslatorTricore::translateShift(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = loadOp(t->operands[0], irb);
    op1 = loadOp(t->operands[1], irb);

    llvm::Value* o = nullptr;
    switch (i->id) {
        case TRICORE_INS_SHAD:
            o = irb.CreateShl(op0, op1);
            break;
        case TRICORE_INS_SHD: //shift_count = sign_ext(const4[3:0]); //D[a] = (shift_count >= 0) ? D[a] << shift_count : D[a] >> (-shift_count);
            if (t->operands[1].imm.value & 0b1000) { //TODO check sign_ext
                o = irb.CreateLShr(op0, op1); //TODO check -shift_count
            } else {
                o = irb.CreateShl(op0, op1);
            }
            break;
        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::ConstantInt* pinc = nullptr; //Post-increment Addressing Mode
    switch (i->id) {
        case TRICORE_INS_ST:    //EA = {off18[17:14], 14b'0, off18[13:0]};      M(EA, word) = A[a];
        case TRICORE_INS_STA:   //M(A[b], word) = A[a];
        case TRICORE_INS_STD:   //M(A[b], word) = D[a];
        case TRICORE_INS_STB:   //M(A[b], byte) = D[a][7:0];
        case TRICORE_INS_STWA: //EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
            break;
        case TRICORE_INS_STHW:  //M(A[b], half-word) = D[a][15:0];              A[b] = A[b] + 2;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 2);
            break;
        case TRICORE_INS_STW:    //M(A[b], word) = D[a];                        A[b] = A[b] + 4;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 4);
            break;
        default:
            assert(false);
    }

    op1 = loadOp(t->operands[1], irb);
    llvm::Type* ty = getIntegerTypeFromByteSize(t->operands[1].mem.size);
//     if (ty->isFloatingPointTy())
//     {
//             // This is not exact, in 64-bit mode, only lower 32-bits of FPR should
//             // be used -> truncate, not cast.
//             op0 = irb.CreateFPCast(op0, ty);
//     }
    if (ty->isIntegerTy()) {
        op1 = irb.CreateZExtOrTrunc(op1, ty);
    } else {
        assert(false && "unhandled type");
        return;
    }
    storeOp(t->operands[0], op1, irb);

    if (pinc) {
        op1 = loadRegister(t->operands[1].reg, irb);
        auto* add = irb.CreateAdd(op1, pinc);
        storeRegister(t->operands[1].reg, add, irb);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) { //TODO check ...
    op0 = loadOp(t->operands[0], irb);
    op2 = loadOp(t->operands[2], irb);
    llvm::Value* ea = nullptr;
    switch(t->op2) {
        case 0x14: // EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
        {
            ea = irb.CreateAdd(op0, loadOp(t->operands[1], irb)); //TODO check if use x86 loadOp(..., lea=true)
            irb.CreateStore(op2, irb.CreateLoad(ea));
            break;
        }
        case 0x05: // EA = A[b]; M(EA, doubleword) = E[a]; A[b] = EA + sign_ext(off10);
        {
            t->operands[1].extended = true;
            ea = op0;
            auto* pt = llvm::PointerType::get(llvm::IntegerType::getInt64Ty(_module->getContext()), 0);
            irb.CreateStore(op2, irb.CreateIntToPtr(ea, pt)); //M(EA, doubleword) = E[a]
            ea = irb.CreateAdd(ea, loadOp(t->operands[1], irb)); //EA + sign_ext(off10)
            break;
        }
        case 0x26: // EA = A[b] + sign_ext(off10); M(EA, word) = A[a];
        {
            ea = irb.CreateAdd(op0, loadOp(t->operands[1], irb)); //TODO check if use x86 loadOp(..., lea=true)
            auto* pt = llvm::PointerType::get(llvm::IntegerType::getInt32Ty(_module->getContext()), 0);
            irb.CreateStore(op2, irb.CreateIntToPtr(ea, pt)); //M(EA, word) = A[a]
            break;
        }
        default:
            assert(false);
    }

    storeOp(t->operands[0], ea, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateSub(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = loadOp(t->operands[0], irb);
    op1 = loadOp(t->operands[1], irb);

    llvm::Value* o = nullptr;
    switch (i->id) {
        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            o = irb.CreateSub(op0, op1);
            break;
        default:
            assert(false);
    }
    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateNop(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    // nothing
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperationsD(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = loadOp(t->operands[0], irb);
    op1 = loadOp(t->operands[1], irb);

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

    storeOp(t->operands[0], o, irb);
}


} // namespace capstone2llvmir
} // namespace retdec
