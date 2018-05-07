#include "retdec/capstone2llvmir/tricore/tricore.h"

#include "retdec/llvm-support/utils.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateAdd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::Value* add = nullptr;

    switch(i->id) {
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
        case TRICORE_INS_ADDIH_A: //A[c] = A[a] + {const16, 16’h0000};
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            add = irb.CreateAdd(op1, op2);
            break;
        case TRICORE_INS_ADDA: //A[a] = A[a] + sign_ext(const4);
        case TRICORE_INS_ADDD_c: //result = D[a] + sign_ext(const4); D[a] = result[31:0];
        case TRICORE_INS_ADDDD: //result = D[a] + D[b]; D[a] = result[31:0];
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
        {
            uint64_t const9From5To0 = t->operands[2].imm.value & 0b111111;

            if ((const9From5To0 >> 5) & 1) { //msb is set --> -const9[5:0]
                auto* sh = llvm::ConstantInt::getSigned(getType(6), const9From5To0);
                o = irb.CreateLShr(op1, irb.CreateSExt(sh, op1->getType()));
            } else {
                auto* sh = llvm::ConstantInt::get(getType(6), const9From5To0);
                o = irb.CreateShl(op1, irb.CreateZExt(sh, op1->getType()));
            }
            break;
        }
        case 0x0A: // D[c] = D[a] | zero_ext(const9);
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

    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);

    llvm::Value* o = nullptr;
    switch (t->op2) {
        case 0x08: // D[c] = D[a] & D[b];
            o = irb.CreateAnd(op1, op2);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateExtr(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = loadOp(t->operands[1], irb); //D[a]
    op2 = loadOp(t->operands[2], irb); //pos
    op3 = loadOp(t->operands[3], irb); //witdth

    switch (t->op2) {
        case 0x3: //D[c] = zero_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
        {
            auto* lshr = irb.CreateLShr(op1, op2); //(D[a] >> pos)
            auto* extr = irb.CreateAnd(lshr, ~(~0 << t->operands[3].imm.value));
            storeOp(t->operands[0], extr, irb);
            break;
        }
        default:
            assert(false);
    }

}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::Value* target = nullptr;
    bool relative = true;

    switch (i->id) {
        case TRICORE_INS_J32: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_J16: //PC = PC + sign_ext(disp8) * 2;
            target = loadOp(t->operands[0], irb);
            break;

        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
            target = loadOp(t->operands[0], irb);
            target = irb.CreateAnd(target, ~(~0 << 31) << 1);
            assert(target != nullptr);
            relative = false;
            break;

        default:
            assert(false);
    }

    generateBranchFunctionCall(i, irb, target, relative);
}

void Capstone2LlvmIrTranslatorTricore::translateJl(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb);

    op0 = loadOp(t->operands[0], irb);
    generateBranchFunctionCall(i, irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = loadOp(t->operands[0], irb);

    llvm::Value* cond = nullptr;
    llvm::Value* target = nullptr;
    switch (i->id) {
        case TRICORE_INS_LOOP: //if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
        {
            auto* sub = irb.CreateSub(op0, llvm::ConstantInt::get(op0->getType(), 1));
            storeRegister(t->operands[0].reg, sub, irb);

            cond = irb.CreateICmpNE(sub, llvm::ConstantInt::get(sub->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;
        }
        case TRICORE_INS_JEQA:
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

        case TRICORE_INS_JLTD:
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);
            switch (t->op2) {
                case 0x00: //Signed
                    cond = irb.CreateICmpSLT(op0, op1);
                    break;
                case 0x01: //Unsigned
                    cond = irb.CreateICmpULT(op0, op1);
                    break;
                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JEQ_15_c: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);

            op1 = irb.CreateSExtOrTrunc(op1, op0->getType());

            switch (t->op2) {
                case 0x01: // TRICORE_INS_JNE_c
                    cond = irb.CreateICmpNE(op0, op1);
                    break;
                case 0x00: // TRICORE_INS_JEQ_15_c
                    cond = irb.CreateICmpEQ(op0, op1);
                    break;
                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JNZ_D15: //if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
            target = loadOp(t->operands[1], irb);
            cond = irb.CreateICmpNE(op0, llvm::ConstantInt::get(op0->getType(), 0));
            break;

        case TRICORE_INS_JZ_D15: // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
            target = loadOp(t->operands[1], irb);
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
            break;

        case TRICORE_INS_JNZT: //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
            op0 = irb.CreateAnd(op0, 1 << t->n);
            if (t->op2) { // eq A[a][n] == 1
                cond = irb.CreateICmpNE(op0, llvm::ConstantInt::get(op0->getType(), 0));
            } else {
                cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
            }
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JZD: //if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZA_16: //if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        default:
            assert(false);
    }

    generateCondBranchFunctionCall(i, irb, cond, target);
}

void Capstone2LlvmIrTranslatorTricore::translateLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    eOpConv ct = eOpConv::THROW;
    llvm::Value* pinc = nullptr;
    op1 = loadOp(t->operands[1], irb);

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

    storeOp(t->operands[0], op1, irb, ct);

    if (pinc) {
        auto* regPinc = loadRegister(t->operands[1].reg, irb);
        auto* add = irb.CreateAdd(regPinc, pinc);
        storeRegister(t->operands[1].reg, add, irb);
    }
}


void Capstone2LlvmIrTranslatorTricore::translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch(t->op2) {
        case 0x05: // EA = A[b]; E[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
            op0 = loadOp(t->operands[0], irb); //A[b]
            op1 = loadOp(t->operands[1], irb); //M(EA, doubleword)
//             op2 = loadOp(t->operands[2], irb); //E[a]
            op3 = loadOp(t->operands[3], irb); //off10;

            storeOp(t->operands[2], op1, irb);
            storeOp(t->operands[0], irb.CreateAdd(op0, op3), irb);
            break;

        case 0x20: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, byte));
//             op0 = loadOp(t->operands[0], irb); //D[a]
            op1 = loadOp(t->operands[1], irb); //(M(EA, byte))
            storeOp(t->operands[0], op1, irb);
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateLdAbs(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (i->id) {
        case TRICORE_INS_LD:
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb, eOpConv::THROW);
            break;

        default:
            assert(false);
    }
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
        {
            uint64_t const4 = t->operands[1].imm.value;
            if ((const4 >> 3) & 1) { // msb is set --> -shift_count
                o = irb.CreateLShr(op0, irb.CreateSExt(llvm::ConstantInt::getSigned(getType(4), const4), op0->getType()));
            } else {
                o = irb.CreateShl(op0, op1);
            }
            break;
        }
        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::ConstantInt* pinc = nullptr; //Post-increment Addressing Mode
    eOpConv ec = eOpConv::THROW;

    switch (i->id) {
        case TRICORE_INS_ST:    //EA = {off18[17:14], 14b'0, off18[13:0]};      M(EA, word) = A[a];
        case TRICORE_INS_STA:   //M(A[b], word) = A[a];
        case TRICORE_INS_STD:   //M(A[b], word) = D[a];
        case TRICORE_INS_STB:   //M(A[b], byte) = D[a][7:0];
        case TRICORE_INS_STWA:  //EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
            ec = eOpConv::THROW;
            break;

        case TRICORE_INS_STHW:  //M(A[b], half-word) = D[a][15:0];              A[b] = A[b] + 2;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 2);
            ec = eOpConv::SEXT_TRUNC;
            break;

        case TRICORE_INS_STW:    //M(A[b], word) = D[a];                        A[b] = A[b] + 4;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 4);
            ec = eOpConv::THROW;
            break;

        default:
            assert(false);
    }

    op1 = loadOp(t->operands[1], irb);
    storeOp(t->operands[0], op1, irb, ec);

    if (pinc) {
        op0 = loadRegister(t->operands[0].reg, irb);
        auto* add = irb.CreateAdd(op0, pinc);
        storeRegister(t->operands[0].reg, add, irb);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) { //TODO check ...
    op0 = loadOp(t->operands[0], irb); //A[b]
//  op1 = loadOp(t->operands[1], irb); //M(EA, doubleword)
    op2 = loadOp(t->operands[2], irb); //E[a]
    op3 = loadOp(t->operands[3], irb); //off10

    llvm::Value* ea = nullptr;
    switch(t->op2) {
        case 0x05: // EA = A[b]; M(EA, doubleword) = E[a]; A[b] = EA + sign_ext(off10);
        case 0x14: // EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
            ea = op3;
            break;

        case 0x26: // EA = A[b] + sign_ext(off10); M(EA, word) = A[a];
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[1], op2, irb, eOpConv::THROW);
    if (ea) {
        storeOp(t->operands[0], irb.CreateAdd(op0, ea), irb, eOpConv::THROW);
    }
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

void Capstone2LlvmIrTranslatorTricore::translateCall(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (i->id) {
        case TRICORE_INS_CALL16:
        case TRICORE_INS_CALL32:
            storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
            op0 = loadOp(t->operands[0], irb);
            generateCallFunctionCall(i, irb, op0); //PC = PC + sign_ext(2 * disp24);
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translate00(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (t->op2) {
        case 0x00:
            break;

        case 0x09:
        {
//             auto* sp = loadRegister(TRICORE_REG_SP, irb);
//             auto* pt = llvm::PointerType::get(sp->getType(), 0);
//             auto* addr = irb.CreateIntToPtr(sp, pt);
//             auto* l = irb.CreateLoad(addr);
//             generateReturnFunctionCall(irb, loadRegister(TRICORE_REG_D_2, irb));
//             generateBranchFunctionCall(irb, loadRegister(TRICORE_REG_RA, irb));
            break;
        }

        case 0x0A:
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateIgnore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    //do nothing
    // e.g. TRICORE_INS_ISYNC;
}

} // namespace capstone2llvmir
} // namespace retdec
