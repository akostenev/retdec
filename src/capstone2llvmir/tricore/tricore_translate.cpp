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


        case TRICORE_INS_ADDSCA: //A[c] = A[b] + (D[a] << n);
            switch (t->op2) {
                case 0x60:
                    op1 = loadOp(t->operands[1], irb);
                    op2 = loadOp(t->operands[2], irb);
                    add = irb.CreateAdd(op1, irb.CreateShl(op2, t->n));
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_ADDSCA16: //A[a] = (A[b] + (D[15] << n));
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            add = irb.CreateAdd(op1, irb.CreateShl(op2, t->n));
            break;

        case TRICORE_INS_CADD: //condition = D[d] != 0; result = ((condition) ? D[a] + sign_ext(const9) : D[a]); D[c] = result[31:0];
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            op3 = loadOp(t->operands[3], irb);
            switch (t->op2) {
                case 0x00:
                    add = irb.CreateSelect(irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0)), irb.CreateAdd(op1, op2), op1);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_MADD: //result = D[d] + (D[a] * sign_ext(const9)); D[c] = result[31:0];
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            op3 = loadOp(t->operands[3], irb);
            switch (t->op2) {
                case 0x01:
                    add = irb.CreateAdd(op3, irb.CreateMul(op1, op2));
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], add, irb, eOpConv::SECOND_SEXT);
}

void Capstone2LlvmIrTranslatorTricore::translateAnd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = loadOp(t->operands[0], irb);
    op1 = loadOp(t->operands[1], irb);

    llvm::Value* v = nullptr;
    switch (i->id) {
        case TRICORE_INS_ANDD15: //D[15] = D[15] & zero_ext(const8);
            v = irb.CreateAnd(op0, op1);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], v, irb, eOpConv::THROW);
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
                const9From5To0 = const9From5To0 - 32;
                auto* sh = llvm::ConstantInt::getSigned(getType(6), const9From5To0);
                o = irb.CreateLShr(op1, irb.CreateSExt(sh, op1->getType()));
            } else {
                auto* sh = llvm::ConstantInt::get(getType(6), const9From5To0);
                o = irb.CreateShl(op1, irb.CreateZExt(sh, op1->getType()));
            }
            break;
        }
        case 0x01:
        {
//             if (const9[5:0] >= 0) then {
//                 carry_out = const9[5:0] ? (D[a][31:32 - const9[5:0]] != 0) : 0;
//                 result = D[a] << const9[5:0];
//             } else {
//                 shift_count = 0 - const9[5:0];
//                 msk = D[a][31] ? (((1 << shift_count) - 1) << (32 - shift_count)) : 0;
//                 result = msk | (D[a] >> shift_count);
//                 carry_out = (D[a][shift_count - 1:0] != 0);
//             }
//             D[c] = result[31:0];

            uint64_t const9From5To0 = t->operands[2].imm.value & 0b111111;
            if (const9From5To0 >> 5 & 1) { //msb is set -> -const9[5:0]
                const9From5To0 = (const9From5To0 ^ 0b111111) + 1;

                auto* testBit31 = irb.CreateAnd(op1, 1 << 31);
                auto* op1Bit31Set = irb.CreateICmpUGT(testBit31, llvm::ConstantInt::get(op1->getType(), 0));

                auto bodyIrb = generateIfThenElse(op1Bit31Set, irb); //first if, second else

                auto* shl1 = bodyIrb.first.CreateShl(llvm::ConstantInt::get(getType(), 1), const9From5To0); //(1 << shift_count)
                shl1 = bodyIrb.first.CreateSub(shl1, llvm::ConstantInt::get(getType(), 1)); // - 1
                auto* mskIf = bodyIrb.first.CreateShl(shl1, 32 - const9From5To0);
                storeOp(t->operands[0], bodyIrb.first.CreateOr(mskIf, bodyIrb.first.CreateLShr(op1, const9From5To0)), bodyIrb.first, eOpConv::THROW);

                storeOp(t->operands[0], bodyIrb.second.CreateLShr(op1, const9From5To0), bodyIrb.second, eOpConv::THROW);
                //TODO Carry Flag
                return;
            } else {
                //TODO Carry Flag
                auto* sh = llvm::ConstantInt::get(getType(6), const9From5To0);
                o = irb.CreateShl(op1, irb.CreateZExt(sh, op1->getType()));
            }
            break;
        }
        case 0x08: // D[c] = D[a] & zero_ext(const9);
            o = irb.CreateAnd(op1, op2);
            break;

        case 0x0A: // D[c] = D[a] | zero_ext(const9);
            o = irb.CreateOr(op1, op2);
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

void Capstone2LlvmIrTranslatorTricore::translateCmp(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) { //TODO rename to translate8B ?
    op0 = loadOp(t->operands[0], irb);
    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);

    llvm::Value* v = nullptr;
    switch (i->id) {
        case TRICORE_INS_CMP:
            switch (t->op2) {
                case 0x03: //result = D[a] + sign_ext(const9); // unsigned addition D[c] = suov(result, 32);
                        //result = D[a] + D[b]; // unsigned addition D[c] = suov(result, 32); TODO RR format?
                    v = irb.CreateAdd(op1, op2);
                    break;

                case 0x10: //result = (D[a] == sign_ext(const9)); D[c] = zero_ext(result);
                {
                    llvm::Value* cond = irb.CreateICmpEQ(op1, op2);
                    v = irb.CreateSelect(cond, llvm::ConstantInt::get(op1->getType(), 1), llvm::ConstantInt::get(op1->getType(), 0));
                    break;
                }
                case 0x11: //result = (D[a] != sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpNE(op1, op2);
                    break;

                case 0x12: //result = (D[a] < sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpULT(op1, op2);
                    break;

                case 0x14: //result = (D[a] >= sign_ext(const9)); D[c] = zero_ext(result);
                        //result = (D[a] >= D[b]); D[c] = zero_ext(result); TODO GED with RR op_format???
                    v = irb.CreateICmpSGE(op1, op2);
                    break;

                case 0x20: //D[c] = {D[c][31:1], D[c][0] AND (D[a] == sign_ext(const9))};
                {
                    op0 = loadOp(t->operands[0], irb);
                    llvm::Value* cond = irb.CreateICmpEQ(op1, op2);
                    llvm::Value* lastBitInDc = irb.CreateICmpEQ(irb.CreateAnd(op0, 1), llvm::ConstantInt::get(op0->getType(), 1));
                    cond = irb.CreateAnd(cond, lastBitInDc);
                    lastBitInDc = irb.CreateSelect(cond, llvm::ConstantInt::get(op0->getType(), 1), llvm::ConstantInt::get(op0->getType(), 0));
                    v = irb.CreateAnd(op0, irb.CreateAnd(lastBitInDc, 0xFFFFFFFF));
                    break;
                }
                case 0x21: //D[c] = {D[c][31:1], D[c][0] AND (D[a] != sign_ext(const9))};
                {
                    op0 = loadOp(t->operands[0], irb);
                    llvm::Value* cond = irb.CreateICmpNE(op1, op2);
                    llvm::Value* lastBitInDc = irb.CreateICmpEQ(irb.CreateAnd(op0, 1), llvm::ConstantInt::get(op0->getType(), 1));
                    cond = irb.CreateAnd(cond, lastBitInDc);
                    lastBitInDc = irb.CreateSelect(cond, llvm::ConstantInt::get(op0->getType(), 1), llvm::ConstantInt::get(op0->getType(), 0));
                    v = irb.CreateAnd(op0, irb.CreateAnd(lastBitInDc, 0xFFFFFFFF));
                    break;
                }
                default:
                    assert(false);
            }
        case TRICORE_INS_EQ16: ////result = (D[a] == sign_ext(const4)); D[15] = zero_ext(result);
            v = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), llvm::ConstantInt::get(op0->getType(), 1), llvm::ConstantInt::get(op0->getType(), 0));
            break;

        case TRICORE_INS_CMOVN16: //D[a] = ((D[15] == 0) ? sign_ext(const4) : D[a]);
            v = irb.CreateSelect(irb.CreateICmpEQ(op1, llvm::ConstantInt::get(op1->getType(), 0)), op2, op0);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], v, irb, eOpConv::ZEXT_TRUNC);
}

void Capstone2LlvmIrTranslatorTricore::translateDiv(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {

    switch (i->id) {
        case TRICORE_INS_DIV:
            switch (t->op2) {
                case 0x0A: //E[c] = {00000000H , D[a]};
                    op0 = loadOp(t->operands[0], irb);
                    op1 = loadOp(t->operands[1], irb);
                    storeOp(t->operands[0], irb.CreateZExt(op1, op0->getType()), irb);
                    break;

                case 0x1A: //DVINITE E[c] = sign_ext(D[a]);
                    op1 = loadOp(t->operands[1], irb);
                    storeOp(t->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_DVSTEP:
            switch (t->op2) {
                case 0x03: //SUB.F
                    op1 = loadOp(t->operands[1], irb);
                    op2 = loadOp(t->operands[2], irb);
                    storeOp(t->operands[0], irb.CreateSub(op1, op2), irb);
                    break;

                case 0x0A: //IXMAX
                case 0x0D: //DVADJ
                    break;

                case 0x0E:
                case 0x0F:
                {
                    op1 = loadOp(t->operands[1], irb); //D[b]
                    op2 = loadOp(t->operands[2], irb); //E[d]
                    op1 = irb.CreateZExt(op1, op2->getType());

                    auto* div = irb.CreateUDiv(op2, op1);
                    div = irb.CreateTrunc(div, getType());
                    storeRegister(extendedRegToRegs(t->operands[0].reg).first, div, irb);

                    auto* rem = irb.CreateURem(op2, op1);
                    rem = irb.CreateTrunc(rem, getType());
                    storeRegister(extendedRegToRegs(t->operands[0].reg).second, rem, irb);

                    break;
                }

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateExtr(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = loadOp(t->operands[1], irb); //D[a]
    op3 = loadOp(t->operands[3], irb); //pos

    llvm::Value* extr = nullptr;
    eOpConv ct = eOpConv::THROW;
    switch (t->op2) {
        case 0x00:
        {
            //mask = (2^width -1) << pos;
            //D[c] = (D[a] & ~mask) | ((D[b] << pos) & mask);
            //If pos + width > 32, then the result is undefined.
            op2 = loadOp(t->operands[2], irb); //D[b]
            llvm::Value* mask = llvm::ConstantInt::get(getType(), ~(~0 << t->operands[4].imm.value));
            mask = irb.CreateShl(mask, op3);
            extr = irb.CreateOr(irb.CreateAnd(op1, irb.CreateNot(mask)), irb.CreateAnd(irb.CreateShl(op2, op3), mask));
            break;
        }
        case 0x2: //D[c] = sign_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
            extr = irb.CreateAnd(irb.CreateLShr(op1, op3), ~(~0 << t->operands[4].imm.value));
            ct = eOpConv::SEXT_TRUNC;
            break;

        case 0x3: //D[c] = zero_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
            extr = irb.CreateAnd(irb.CreateLShr(op1, op3), ~(~0 << t->operands[4].imm.value));
            ct = eOpConv::ZEXT_TRUNC;
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], extr, irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {

    switch (i->id) {
        case TRICORE_INS_J32: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_J16: //PC = PC + sign_ext(disp8) * 2;
            generateBranchFunctionCall(i, irb, loadOp(t->operands[0], irb));
            break;

        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
        {
            auto target = loadOp(t->operands[0], irb);
//             target = irb.CreateAnd(target, ~(~0 << 31) << 1);
            generateBranchFunctionCall(i, irb, target, false);
            break;
        }
        default:
            assert(false);
    }
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

        case TRICORE_INS_JLEZD: //If (D[b] <= 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpSLE(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JGEZD: //if (D[b] >= 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpSGE(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JNEQ32:
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);
            switch (t->op2) {
                case 0x01: // if (D[a] != D[b]) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpNE(op0, op1);
                    break;

                case 0x00: //if (D[a] == D[b]) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpEQ(op0, op1);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_JEQ32: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);
            op1 = irb.CreateSExtOrTrunc(op1, op0->getType());

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

        case TRICORE_INS_JNZ_D15: //if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JNZ16: //if (D[b] != 0) then PC = PC + zero_ext(disp4) * 2
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

        case TRICORE_INS_JZT_16: //if (!D[15][n]) then PC = PC + zero_ext(disp4) * 2;
            op0 = irb.CreateAnd(op0, 1 << t->n);
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JZD: //if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZA_16: //if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpEQ(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JNED15: //if (D[15] != sign_ext(const4)) then PC = PC + zero_ext(disp4) * 2;
            op1 = loadOp(t->operands[1], irb);
            cond = irb.CreateICmpNE(op0, op1);
            target = loadOp(t->operands[2], irb);
            break;

        case TRICORE_INS_JGTZ:
            cond = irb.CreateICmpSGT(op0, llvm::ConstantInt::get(op0->getType(), 0));
            target = loadOp(t->operands[1], irb);
            break;

        case TRICORE_INS_JGEDD: //if (D[a] >= D[b]) then PC = PC + sign_ext(disp15) * 2;
            op1 = loadOp(t->operands[1], irb);
            target = loadOp(t->operands[2], irb);
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpSGE(op0, op1);
                    break;

                case 0x01:
                    cond = irb.CreateICmpUGE(op0, op1);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_JGE_U_c:
            target = loadOp(t->operands[2], irb);
            op1 = loadOp(t->operands[1], irb);
            switch (t->op2) {
                case 0x00: //if (D[a] >= sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpSGE(op0, op1);
                    break;

                case 0x01: //if (D[a] >= zero_ext(const4)) then { // unsigned comparison PC = PC + sign_ext(disp15) * 2; }
                    cond = irb.CreateICmpUGE(op0, op1);;
                    break;

                default:
                    assert(false);
            }
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
        case TRICORE_INS_LDB: //EA = {off18[17:14], 14b'0, off18[13:0]}; D[a] = sign_ext(M(EA, byte));
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
        case TRICORE_INS_MOVD: // D[a] = sign_ext(const4);
        case TRICORE_INS_LDHW16_REL: //D[c] = sign_ext(M(A[15] + zero_ext(2 * off4), half-word));
        case TRICORE_INS_LDHW16: //D[c] = sign_ext(M(A[b], halfword));
            ct = eOpConv::SEXT_TRUNC;
            break;

        case TRICORE_INS_LDA: //A[c] = M(A[15] + zero_ext(4 * off4), word);
        case TRICORE_INS_LD_BUD15: // D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
        case TRICORE_INS_MOVA: // A[a] = zero_ext(const4);
        case TRICORE_INS_MTCR: // CR[const16] = D[a];
        case TRICORE_INS_MFCR: // D[c] = CR[const16];
        case TRICORE_INS_MOVU: // D[c] = zero_ext(const16);
        case TRICORE_INS_LD_BUD: // EA = A[b] + sign_ext(off16); D[a] = zero_ext(M(EA, byte));
        case TRICORE_INS_MOVD15: //D[15] = zero_ext(const8);
        case TRICORE_INS_LDB_REL: //D[c] = zero_ext(M(A[15] + zero_ext(off4), byte));
            ct = eOpConv::ZEXT_TRUNC;
            break;

        case TRICORE_INS_LDA_PINC: // A[c] = M(A[b], word); A[b] = A[b] + 4;
        case TRICORE_INS_LDD_PINC: // D[c] = M(A[b], word); A[b] = A[b] + 4;
            pinc = llvm::ConstantInt::get(getType(), 4);
            break;

        case TRICORE_INS_LD_HD_PINC: // D[c] = sign_ext(M(A[b], half-word)); A[b] = A[b] + 2;
            ct = eOpConv::SEXT_TRUNC;
            pinc = llvm::ConstantInt::get(getType(), 2);
            break;

        case TRICORE_INS_LDD: //D[c] = M(A[b], word);
        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
        case TRICORE_INS_LEA: // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
        case TRICORE_INS_LDW: //EA = A[b] + sign_ext(off16); D[a] = M(EA, word);
        case TRICORE_INS_MOVAA: //A[a] = A[b];
        case TRICORE_INS_MOVAD: //A[a] = D[b];
        case TRICORE_INS_MOVDA: //D[a] = A[b];
        case TRICORE_INS_MOVDD: //D[a] = D[b];
        case TRICORE_INS_LD16A: //A[c] = M(A[b], word);
        case TRICORE_INS_LD: // 3x op2
        case TRICORE_INS_LDW16: //D[c] = M(A[15] + zero_ext(4 * off4), word);
        case TRICORE_INS_LDA_OFF: //EA = A[b] + sign_ext(off16); A[a] = M(EA, word);
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

void Capstone2LlvmIrTranslatorTricore::translateConditionalLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (i->id) {
        case TRICORE_INS_CMOVD: //D[a] = ((D[15] != 0) ? D[b] : D[a]);
        {
            op1 = loadOp(t->operands[1], irb);
            auto* cond = irb.CreateICmpNE(loadRegister(TRICORE_REG_D_15, irb), llvm::ConstantInt::get(getType(), 0));
            auto irbIf = generateIfThen(cond, irb);
            storeOp(t->operands[0], op1, irbIf);
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch(t->op2) {
        case 0x05: // EA = A[b]; E[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
            op0 = loadOp(t->operands[0], irb); //A[b]
            op1 = loadOp(t->operands[1], irb); //M(EA, doubleword)
//             op2 = loadOp(t->operands[2], irb); //E[a]
            op3 = loadOp(t->operands[3], irb); //off10;

            storeOp(t->operands[2], op1, irb); // E[a] = M(EA, doubleword);
            storeOp(t->operands[0], irb.CreateAdd(op0, op3), irb); // A[b] = EA + sign_ext(off10);
            break;

        case 0x16: // EA = A[b] + sign_ext(off10); A[a] = M(EA, word); A[b] = EA;
        {
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb); ////A[a] = M(EA, word)

            auto lea = t->operands[1];
            lea.mem.lea = true;
            storeRegister(lea.mem.base, loadOp(lea, irb), irb); //A[b] = EA
            break;
        }
        case 0x20: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, byte));
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
            break;

        case 0x21: //EA = A[b] + sign_ext(off10); D[a] = zero_ext(M(EA, byte));
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb, eOpConv::ZEXT_TRUNC);
            break;

        case 0x22: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, halfword));
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
            break;

        case 0x25: //EA = A[b] + sign_ext(off10); E[a] = M(EA, doubleword);
            op1 = loadOp(t->operands[1], irb);
            storeOp(t->operands[0], op1, irb);
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateMul(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    llvm::Value* mul = nullptr;
    switch (i->id) {
        case TRICORE_INS_MULD:
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            switch (t->op2) {
                case 0x0A: //result = D[a] * D[b]; D[c] = result[31:0];
                case 0x88: //result = D[a] * D[b]; // unsigned D[c] = suov(result, 32);
                case 0x8A: //result = D[a] * D[b]; D[c] = ssov(result, 32);
                    mul = irb.CreateMul(op1, op2);
                    break;

                case 0x68: //result = D[a] * D[b]; // unsigned E[c] = result[63:0];
                    op1 = irb.CreateZExt(op1, op0->getType());
                    op2 = irb.CreateZExt(op2, op0->getType());
                    mul = irb.CreateMul(op1, op2);
                    break;

                case 0x6a: //result = D[a] * D[b]; E[c] = result[63:0];
                    op1 = irb.CreateSExt(op1, op0->getType());
                    op2 = irb.CreateSExt(op2, op0->getType());
                    mul = irb.CreateMul(op1, op2);
                    break;

                default:
                    assert(false && TRICORE_INS_MULD);
            }
            break;

        case TRICORE_INS_MULD2: // result = D[a] * D[b]; D[a] = result[31:0];
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            mul = irb.CreateMul(op0, op1);
            break;

        case TRICORE_INS_MULE: //result = D[a] * sign_ext(const9); E[c] = result[63:0];
            op0 = loadOp(t->operands[0], irb);
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            op1 = irb.CreateSExt(op1, op0->getType());
            op2 = irb.CreateSExt(op2, op0->getType());
            mul = irb.CreateMul(op1, op2);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], mul, irb, eOpConv::THROW);
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
        case TRICORE_INS_STB:   //M(A[b], byte) = D[a][7:0];
        case TRICORE_INS_STBA:  //M(A[15] + zero_ext(off4), byte) = D[a][7:0];
        case TRICORE_INS_ST_BA: //EA = A[b] + sign_ext(off16); M(EA, byte) = D[a][7:0];
        case TRICORE_INS_STD:   //M(A[b], word) = D[a];
        case TRICORE_INS_STWA:  //EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
        case TRICORE_INS_STD15: //M(A[10] + zero_ext(4 * const8), word) = D[15];
        case TRICORE_INS_STHW16: //M(A[b], half-word) = D[a][15:0];
        case TRICORE_INS_STB_ABS: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, byte) = D[a][7:0];
        case TRICORE_INS_STHW16_REL: //M(A[15] + zero_ext(2 * off4), half-word) = D[a][15:0];
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

        case TRICORE_INS_STHW16D15: //M(A[b] + zero_ext(2 * off4), half-word) = D[15][15:0];
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

void Capstone2LlvmIrTranslatorTricore::translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
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

        case 0x20: // EA = A[b] + sign_ext(off10); M(EA, byte) = D[a][7:0];
        case 0x25: // EA = A[b] + sign_ext(off10); M(EA, doubleword) = E[a];
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

    switch (i->id) {
        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            storeOp(t->operands[0], irb.CreateSub(op0, op1), irb);
            break;

        case TRICORE_INS_SUBD15: //result = D[a] - D[b]; D[15] = result[31:0];
            storeRegister(TRICORE_REG_D_15, irb.CreateSub(op0, op1), irb);
            break;

        case TRICORE_INS_SUBD1516: //result = D[15] - D[b]; D[a] = result[31:0];
            op2 = loadOp(t->operands[2], irb);
            storeOp(t->operands[0], irb.CreateSub(op1, op2), irb);
            break;

        default:
            assert(false);
    }
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

        case TRICORE_INS_FCALL:
        {
            storeOp(t->operands[0], loadOp(t->operands[1], irb), irb); //M(EA,word) = A[11];
            generateCallFunctionCall(i, irb, loadOp(t->operands[2], irb)); //PC = PC + sign_ext(2 * disp24);
            storeRegister(TRICORE_REG_A_11, getNextInsnAddress(i), irb); //A[11] = ret_addr[31:0]; ret_addr = PC + 4;

            t->operands[0].mem.lea = true;
            storeRegister(TRICORE_REG_A_10, loadOp(t->operands[0], irb), irb); //A[10] = EA[31:0];
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translate0B(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id = 0x0B);

    switch (t->op2) {
        case 0x00: //result = D[a] + D[b]; D[c] = result[31:0];
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            storeOp(t->operands[0], irb.CreateAdd(op1, op2), irb);
            break;

        case 0x08: //SUBD result = D[a] - D[b]; D[c] = result[31:0];
        case 0x0A: //result = D[a] - D[b]; D[c] = ssov(result, 32);
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            storeOp(t->operands[0], irb.CreateSub(op1, op2), irb);
            break;

        case 0x14: //result = (D[a] >= D[b]); D[c] = zero_ext(result);
        {
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            llvm::Value* cond = irb.CreateICmpSGE(op1, op2);
            llvm::Value* sel = irb.CreateSelect(cond, llvm::ConstantInt::get(op1->getType(), 1), llvm::ConstantInt::get(op1->getType(), 2));
            storeOp(t->operands[0], sel, irb, eOpConv::ZEXT_TRUNC);
            break;
        }
        case 0x18: //D[c] = (D[a] < D[b]) ? D[a] : D[b];
        {
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            auto* sle = irb.CreateICmpSLT(op1, op2);
            auto* val = irb.CreateSelect(sle, op1, op2);
            storeOp(t->operands[0], val, irb);
            break;
        }
        case 0x1A: //D[c] = (D[a] > D[b]) ? D[a] : D[b];
        {
            op1 = loadOp(t->operands[1], irb);
            op2 = loadOp(t->operands[2], irb);
            auto* sle = irb.CreateICmpSGT(op1, op2);
            auto* val = irb.CreateSelect(sle, op1, op2);
            storeOp(t->operands[0], val, irb);
            break;
        }
        case 0x7e: //sat_neg = (D[a] < -8000 H ) ? -8000 H : D[a]; D[c] = (sat_neg > 7FFF H ) ? 7FFF H : sat_neg;
        {
            op1 = loadOp(t->operands[1], irb);
            llvm::Value* cond = irb.CreateICmpSGE(op1, llvm::ConstantInt::get(op1->getType(), -0x8000, true));
            llvm::Value* sel = irb.CreateSelect(cond, op1, llvm::ConstantInt::get(op1->getType(), -0x8000, true));
            llvm::Value* cond2 = irb.CreateICmpSGT(sel, llvm::ConstantInt::get(sel->getType(), 0x7FFF));
            llvm::Value* sel2 = irb.CreateSelect(cond2, llvm::ConstantInt::get(sel->getType(), 0x7FFF), sel);
            storeOp(t->operands[0], sel2, irb);
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translate00(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    switch (t->op2) {
        case 0x00:
            break;

        case 0x09: //PC = {A[11] [31:1], 1’b0};
        {
            auto* ra = loadRegister(TRICORE_REG_RA, irb);
//             ra = irb.CreateAnd(ra, ~(~0 << 31) << 1);
            generateReturnFunctionCall(i, irb, ra, false);
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

void Capstone2LlvmIrTranslatorTricore::translateInsertBit(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_INST);

    op1 = loadOp(t->operands[1], irb);
    op2 = loadOp(t->operands[2], irb);
//     op3 = loadOp(t->operands[3], irb);
    op4 = loadOp(t->operands[4], irb);
    switch (t->op2) {
        case 0x00: //D[c] = {D[a][31:(pos1+1)], D[b][pos2], D[a][(pos1-1):0]};
        {
            auto* bitInPos2 = irb.CreateAnd(irb.CreateLShr(op2, op4), 1);
            op1 = irb.CreateAnd(op1, irb.CreateOr(irb.CreateShl(bitInPos2, op4), ~(~0 << t->operands[4].imm.value)));
            break;
        }
        case 0x01: //D[c] = {D[a][31:(pos1+1)], !D[b][pos2], D[a][(pos1-1):0]};
        {
            auto* bitInPos2 = irb.CreateNot(irb.CreateAnd(irb.CreateLShr(op2, op4), 1));
            op1 = irb.CreateAnd(op1, irb.CreateOr(irb.CreateShl(bitInPos2, op4), ~(~0 << t->operands[4].imm.value)));
            break;
        }
        default:
            assert(false);
    }

    storeOp(t->operands[0], op1, irb);
}

} // namespace capstone2llvmir
} // namespace retdec
