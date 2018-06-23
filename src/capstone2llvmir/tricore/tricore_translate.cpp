#include "retdec/capstone2llvmir/tricore/tricore.h"

#include "retdec/llvm-support/utils.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateAdd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);
    op3 = ld<3>(t, irb);

    llvm::Value* add = nullptr;
    switch(i->id) {
        case TRICORE_INS_ADD16_D15_DD: //result = D[a] + D[b]; D[15] = result[31:0];
        case TRICORE_INS_ADD16_D15_c: //result = D[15] + sign_ext(const4); D[a] = result[31:0];
        case TRICORE_INS_ADD16: //result = D[15] + D[b]; D[a] = result[31:0];
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
        case TRICORE_INS_ADDIH_A: //A[c] = A[a] + {const16, 16’h0000};
        case TRICORE_INS_ADDIH_D: //result = D[a] + {const16, 16’h0000}; D[c] = result[31:0];
        case TRICORE_INS_ADD16_D15: //result = D[a] + sign_ext(const4); D[15] = result[31:0];
            add = irb.CreateAdd(op1, op2);
            break;

        case TRICORE_INS_ADDA: //A[a] = A[a] + sign_ext(const4);
        case TRICORE_INS_ADDD_c: //result = D[a] + sign_ext(const4); D[a] = result[31:0];
        case TRICORE_INS_ADDDD: //result = D[a] + D[b]; D[a] = result[31:0];
            add = irb.CreateAdd(ld<0>(t, irb), op1);
            break;

        case TRICORE_INS_ADDSCA: //A[c] = A[b] + (D[a] << n);
            switch (t->op2) {
                case 0x02: //A[c] = A[a] - A[b];
                    add = irb.CreateSub(op1, op2);
                    break;

                case 0x48: //D[c] = (A[a] == 0);
                    add = irb.CreateSelect(irb.CreateICmpEQ(op1, constInt<0>(op1)), constInt<1>(op1), constInt<0>(op1));
                    break;

                case 0x49:
                    add = irb.CreateSelect(irb.CreateICmpNE(op1, constInt<0>(op1)), constInt<1>(op1), constInt<0>(op1));
                    break;

                case 0x60: //A[c] = A[b] + (D[a] << n);
                    add = irb.CreateAdd(op1, irb.CreateShl(op2, t->n));
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_ADDSCA16: //A[a] = (A[b] + (D[15] << n));
            add = irb.CreateAdd(op1, irb.CreateShl(op2, t->n));
            break;

        case TRICORE_INS_CADD:
            switch (t->op2) {
                case 0x00: // condition = D[d] != 0; result = ((condition) ? D[a] + sign_ext(const9) : D[a]); D[c] = result[31:0];
                    add = irb.CreateSelect(irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0)), irb.CreateAdd(op1, op2), op1);
                    break;

                case 0x01: // condition = (D[d] == 0); result = ((condition) ? D[a] + sign_ext(const9) : D[a]); D[c] = result[31:0];
                    add = irb.CreateSelect(irb.CreateICmpEQ(op3, llvm::ConstantInt::get(op3->getType(), 0)), irb.CreateAdd(op1, op2), op1);
                    break;

                case 0x04: // D[c] = ((D[d] != 0) ? D[a] : sign_ext(const9));
                    add = irb.CreateSelect(irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0)), op1, op2);
                    break;

                case 0x05: // D[c] = ((D[d] == 0) ? D[a] : sign_ext(const9));
                    add = irb.CreateSelect(irb.CreateICmpEQ(op3, llvm::ConstantInt::get(op3->getType(), 0)), op1, op2);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_CADD16:
        {
            op0 = ld<0>(t, irb);
            add = irb.CreateSelect(irb.CreateICmpNE(op1, constInt<0>(op1)), irb.CreateAdd(op0, op2), op0);
            break;
        }
        case TRICORE_INS_MADD: //result = D[d] + (D[a] * sign_ext(const9)); D[c] = result[31:0];
            switch (t->op2) {
                case 0x01:
                    add = irb.CreateAdd(op3, irb.CreateMul(op1, op2));
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_MADD_RRR2: //result = D[d] + (D[a] * D[b]); D[c] = result[31:0];
            switch (t->op2) {
                case 0x0A:
                    add = irb.CreateAdd(op3, irb.CreateMul(op1, op2));
                    break;

                case 0x6A:
                    op1 = irb.CreateSExt(op1, op3->getType());
                    op2 = irb.CreateSExt(op2, op3->getType());
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

void Capstone2LlvmIrTranslatorTricore::translateBitOperations(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    llvm::Value* v = nullptr;
    switch (i->id) {
        case TRICORE_INS_ANDD: //D[a] = D[a] & D[b];
        case TRICORE_INS_ANDD15: //D[15] = D[15] & zero_ext(const8);
            v = irb.CreateAnd(op0, op1);
            break;

        case TRICORE_INS_NAND:
        {
            auto* bitPos1 = irb.CreateAnd(irb.CreateLShr(op1, t->operands[3].imm.value), 1);
            auto* bitPos2 = irb.CreateAnd(irb.CreateLShr(op2, t->operands[4].imm.value), 1);
            switch (t->op2) {
                case 0x00: // result = !(D[a][pos1] AND D[b][pos2]); D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateNot(irb.CreateICmpNE(irb.CreateAnd(bitPos1, bitPos2), constInt<0>(op1)));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x01: // result = D[a][pos1] OR !D[b][pos2]; D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(bitPos1, irb.CreateNot(bitPos2)), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x02: //result = !(D[a][pos1] XOR D[b][pos2]); D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpEQ(irb.CreateXor(bitPos1, bitPos2), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x03: //result = D[a][pos1] XOR D[b][pos2]; D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpNE(irb.CreateXor(bitPos1, bitPos2), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                default:
                    assert(false);
            }
            break;
        }
        case TRICORE_INS_NAND_NOR:
        {
            auto* bitPos1 = irb.CreateAnd(irb.CreateLShr(op1, t->operands[3].imm.value), 1);
            auto* bitPos2 = irb.CreateAnd(irb.CreateLShr(op2, t->operands[4].imm.value), 1);
            switch (t->op2) {
                case 0x00: //result = D[a][pos1] AND D[b][pos2]; D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpNE(irb.CreateAnd(bitPos1, bitPos2), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x01: //result = D[a][pos1] OR D[b][pos2]; D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(bitPos1, bitPos2), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x02: //result = !(D[a][pos1] OR D[b][pos2]); D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpEQ(irb.CreateOr(bitPos1, bitPos2), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                case 0x03: //result = D[a][pos1] AND !D[b][pos2]; D[c] = zero_ext(result);
                {
                    auto* cond = irb.CreateICmpNE(irb.CreateAnd(bitPos1, irb.CreateNot(bitPos2)), constInt<0>(op1));
                    v = irb.CreateZExt(irb.CreateSelect(cond, constInt<1>(op0), constInt<0>(op0)), op0->getType());
                    break;
                }
                default:
                    assert(false);
            }
            break;
        }
        case TRICORE_INS_ORD: //D[a] = D[a] | D[b];
        case TRICORE_INS_OR16_D15: //D[15] = D[15] | zero_ext(const8);
            v = irb.CreateOr(op0, op1);
            break;

        case TRICORE_INS_NOT16:
            v = irb.CreateNot(op0);
            break;

        case TRICORE_INS_EQ16_D15: //result = (D[a] == D[b]); D[15] = zero_ext(result);
            v = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
            break;

        case TRICORE_INS_XOR16: //D[a] = D[a] ^ D[b];
            v = irb.CreateXor(op0, op1);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], v, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations1(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_BIT_OPERATIONS1);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

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
                auto* op1Bit31Set = irb.CreateICmpUGT(testBit31, constInt<0>(op1));

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

        case 0x0B: //D[c] = ~(D[a] | zero_ext(const9));
            o = irb.CreateNot(irb.CreateOr(op1, op2));
            break;

        case 0x0C: // D[c] = D[a] ^ zero_ext(const9);
            o = irb.CreateXor(op1, op2);
            break;

        case 0x0D: //D[c] = ~(D[a] ^ zero_ext(const9));
            o = irb.CreateNot(irb.CreateXor(op1, op2));
            break;

        case 0x0E: //D[c] = D[a] & ~zero_ext(const9);
            o = irb.CreateAnd(op1, irb.CreateNot(op2));
            break;

        case 0x0F: //D[c] = D[a] | ~zero_ext(const9);
            o = irb.CreateOr(op1, irb.CreateNot(op2));
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateBitOperations2(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_BIT_OPERATIONS2);

    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    llvm::Value* o = nullptr;
    switch (t->op2) {
        case 0x00:
        case 0x01:
        {
            /* TODO flaggs
             * if (D[b][5:0] >= 0) then {
                carry_out = D[b][5:0] ? (D[a][31:32 - D[b][5:0]] != 0) : 0;
                result = D[a] << D[b][5:0];
               } else {
                shift_count = 0 - D[b][5:0];
                msk = D[a][31] ? (((1 << shift_count) - 1) << (32 - shift_count)) : 0;
                result = msk | (D[a] >> shift_count);
                carry_out = (D[a][shift_count - 1:0] != 0);
               }
               D[c] = result[31:0];
             */
            auto* first6Bits = irb.CreateAnd(op2, 0b111111);
            auto* cond = irb.CreateICmpUGE(first6Bits, constInt<0>(op2));
            auto* shift_count = irb.CreateNeg(first6Bits);
            auto* condFirstBitIsSet = irb.CreateICmpEQ(irb.CreateLShr(op1, 31), constInt<1>(op1));
            auto* msk = irb.CreateSelect(condFirstBitIsSet,
                                         irb.CreateShl(
                                            irb.CreateSub(irb.CreateShl(constInt<1>(op1), shift_count), constInt<1>(op1)),
                                            irb.CreateSub(constInt<32>(op1), shift_count)
                                        ),
                                        constInt<0>(op1)
            );
            o = irb.CreateSelect(cond, irb.CreateShl(op1, first6Bits), irb.CreateOr(msk, irb.CreateLShr(op1, shift_count)));
            break;
        }
        case 0x08: // D[c] = D[a] & D[b];
            o = irb.CreateAnd(op1, op2);
            break;

        case 0x09: //D[c] = ~(D[a] & D[b]);
            o = irb.CreateNot(irb.CreateAnd(op1, op2));
            break;

        case 0x0A: //D[c] = D[a] | D[b];
            o = irb.CreateOr(op1, op2);
            break;

        case 0x0B: //D[c] = ~(D[a] | D[b]);
            o = irb.CreateNot(irb.CreateOr(op1, op2));
            break;

        case 0x0C: //D[c] = D[a] ^ D[b];
            o = irb.CreateXor(op1, op2);
            break;

        case 0x0D: //D[c] = ~(D[a] ^ D[b]);
            o = irb.CreateNot(irb.CreateXor(op1, op2));
            break;

        case 0x0E: //D[c] = D[a] & ~D[b];
            o = irb.CreateAnd(op1, irb.CreateNot(op2));
            break;

        case 0x0F: //D[c] = D[a] | ~D[b];
            o = irb.CreateOr(op1, irb.CreateNot(op2));
            break;

        case 0x1B: //result = leading_zeros(D[a]); D[c] = zero_ext(result);
            //***UNIMPLEMENTED
            return;

        default:
            assert(false);
    }

    storeOp(t->operands[0], o, irb);
}

void Capstone2LlvmIrTranslatorTricore::translate8B(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    llvm::Value* v = nullptr;
    switch (i->id) {
        case TRICORE_INS_CMP:
            switch (t->op2) {
                case 0x00: //result = D[a] + sign_ext(const9); D[c] = result[31:0];
                case 0x02: //result = D[a] + sign_ext(const9); D[c] = ssov(result, 32);
                case 0x03: //result = D[a] + sign_ext(const9); // unsigned addition D[c] = suov(result, 32);
                case 0x04: //result = D[a] + sign_ext(const9); D[c] = result[31:0]; carry_out = carry(D[a],sign_ext(const9),0); //TODO Flag
                case 0x05: //result = D[a] + sign_ext(const9) + PSW.C; D[c] = result[31:0]; carry_out = carry(D[a],sign_ext(const9),PSW.C); //TODO Flag
                    v = irb.CreateAdd(op1, op2);
                    break;

                case 0x08: //result = sign_ext(const9) - D[a]; D[c] = result[31:0];
                    v = irb.CreateSub(op2, op1);
                    break;

                case 0x0E: //result = (D[a] > sign_ext(const9)) ? D[a] - sign_ext(const9) : sign_ext(const9) - D[a];  D[c] = result[31:0];
                case 0x0F: //result = (D[a] > sign_ext(const9)) ? D[a] - sign_ext(const9) : sign_ext(const9) - D[a]; D[c] = ssov(result, 32);
                    v = irb.CreateSelect(irb.CreateICmpSGT(op1, op2), irb.CreateSub(op1, op2), irb.CreateSub(op2, op1));
                    break;

                case 0x10: //result = (D[a] == sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpEQ(op1, op2);
                    break;

                case 0x11: //result = (D[a] != sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpNE(op1, op2);
                    break;

                case 0x12: //result = (D[a] < sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpSLT(op1, op2);
                    break;

                case 0x13: //result = (D[a] < zero_ext(const9)); // unsigned D[c] = zero_ext(result);
                    v = irb.CreateICmpULT(op1, op2);

                case 0x14: //result = (D[a] >= sign_ext(const9)); D[c] = zero_ext(result);
                    v = irb.CreateICmpSGE(op1, op2);
                    break;

                case 0x15: //result = (D[a] >= zero_ext(const9)); // unsigned D[c] = zero_ext(result);
                    v = irb.CreateICmpUGE(op1, op2);
                    break;

                case 0x20: //D[c] = {D[c][31:1], D[c][0] AND (D[a] == sign_ext(const9))};
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    llvm::Value* lastBitInDc = irb.CreateAnd(op0, 1);
                    llvm::Value* eqBit = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    llvm::Value* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, eqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x21: //D[c] = {D[c][31:1], D[c][0] AND (D[a] != sign_ext(const9))};
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpNE(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x23: //D[c] = {D[c][31:1], D[c][0] AND (D[a] < zero_ext(const9))}; // unsigned
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpULT(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x27: //D[c] = {D[c][31:1], D[c][0] OR (D[a] == sign_ext(const9))};
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x2A: //D[c] = {D[c][31:1], D[c][0] OR (D[a] < zero_ext(const9))}; // unsigned
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpSLT(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x2B: //D[c] = {D[c][31:1], D[c][0] OR (D[a] >= sign_ext(const9))};
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpSGE(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                case 0x2C: //D[c] = {D[c][31:1], D[c][0] OR (D[a] >= zero_ext(const9))}; // unsigned
                {
                    op0 = ld<0>(t, irb);
                    llvm::Value* vTrue = irb.CreateOr(op0, 1);
                    llvm::Value* vFalse = irb.CreateAnd(op0, ~(~0 << 30) << 1);

                    auto* lastBitInDc = irb.CreateAnd(op0, 1);
                    auto* neqBit = irb.CreateSelect(irb.CreateICmpUGE(op1, op2), constInt<1>(op0), constInt<0>(op0));
                    auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, neqBit), constInt<0>(op0));
                    v = irb.CreateSelect(cond, vTrue, vFalse);
                    break;
                }
                default:
                    assert(false);
            }
        case TRICORE_INS_EQ16: ////result = (D[a] == sign_ext(const4)); D[15] = zero_ext(result);
            v = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
            break;

        case TRICORE_INS_CMOVN16: //D[a] = ((D[15] == 0) ? sign_ext(const4) : D[a]);
            v = irb.CreateSelect(irb.CreateICmpEQ(op1, constInt<0>(op1)), op2, op0);
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], v, irb, eOpConv::ZEXT_TRUNC);
}

void Capstone2LlvmIrTranslatorTricore::translateDiv(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    switch (i->id) {
        case TRICORE_INS_DIV:
            switch (t->op2) {
                case 0x0A: //E[c] = {00000000H , D[a]};
                    storeOp(t->operands[0], irb.CreateZExt(op1, op0->getType()), irb);
                    break;

                case 0x1A: //DVINITE E[c] = sign_ext(D[a]);
                    storeOp(t->operands[0], op1, irb, eOpConv::SEXT_TRUNC);
                    break;

                case 0x4A: //E[c][63:24] = zero_ext(D[a]); E[c][23:0] = 0;
                    op1 = irb.CreateZExt(op1, op0->getType());
                    op1 = irb.CreateShl(op1, 24);
                    storeOp(t->operands[0], op1, irb);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_DVSTEP:
            switch (t->op2) {
                case 0x03: //SUB.F
                    storeOp(t->operands[0], irb.CreateSub(op1, op2), irb);
                    break;

                case 0x0A: //IXMAX
                case 0x0D: //DVADJ
                    break;

                case 0x0E:
                case 0x0F:
                {
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
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);
    op3 = ld<3>(t, irb);

    llvm::Value* extr = nullptr;
    eOpConv ct = eOpConv::THROW;
    switch (i->id) {
        case TRICORE_INS_EXTR:
            switch (t->op2) {
                case 0x00:
                {
                    //mask = (2^width -1) << pos;
                    //D[c] = (D[a] & ~mask) | ((D[b] << pos) & mask);
                    //If pos + width > 32, then the result is undefined.
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
            break;

        case TRICORE_INS_EXTR_INSR:
        {
            auto* width = irb.CreateAnd(irb.CreateLShr(op3, 32), 0b11111);
            auto* first5BitOfEd = irb.CreateAnd(op3, 0b11111);

            switch (t->op2) {
                case 0x00:
                {
                    /**
                     *  width = E[d][36:32];
                        mask = (2^width -1) << E[d][4:0];
                        D[c] = (D[a] & ~mask) | ((D[b] << E[d][4:0]) & mask);
                        If E[d][4:0] + E[d][36:32] > 32, then the result is undefined.
                     */
                    auto* mask = irb.CreateShl(irb.CreateNot(irb.CreateShl(irb.CreateNot(constInt<0>(op1)), width)), first5BitOfEd);
                    extr = irb.CreateOr(irb.CreateAnd(op1, irb.CreateNot(mask)), irb.CreateAnd(irb.CreateShl(op2, first5BitOfEd), mask));
                    break;
                }
                case 0x02:
                {
                    /**
                    *   width = E[d][36:32];
                        D[c] = sign_ext((D[a] >> E[d][4:0])[width-1:0]);
                        If E[d][4:0] + width > 32 or if width = 0, then the results are undefined.
                     */
                    extr = irb.CreateSExt(
                            irb.CreateAnd(irb.
                                CreateLShr(op3, first5BitOfEd),
                                irb.CreateNot(irb.CreateShl(irb.CreateNot(constInt<0>(op3)), irb.CreateSub(width, constInt<1>(width))))
                            ),
                            op1->getType()
                        );
                    break;
                }
                case 0x03:
                    /**
                     *  width = E[d][36:32];
                     *  D[c] = zero_ext((D[a] >> E[d][4:0])[width-1:0]);
                        If E[d][4:0] + width > 32 or if width = 0, then the results are undefined.
                     */
                   extr = irb.CreateZExt(
                            irb.CreateAnd(irb.
                                CreateLShr(op3, first5BitOfEd),
                                irb.CreateNot(irb.CreateShl(irb.CreateNot(constInt<0>(op3)), irb.CreateSub(width, constInt<1>(width))))
                            ),
                            op1->getType()
                        );
                    break;

                case 0x04: //D[c] = ({D[a], D[b]} << D[d][4:0])[63:32]; If D[d] > 31 the result is undefined.
                {
                    llvm::Value* comb = llvm::ConstantInt::get(getType(64), 0);
                    comb = irb.CreateOr(comb, irb.CreateShl(irb.CreateZExt(op1, comb->getType()), 32));
                    comb = irb.CreateOr(comb, irb.CreateZExt(op2, comb->getType()));
                    extr = irb.CreateTrunc(irb.CreateAnd(irb.CreateLShr(irb.CreateShl(comb, irb.CreateZExt(first5BitOfEd, comb->getType())), 32), 0xFFFFFFFF), op1->getType());
                    break;
                }
                default:
                    assert(false);
            }
            break;
        }
        default:
            assert(false);
    }

    storeOp(t->operands[0], extr, irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateInsertImask(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_INSERT_IMASK);
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    switch (t->op2) {
        case 0x00: //Insert
        {
            //mask = (2^width -1) << pos;
            //D[c] = (D[a] & ~mask) | ((zero_ext(const4) << pos) & mask);
            //If pos + width > 32, then the result is undefined.
            auto* mask = llvm::ConstantInt::get(op1->getType(), ~(~0 << t->operands[3].imm.value) << t->operands[4].imm.value);
            auto* value = irb.CreateOr(irb.CreateAnd(op1, irb.CreateNot(mask)), irb.CreateAnd(irb.CreateShl(op2, t->operands[4].imm.value), mask));
            storeOp(t->operands[0], value, irb);
            break;
        }
        case 0x01: //Imask
        {
            //E[c][63:32] = ((2^width -1) << pos);
            //E[c][31:0] = (zero_ext(const4) << pos);
            //If pos + width > 32 the result is undefined.
            auto* mask = llvm::ConstantInt::get(op0->getType(), ~(~0 << t->operands[2].imm.value) << t->operands[3].imm.value);
            auto* value = irb.CreateZExt(irb.CreateShl(op1, t->operands[3].imm.value), op0->getType());
            storeOp(t->operands[0], irb.CreateOr(irb.CreateShl(mask, 32), value), irb);
            break;
        }
        default:
            assert(false && "Unknown op2");
    }
}

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);

    switch (i->id) {
        case TRICORE_INS_J32: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_J16: //PC = PC + sign_ext(disp8) * 2;
            generateBranchFunctionCall(i, irb, op0);
            break;

        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
//             generateBranchFunctionCall(i, irb, irb.CreateAnd(op0, 0xFFFFFFFE), false);
            generateBranchFunctionCall(i, irb, op0, false);
            break;

        case TRICORE_INS_JA: ///PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};
            generateBranchFunctionCall(i, irb, op0, false);
            break;

        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateJl(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb);
    generateBranchFunctionCall(i, irb, ld<0>(t, irb));
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    llvm::Value* cond = nullptr;
    llvm::Value* target = op0;
    switch (i->id) {
        case TRICORE_INS_JNZ_D15: //if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JNZ16: //if (D[b] != 0) then PC = PC + zero_ext(disp4) * 2
            cond = irb.CreateICmpNE(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JZD: //if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZA_16: //if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZ_D15: // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
            cond = irb.CreateICmpEQ(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JLEZD: //If (D[b] <= 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpSLE(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JLTZ16: //if (D[b] < 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpSLT(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JGEZD: //if (D[b] >= 0) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpSGE(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JNE16_D15: //if (D[15] != sign_ext(const4)) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JNE_16_z_r: //if (D[15] != D[b]) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpNE(op1, op2);
            break;

        case TRICORE_INS_JEQ16_D15: //if (D[15] != sign_ext(const4)) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JEQ16: //if (D[15] == D[b]) then PC = PC + zero_ext(disp4) * 2;
            cond = irb.CreateICmpEQ(op1, op2);
            break;

        case TRICORE_INS_JGTZ:
            cond = irb.CreateICmpSGT(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_LOOP16: //if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
        {
            auto* sub = irb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1));
            storeRegister(t->operands[1].reg, sub, irb);
            cond = irb.CreateICmpNE(sub, llvm::ConstantInt::get(sub->getType(), 0));
            break;
        }
        case TRICORE_INS_JZ:
            switch (t->op2) {
                case 0x00: //if (A[a] == 0) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpEQ(op1, constInt<0>(op1));
                    break;

                case 0x01: //if (A[a] != 0) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpNE(op1, constInt<0>(op1));
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_JEQA:
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpEQ(op1, op2);
                    break;

                case 0x01:
                    cond = irb.CreateICmpNE(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JLTD:
            switch (t->op2) {
                case 0x00: //Signed
                    cond = irb.CreateICmpSLT(op1, op2);
                    break;

                case 0x01: //Unsigned
                    cond = irb.CreateICmpULT(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JNEQ32:
            switch (t->op2) {
                case 0x00: //if (D[a] == D[b]) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpEQ(op1, op2);
                    break;

                case 0x01: // if (D[a] != D[b]) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpNE(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JEQ32: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            op2 = irb.CreateSExtOrTrunc(op2, op1->getType());
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpEQ(op1, op2);
                    break;

                case 0x01:
                    cond = irb.CreateICmpNE(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JNZT: //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
            op1 = irb.CreateAnd(op1, 1 << t->n);
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpEQ(op1, constInt<0>(op1));
                    break;

                case 0x01:
                    cond = irb.CreateICmpNE(op1, constInt<0>(op1));
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JZT_16: //if (!D[15][n]) then PC = PC + zero_ext(disp4) * 2;
            op1 = irb.CreateAnd(op1, 1 << t->n);
            cond = irb.CreateICmpEQ(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JNZT_16: // if (D[15][n]) then PC = PC + zero_ext(disp4) * 2;
            op1 = irb.CreateAnd(op1, 1 << t->n);
            cond = irb.CreateICmpNE(op1, constInt<0>(op1));
            break;

        case TRICORE_INS_JGEDD: //if (D[a] >= D[b]) then PC = PC + sign_ext(disp15) * 2;
            switch (t->op2) {
                case 0x00:
                    cond = irb.CreateICmpSGE(op1, op2);
                    break;
                case 0x01:
                    cond = irb.CreateICmpUGE(op1, op2);
                    break;
                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JGE:
            switch (t->op2) {
                case 0x00: //if (D[a] >= sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpSGE(op1, op2);
                    break;

                case 0x01: //if (D[a] >= zero_ext(const4)) then { // unsigned comparison PC = PC + sign_ext(disp15) * 2; }
                    cond = irb.CreateICmpUGE(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JLT:
            switch (t->op2) {
                case 0x00: //if (D[a] < sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    cond = irb.CreateICmpSLT(op1, op2);
                    break;

                case 0x01: //if (D[a] < zero_ext(const4)) then { // unsigned comparison PC = PC + sign_ext(disp15) * 2; }
                    cond = irb.CreateICmpULT(op1, op2);
                    break;

                default:
                    assert(false && "Unknown op2");
            }
            break;

        case TRICORE_INS_JNE_INC_DEC:
            switch (t->op2) {
                case 0x00: //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; D[a] = D[a] + 1; The increment is unconditional.
                    cond = irb.CreateICmpNE(op1, op2);
                    storeOp(t->operands[1], irb.CreateAdd(op1, llvm::ConstantInt::get(op1->getType(), 1)), irb);
                    break;

                case 0x01: //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; D[a] = D[a] - 1; The decrement is unconditional.
                    cond = irb.CreateICmpNE(op1, op2);
                    storeOp(t->operands[1], irb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1)), irb);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_LOOP: //if (A[b] != 0) then PC = PC + sign_ext(2 * disp15); A[b] = A[b] - 1;
            switch (t->op2) {
                case 0x00: //if (A[b] != 0) then PC = PC + sign_ext(2 * disp15); A[b] = A[b] - 1;
                    cond = irb.CreateICmpNE(op1, constInt<0>(op1));
                    storeOp(t->operands[1], irb.CreateSelect(cond, irb.CreateSub(op1, llvm::ConstantInt::get(op1->getType(), 1)), op1), irb);
                    break;

                case 0x01:
                    generateBranchFunctionCall(i, irb, target);
                    return;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }

    assert(cond != nullptr);
    assert(target != nullptr);
    generateCondBranchFunctionCall(i, irb, cond, target);
}

void Capstone2LlvmIrTranslatorTricore::translateLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = ld<1>(t, irb);

    eOpConv ct = eOpConv::THROW;
    switch (t->operands[1].mem.ext) {
        case TRICORE_EXT_SEXT_TRUNC:
            ct = eOpConv::SEXT_TRUNC;
            break;

        case TRICORE_EXT_ZEXT_TRUNC:
            ct = eOpConv::ZEXT_TRUNC;
            break;

        default:
            break;
    }
    llvm::Value* pinc = nullptr;
    switch (i->id) {
        case TRICORE_INS_LDB_PINC: //D[c] = zero_ext(M(A[b], byte)); A[b] = A[b] + 1;
            pinc = llvm::ConstantInt::get(getType(), 1);
            break;

        case TRICORE_INS_LD_HD_PINC: // D[c] = sign_ext(M(A[b], half-word)); A[b] = A[b] + 2;
            pinc = llvm::ConstantInt::get(getType(), 2);
            break;

        case TRICORE_INS_LDA_PINC: // A[c] = M(A[b], word); A[b] = A[b] + 4;
        case TRICORE_INS_LDD_PINC: // D[c] = M(A[b], word); A[b] = A[b] + 4;
            pinc = llvm::ConstantInt::get(getType(), 4);
            break;

        default:
            break;
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
            auto* cond = irb.CreateICmpNE(loadRegister(TRICORE_REG_D_15, irb), llvm::ConstantInt::get(getType(), 0));
            auto irbIf = generateIfThen(cond, irb);
            storeOp(t->operands[0], ld<1>(t, irb), irbIf);
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_LD09);

    eOpConv ct = eOpConv::THROW;
    switch (t->operands[1].mem.ext) {
        case TRICORE_EXT_SEXT_TRUNC:
            ct = eOpConv::SEXT_TRUNC;
            break;

        case TRICORE_EXT_ZEXT_TRUNC:
            ct = eOpConv::ZEXT_TRUNC;
            break;

        default:
            break;
    }

    storeOp(t->operands[0], ld<1>(t, irb), irb, ct);
}

void Capstone2LlvmIrTranslatorTricore::translateMul(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    llvm::Value* mul = nullptr;
    switch (i->id) {
        case TRICORE_INS_MULD:
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
            mul = irb.CreateMul(op0, op1);
            break;

        case TRICORE_INS_MULE: //result = D[a] * sign_ext(const9); E[c] = result[63:0];
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
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);

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
    llvm::ConstantInt* pinc = nullptr;
    switch (i->id) {
        case TRICORE_INS_STB_PINC: //M(A[b], byte) = D[a][7:0]; A[b] = A[b] + 1;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 1);
            break;

        case TRICORE_INS_STHW:  //M(A[b], half-word) = D[a][15:0]; A[b] = A[b] + 2;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 2);
            break;

        case TRICORE_INS_ST_PINC:    //M(A[b], word) = D[a]; A[b] = A[b] + 4;
            pinc = llvm::ConstantInt::get(irb.getInt32Ty(), 4);
            break;

        case TRICORE_INS_ST_BIT: //EA = {off18[17:14], 14’b0, off18[13:0]}; M(EA, byte) = (M(EA, byte) AND ~(1 << bpos3)) | (b << bpos3);
        {
            op0 = ld<0>(t, irb);
            auto b = t->operands[1].imm.value;
            auto bpos3 = t->operands[2].imm.value;
            storeOp(t->operands[0], irb.CreateOr(irb.CreateAnd(op0, ~(1 << bpos3)), b << bpos3), irb);
            return;
        }
        default:
            break;
    }

    storeOp(t->operands[0], ld<1>(t, irb), irb);

    if (pinc) {
        op0 = loadRegister(t->operands[0].reg, irb);
        auto* add = irb.CreateAdd(op0, pinc);
        storeRegister(t->operands[0].reg, add, irb);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id == TRICORE_INS_ST89);
    storeOp(t->operands[0], ld<1>(t, irb), irb);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);
    op3 = ld<3>(t, irb);

    llvm::Value* cond = nullptr;
    llvm::Value* vTrue = nullptr;
    llvm::Value* vFalse = nullptr;
    switch (i->id) {
        case TRICORE_INS_SELN:
            switch (t->op2) {
                case 0x00: // condition = (D[d] != 0); result = ((condition) ? D[a] + D[b] : D[a]); D[c] = result[31:0];
                    cond = irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = irb.CreateAdd(op1, op2);
                    vFalse = op1;
                    break;

                case 0x01: //condition = (D[d] == 0); result = ((condition) ? D[a] + D[b] : D[a]); D[c] = result[31:0];
                    cond = irb.CreateICmpEQ(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = irb.CreateAdd(op1, op2);
                    vFalse = op1;
                    break;

                case 0x02: // condition = (D[d] != 0); result = ((condition) ? D[a] - D[b] : D[a]); D[c] = result[31:0];
                    cond = irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = irb.CreateSub(op1, op2);
                    vFalse = op1;
                    break;

                case 0x03: // condition = (D[d] == 0); result = ((condition) ? D[a] - D[b] : D[a]); D[c] = result[31:0];
                    cond = irb.CreateICmpEQ(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = irb.CreateSub(op1, op2);
                    vFalse = op1;
                    break;

                case 0x04: //D[c] = ((D[d] != 0) ? D[a] : D[b]);
                    cond = irb.CreateICmpNE(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = op1;
                    vFalse = op2;
                    break;

                case 0x05: //D[c] = ((D[d] == 0) ? D[a] : D[b]);
                    cond = irb.CreateICmpEQ(op3, llvm::ConstantInt::get(op3->getType(), 0));
                    vTrue = op1;
                    vFalse = op2;
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }

    storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
}

void Capstone2LlvmIrTranslatorTricore::translateSub(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);
    op3 = ld<3>(t, irb);

    llvm::Value* v = nullptr;
    switch (i->id) {
        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            v =  irb.CreateSub(op0, op1);
            break;

        case TRICORE_INS_SUBD1516: //result = D[15] - D[b]; D[a] = result[31:0];
            v = irb.CreateSub(op1, op2);
            break;

        case TRICORE_INS_SUBD15: //result = D[a] - D[b]; D[15] = result[31:0];
            storeRegister(TRICORE_REG_D_15, irb.CreateSub(op0, op1), irb);
            return;

        case TRICORE_INS_MSUB:
            switch (t->op2) {
                case 0x01: // result = D[d] - (D[a] * sign_ext(const9)); D[c] = result[31:0];
                case 0x04: // result = D[d] - (D[a] * zero_ext(const9)); // unsigned operators D[c] = suov(result, 32);
                case 0x05: // result = D[d] - (D[a] * sign_ext(const9)); D[c] = ssov(result, 32);
                    v = irb.CreateSub(op3, irb.CreateMul(op1, op2));
                    break;

                case 0x02: //result = E[d] - (D[a] * zero_ext(const9)); unsigned operators E[c] = result[63:0];
                case 0x06: //result = E[d] - (D[a] * zero_ext(const9)); // unsigned operators E[c] = suov(result, 64);
                    op1 = irb.CreateZExt(op1, op3->getType());
                    op2 = irb.CreateZExt(op2, op3->getType());
                    v = irb.CreateSub(op3, irb.CreateMul(op1, op2));
                    break;

                case 0x03: //result = E[d] - (D[a] * sign_ext(const9)); E[c] = result[63:0];
                case 0x07: //result = E[d] - (D[a] * sign_ext(const9)); E[c] = ssov(result, 64);
                    op1 = irb.CreateSExt(op1, op3->getType());
                    op2 = irb.CreateSExt(op2, op3->getType());
                    v = irb.CreateSub(op3, irb.CreateMul(op1, op2));
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }

    assert(v != nullptr);
    storeOp(t->operands[0], v, irb);
}

void Capstone2LlvmIrTranslatorTricore::translateCall(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    switch (i->id) {
        case TRICORE_INS_CALL16:
        case TRICORE_INS_CALL32:
            storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
            generateCallFunctionCall(i, irb, op0); //PC = PC + sign_ext(2 * disp24);
            break;

        case TRICORE_INS_CALLI:
            switch (t->op2) {
                case 0x00:
                    storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
//                     generateCallFunctionCall(i, irb, irb.CreateAnd(op0, 0xFFFFFFFE), false);
                    generateCallFunctionCall(i, irb, op0, false);
                    break;

                case 0x01:
                    storeOp(t->operands[1], loadRegister(TRICORE_REG_RA, irb), irb);
                    storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
                    generateCallFunctionCall(i, irb, op1, false); // // A[10] = EA[31:0]
                    break;

                case 0x02:
                    storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
//                     generateCallFunctionCall(i, irb, irb.CreateAnd(op0, 0xFFFFFFFE), false);
                    generateCallFunctionCall(i, irb, op0, false);
                    break;

                case 0x03:
//                     generateCallFunctionCall(i, irb, irb.CreateAnd(op0, 0xFFFFFFFE), false);
                    generateCallFunctionCall(i, irb, op0, false);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_CALLABS:
            storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); // A[11] = PC + 4;
            generateCallFunctionCall(i, irb, op0, false); //PC = {disp24[23:20], 7'b0, disp24[19:0], 1'b0};
            break;

        case TRICORE_INS_FCALL:
        {
            storeOp(t->operands[0], op1, irb); //M(EA,word) = A[11];
            generateCallFunctionCall(i, irb, op2); //PC = PC + sign_ext(2 * disp24);
            storeRegister(TRICORE_REG_RA, getNextInsnAddress(i), irb); //A[11] = ret_addr[31:0]; ret_addr = PC + 4;
            storeRegister(TRICORE_REG_SP, op0, irb); //A[10] = EA[31:0];
            break;
        }
        default:
            assert(false);
    }
}

void Capstone2LlvmIrTranslatorTricore::translate0B(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb) {
    assert(i->id = TRICORE_INS_0B);
    op0 = ld<0>(t, irb);
    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);

    auto* lastBitInDc = irb.CreateAnd(op0, 1);
    auto* vTrue = irb.CreateOr(op0, 1);
    auto* vFalse = irb.CreateAnd(op0, ~(0 << 30) << 1);

    switch (t->op2) {
        case 0x00: //result = D[a] + D[b]; D[c] = result[31:0];
        case 0x02: //result = D[a] + D[b]; D[c] = ssov(result, 32);
        case 0x03: //result = D[a] + D[b]; // unsigned addition D[c] = suov(result, 32);
        case 0x04: //result = D[a] + D[b]; D[c] = result[31:0]; carry_out = carry(D[a],D[b],0); //TODO flag
        case 0x05: //result = D[a] + D[b] + PSW.C; D[c] = result[31:0]; carry_out = carry(D[a], D[b], PSW.C); //TODO CARRY
            storeOp(t->operands[0], irb.CreateAdd(op1, op2), irb);
            break;

        case 0x08: //SUBD result = D[a] - D[b]; D[c] = result[31:0];
        case 0x0A: //result = D[a] - D[b]; D[c] = ssov(result, 32);
            storeOp(t->operands[0], irb.CreateSub(op1, op2), irb);
            break;

        case 0x11: //result = (D[a] != D[b]); D[c] = zero_ext(result);
            storeOp(t->operands[0], irb.CreateSelect(irb.CreateICmpNE(op1, op2), constInt<1>(op1), constInt<0>(op1)), irb);
            break;

        case 0x12: //result = (D[a] < D[b]); D[c] = zero_ext(result);
            storeOp(t->operands[0], irb.CreateSelect(irb.CreateICmpSLT(op1, op2), constInt<1>(op1), constInt<0>(op1)), irb);
            break;

        case 0x13: //result = (D[a] < D[b]); // unsigned D[c] = zero_ext(result);
        {
            llvm::Value* cond = irb.CreateICmpULT(op1, op2);
            llvm::Value* sel = irb.CreateSelect(cond, llvm::ConstantInt::get(op1->getType(), 1), constInt<0>(op1));
            storeOp(t->operands[0], sel, irb, eOpConv::ZEXT_TRUNC);
            break;
        }
        case 0x14: //result = (D[a] >= D[b]); D[c] = zero_ext(result);
        {
            llvm::Value* cond = irb.CreateICmpSGE(op1, op2);
            llvm::Value* sel = irb.CreateSelect(cond, llvm::ConstantInt::get(op1->getType(), 1), constInt<0>(op1));
            storeOp(t->operands[0], sel, irb, eOpConv::ZEXT_TRUNC);
            break;
        }
        case 0x15: //result = (D[a] >= D[b]); // unsigned D[c] = zero_ext(result);
        {
            llvm::Value* cond = irb.CreateICmpUGE(op1, op2);
            llvm::Value* sel = irb.CreateSelect(cond, llvm::ConstantInt::get(op1->getType(), 1), constInt<0>(op1));
            storeOp(t->operands[0], sel, irb, eOpConv::ZEXT_TRUNC);
            break;
        }
        case 0x18: //D[c] = (D[a] < D[b]) ? D[a] : D[b];
        {
            auto* sle = irb.CreateICmpSLT(op1, op2);
            auto* val = irb.CreateSelect(sle, op1, op2);
            storeOp(t->operands[0], val, irb);
            break;
        }
        case 0x1A: //D[c] = (D[a] > D[b]) ? D[a] : D[b];
        {
            auto* sle = irb.CreateICmpSGT(op1, op2);
            auto* val = irb.CreateSelect(sle, op1, op2);
            storeOp(t->operands[0], val, irb);
            break;
        }
        case 0x1C: //result = (D[b] >= 0) ? D[b] : (0 - D[b]); D[c] = result[31:0];
        case 0x1D: //result = (D[b] >= 0) ? D[b] : (0 - D[b]); D[c] = ssov(result, 32);
        {
            auto* sle = irb.CreateICmpSGE(op0, constInt<0>(op1));
            auto* val = irb.CreateSelect(sle, op1, irb.CreateNeg(op1));
            storeOp(t->operands[0], val, irb);
            break;
        }
        case 0x20: //D[c] = {D[c][31:1], D[c][0] AND (D[a] == D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x21: //D[c] = {D[c][31:1], D[c][0] AND (D[a] != D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpNE(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x23: //D[c] = {D[c][31:1], D[c][0] AND (D[a] < D[b])}; // unsigned
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpULT(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x25: //D[c] = {D[c][31:1], D[c][0] AND (D[a] >= D[b])}; // unsigned
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpUGE(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateAnd(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x27: //D[c] = {D[c][31:1], D[c][0] OR (D[a] == D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpEQ(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x28: //D[c] = {D[c][31:1], D[c][0] OR (D[a] != D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpNE(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x29: // D[c] = {D[c][31:1], D[c][0] OR (D[a] < D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpSLT(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x2A: //D[c] = {D[c][31:1], D[c][0] OR (D[a] < D[b])}; // unsigned
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpULT(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x2B: //D[c] = {D[c][31:1], D[c][0] OR (D[a] >= D[b])};
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpSGE(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x2C: //D[c] = {D[c][31:1], D[c][0] OR (D[a] >= D[b])}; // unsigned
        {
            auto* condBit = irb.CreateSelect(irb.CreateICmpUGE(op1, op2), constInt<1>(op0), constInt<0>(op0));
            auto* cond = irb.CreateICmpNE(irb.CreateOr(lastBitInDc, condBit), constInt<0>(op0));
            storeOp(t->operands[0], irb.CreateSelect(cond, vTrue, vFalse), irb);
            break;
        }
        case 0x7e: //sat_neg = (D[a] < -8000 H ) ? -8000 H : D[a]; D[c] = (sat_neg > 7FFF H ) ? 7FFF H : sat_neg;
        {
            auto* cond = irb.CreateICmpSGE(op1, llvm::ConstantInt::get(op1->getType(), -0x8000, true));
            auto* sel = irb.CreateSelect(cond, op1, llvm::ConstantInt::get(op1->getType(), -0x8000, true));
            auto* cond2 = irb.CreateICmpSGT(sel, llvm::ConstantInt::get(sel->getType(), 0x7FFF));
            auto* sel2 = irb.CreateSelect(cond2, llvm::ConstantInt::get(sel->getType(), 0x7FFF), sel);
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

        case 0x08:
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

    op1 = ld<1>(t, irb);
    op2 = ld<2>(t, irb);
    op4 = ld<4>(t, irb);
    llvm::Value* v = nullptr;
    switch (t->op2) {
        case 0x00: //D[c] = {D[a][31:(pos1+1)], D[b][pos2], D[a][(pos1-1):0]};
        {
            auto* bitInPos2 = irb.CreateAnd(irb.CreateLShr(op2, op4), 1);
            v = irb.CreateAnd(op1, irb.CreateOr(irb.CreateShl(bitInPos2, op4), ~(~0 << t->operands[4].imm.value)));
            break;
        }
        case 0x01: //D[c] = {D[a][31:(pos1+1)], !D[b][pos2], D[a][(pos1-1):0]};
        {
            auto* bitInPos2 = irb.CreateNot(irb.CreateAnd(irb.CreateLShr(op2, op4), 1));
            v = irb.CreateAnd(op1, irb.CreateOr(irb.CreateShl(bitInPos2, op4), ~(~0 << t->operands[4].imm.value)));
            break;
        }
        default:
            assert(false);
    }

    storeOp(t->operands[0], v, irb);
}

} // namespace capstone2llvmir
} // namespace retdec
