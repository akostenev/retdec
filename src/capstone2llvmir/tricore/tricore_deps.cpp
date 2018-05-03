#include "retdec/capstone2llvmir/tricore/tricore.h"

//////////////////////
// Capstone2Tricore //
//////////////////////

tricore_reg getRegD(unsigned int n) {
    return tricore_reg(0xFF00 + n*4);
}

tricore_reg getRegA(unsigned int n) {
    return tricore_reg(0xFF80 + n*4);
}

void dismNOP(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    //nothing
}

void dismSB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SB;
    t->op_count = 1;

    auto disp8 = tricore_op_imm(bitRange<8, 15>(b).to_ulong(), 8, TRICORE_EXT_SEXT, true);

    switch (i->id) {
        case TRICORE_INS_J_8:           // PC = PC + sign_ext(disp8) * 2;
            t->operands[0] = disp8;
            break;
        case TRICORE_INS_JNZ_D15:       // if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JZ_D15:        // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
            t->op_count = 2;
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = disp8;
            break;
        default:
            assert(false && TRICORE_OF_SB);
    }
}

void dismSBC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismSBR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SBR;
    t->op_count = 2;

    auto disp4 = tricore_op_imm(bitRange<8, 11>(b).to_ulong(), 4);
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LOOP: // if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
        {
            t->operands[0] = getRegA(s2); //A[b]

            std::bitset<64> add = bitRange<8, 11>(b) << 1; // disp4, 0
            for (unsigned int i = 5; i < 32; i++) { // 27b’111111111111111111111111111
                add.set(i);
            }
            t->operands[1] = cs_tricore_op(add.to_ulong()); //{27b’111111111111111111111111111, disp4, 0};
            break;
        }
        case TRICORE_INS_JZD: // if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = getRegD(s2); //D[b]
            t->operands[1] = {disp4, TRICORE_EXT_ZEXT, true}; //zero_ext(disp4) * 2;
            break;

        case TRICORE_INS_JZA_16: // if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = getRegA(s2); //A[b]
            t->operands[1] = {disp4, TRICORE_EXT_ZEXT, true}; //zero_ext(disp4) * 2;
            break;

        default:
            assert(false && TRICORE_OF_SBR);
    }
}

void dismSBRN(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismSC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SC;
    t->op_count = 2;

    auto const8 = tricore_op_imm(bitRange<8, 15>(b).to_ulong(), 8);

    switch (i->id) {
        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
            t->operands[0] = TRICORE_REG_A_10;
            t->operands[1] = {const8, TRICORE_EXT_ZEXT};
            break;

        default:
            assert(false && TRICORE_OF_SC);
    }
}

void dismSLR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SLR;
    t->op_count = 2;

    auto d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LDA_PINC: //A[c] = M(A[b], word); A[b] = A[b] + 4;
            t->operands[0] = getRegA(d);
            t->operands[1] = {getRegA(s2), 0};
            break;

        case TRICORE_INS_LDD: //D[c] = M(A[b], word); A[b] = A[b] + 4;
           t->operands[0] = getRegD(d);
           t->operands[1] = {getRegA(s2), 0};
           break;

        case TRICORE_INS_LD_HD_PINC: //D[c] = sign_ext(M(A[b], half-word));  A[b] = A[b] + 2;
            t->operands[0] = getRegD(d);
            t->operands[1] = {getRegA(s2), 0, HALFWORD, TRICORE_EXT_SEXT};
            break;

        default:
            assert(false && TRICORE_OF_SLR);
    }
}

void dismSLRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SLRO;
    t->op_count = 2;

    auto d = bitRange<8, 11>(b).to_ulong();
    auto off4 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LDA: //A[c] = M(A[15] + zero_ext(4 * off4), word);
            t->operands[0] = getRegA(d);
            t->operands[1] = {TRICORE_REG_A_15, off4 * 4};
            break;

        default:
            assert(false && TRICORE_OF_SLRO);
    }
}

void dismSR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SR;
    t->op_count = 1;

    t->op2 = bitRange<12, 15>(b).to_ulong();
    auto s1d = bitRange<8, 11>(b).to_ulong();

    switch (i->id) {
     case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
            t->operands[0] = getRegA(s1d);
            break;

     default:
         assert(false && TRICORE_OF_SR);
    }
}

void dismSRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SRC;
    t->op_count = 2;

    auto const4 = tricore_op_imm(bitRange<12, 15>(b).to_ulong(), 4);
    auto s1d = bitRange<8, 11>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_ADDA: //A[a] = A[a] + sign_ext(const4);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = {const4, TRICORE_EXT_SEXT};
            break;

        case TRICORE_INS_MOVA: //A[a] = zero_ext(const4);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = {const4, TRICORE_EXT_ZEXT};
            break;

        case TRICORE_INS_ADDD: //D[a] = sign_ext(const4);
        case TRICORE_INS_MOVD_A: //D[a] = sign_ext(const4);
        case TRICORE_INS_SHAD: // ... to long //TODO check
        case TRICORE_INS_SHD: //shift_count = sign_ext(const4[3:0]); D[a] = (shift_count >= 0) ? D[a] << shift_count : D[a] >> (-shift_count); //TODO check
            t->operands[0] = getRegD(s1d);
            t->operands[1] = {const4, TRICORE_EXT_SEXT};
            break;

        default:
            assert(false && TRICORE_OF_SRC);
    }
}

void dismSRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SRO;
    t->op_count = 2;

    auto off4 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    auto regA = getRegA(s2);

    switch (i->id) {
        case 0xCC: //A[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_A_15;
            t->operands[1] = {regA, 4 * off4};
            break;

        case TRICORE_INS_LD_BUD: //D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = {regA, off4, BYTE, TRICORE_EXT_ZEXT};
            break;

        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = {regA, 2* off4, HALFWORD, TRICORE_EXT_SEXT};
            break;

        case 0x4C: //D[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = {regA, 4 * off4};
            break;

        case 0xEC: //M(A[b] + zero_ext(4 * off4), word) = A[15];
            t->operands[0] = {regA, 4 * off4};
            t->operands[1] = {TRICORE_REG_A_15};
            break;

        case 0x2C: //M(A[b] + zero_ext(off4), byte) = D[15][7:0];
            t->operands[0] = {regA, off4, BYTE};
            t->operands[1] = {TRICORE_REG_D_15};
            break;

        case 0xAC: //M(A[b] + zero_ext(2 * off4), half-word) = D[15][15:0];
            t->operands[0] = {regA, 2 * off4, HALFWORD};
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case 0x6C: //M(A[b] + zero_ext(4 * off4), word) = D[15];
            t->operands[0] = {regA, 4 * off4};
            t->operands[1] = TRICORE_REG_D_15;
            break;

        default:
            assert(false);
    }
}

void dismSRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SRR;
    t->op_count = 2;

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_MOVAA: //A[a] = A[b];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = getRegA(s2);
            break;

        case TRICORE_INS_MOVAD: //A[a] = D[b];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = getRegD(s2);
            break;

        case TRICORE_INS_MOVDA: //D[a] = A[b];
            t->operands[0] = getRegD(s1d);
            t->operands[1] = getRegA(s2);
            break;

        case TRICORE_INS_MOVDD: //D[a] = D[b];
        case TRICORE_INS_ORD: //D[a] = D[a] | D[b];
        case TRICORE_INS_ANDD: //D[a] = D[a] & D[b];
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            t->operands[0] = getRegD(s1d);
            t->operands[1] = getRegD(s2);
            break;

        default:
            assert(false);
    }
}

void dismSRRS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismSSR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_SSR;
    t->op_count = 2;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    auto regAb = getRegA(s2);
    auto regDa = getRegD(s1);

    switch (i->id) {
        case TRICORE_INS_STA: //M(A[b], word) = A[a];
            t->operands[0] = {regAb, 0};
            t->operands[1] = getRegA(s1);
            break;

        case TRICORE_INS_STB: //M(A[b], byte) = D[a][7:0];
            t->operands[0] = {regAb, 0, BYTE};
            t->operands[1] = regDa;
            break;

        case TRICORE_INS_STD: //M(A[b], word) = D[a];
        case TRICORE_INS_STW: //M(A[b], word) = D[a]; A[b] = A[b] + 4;
            t->operands[0] = {regAb, 0};
            t->operands[1] = regDa;
            break;

        case TRICORE_INS_STHW: //M(A[b], half-word) = D[a][15:0]; A[b] = A[b] + 2;
            t->operands[0] = {regAb, 0, HALFWORD};
            t->operands[1] = regDa;
            break;

        default:
            assert(false);
    }
}

void dismSSRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}



void dismABS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_ABS;
    t->op_count = 2;
    t->op2 = bitRange<26, 27>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto bOff18 = (bitRange<12, 15>(b) << 14) | (bitRange<22, 25>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));
    auto bExtOff18 = (bitRange<14, 17>(bOff18) << 28) | (bitRange<0, 13>(bOff18));
    auto ea = bExtOff18.to_ulong();

    switch (i->id) {
        case 0x85: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = M(EA, word);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = {TRICORE_REG_INVALID, ea};
            break;

        case 0xC5: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = EA[31:0];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = tricore_op_imm(ea);
            break;

        case 0x05: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = sign_ext(M(EA, byte));
            t->operands[0] = getRegD(s1d);
            t->operands[1] = {TRICORE_REG_INVALID, ea, BYTE, TRICORE_EXT_SEXT};
            break;

        case TRICORE_INS_ST: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = A[a];
            t->operands[0] = {TRICORE_REG_INVALID, ea};
            t->operands[1] = getRegA(s1d);
            break;

        case 0x65: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, halfword) = D[a][31:16];
            t->operands[0] = {TRICORE_REG_INVALID, ea, HALFWORD};
            t->operands[1] = getRegD(s1d);
            break;

//         case 0xE5: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = (M(EA, word) & ~E[a][63:32]) | (E[a][31:0] & E[a][63:32])
//         case 0x15: // EA = {off18[17:14], 14b'0, off18[13:0]};  {dummy, dummy, A[10:11], D[8:11], A[12:15], D[12:15]} = M(EA, 16-word);
//         case 0x25: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, byte) = D[a][7:0];
//         case 0x45: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = {M(EA, halfword), 16’h0000};

        default:
            assert(false && TRICORE_OF_ABS);
    }
}

void dismABSB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_B;
    t->op_count = 1;

    auto bDisp24 = bitRange<8, 15>(b) << 16 | bitRange<16, 31>(b);
    auto disp24 = tricore_op_imm(bDisp24.to_ulong(), 24);
    auto bExpDisp24 = (bitRange<20, 23>(bDisp24) << 28) | (bitRange<0, 19>(bDisp24) << 1);
    auto expDisp24 = tricore_op_imm(bExpDisp24.to_ulong(), 31);

    switch (i->id) {
//         case 0x6D:
//         case 0xED:
//         case 0x61: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = PC + sign_ext(2 * disp24); A[11] = ret_addr[31:0]; A[10] = EA[31:0];
//         case 0xE1: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = {disp24[23:20], 7'b0, disp24[19:0], 1'b0}; A[11] = ret_addr[31:0]; A[10] = EA[31:0]
        case TRICORE_INS_J_24: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_JL: //A[11] = PC + 4; PC = PC + sign_ext(disp24) * 2;
            t->operands[0] = {disp24, TRICORE_EXT_SEXT, true};
            break;

        case TRICORE_INS_JA: //PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};
            t->operands[0] = expDisp24;
            break;

        case TRICORE_INS_CALL_24: // ... to long
            t->operands[0] = {expDisp24, TRICORE_EXT_NOTHING, true};
            break;

        default:
            assert(false && TRICORE_OF_B);
    }
}

void dismBIT(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismBO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_BO;
    t->op_count = 3;
    t->op2 = bitRange<22, 27>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto off10 = tricore_op_imm(((bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b))).to_ulong(), 10, TRICORE_EXT_SEXT);

    switch (i->id) {
        case TRICORE_INS_ST89: // ATTENTION decomp needs to test op2 and work accordingly with op0, op1, op2 //TODO or implement here???
            //14H: EA = A[b] + sign_ext(off10); M(EA, word) = D[a];             A[b] = EA;
            //05H: EA = A[b];                   M(EA, doubleword) = E[a];       A[b] = EA + sign_ext(off10);
        case TRICORE_INS_LD09:
            //05H: EA = A[b];                   E[a] = M(EA, doubleword);       A[b] = EA + sign_ext(off10);
            //20H: EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, byte));
            t->operands[0] = getRegA(s2);
            t->operands[1] = off10;
            t->operands[2] = getRegD(s1d); // D[a] // E[a
            break;

        default:
            assert(false && TRICORE_OF_BO);
    }
}

void dismBOL(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_BOL;
    t->op_count = 2;

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto off16 = ((bitRange<22, 27>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b))).to_ulong();

    switch (i->id) {
        case TRICORE_INS_STWA:  // EA = A[b] + sign_ext(off16); M(EA, word) = D[a];
            t->operands[0] = {getRegA(s2), off16, WORD, TRICORE_EXT_NOTHING, TRICORE_EXT_SEXT};
            t->operands[1] = getRegD(s1d);
            break;

        case TRICORE_INS_LEA:   // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = {getRegA(s2), off16, WORD, TRICORE_EXT_NOTHING, TRICORE_EXT_SEXT};
            t->operands[1].mem.lea = true;
            break;

        case TRICORE_INS_LDW:   // EA = A[b] + sign_ext(off16); D[a] = M(EA, word);
            t->operands[0] = getRegD(s1d);
            t->operands[1] = {getRegA(s2), off16, WORD, TRICORE_EXT_NOTHING, TRICORE_EXT_SEXT};
            break;

        default:
            assert(false && TRICORE_OF_BOL);
    }
}

void dismBRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_BRC;
    t->op_count = 3;
    t->op2 = bitRange<30, 31>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const4 = tricore_op_imm(bitRange<12, 15>(b).to_ulong(), 4, TRICORE_EXT_SEXT);
    auto disp15 = tricore_op_imm(bitRange<16, 30>(b).to_ulong(), 15, TRICORE_EXT_SEXT, true);

    switch (i->id) {
        case TRICORE_INS_JEQ_15_c:  //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                                    //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegD(s1);
            t->operands[1] = const4;
            t->operands[2] = disp15;
            break;

//         case 0xFF:
//         case 0xBF:
//         case 0x9F:
        default:
            assert(false && TRICORE_OF_BRC);
    }
}

void dismBRN(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_BRN;
    t->op_count = 2;
    t->op2 = bitRange<30, 31>(b).to_ulong();
    t->n = (bitRange<6, 7>(b) << 3 | bitRange<12, 15>(b)).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto disp15 = tricore_op_imm(bitRange<16, 29>(b).to_ulong(), 15, TRICORE_EXT_SEXT, true);

    switch (i->id) {
        case TRICORE_INS_JNZT: //if (D[a][n]) then PC = PC + sign_ext(disp15) * 2;
                               //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegD(s1);
            t->operands[1] = disp15;
            break;

        default:
            assert(false && TRICORE_OF_BRN);
    }
}

void dismBRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_BRR;
    t->op_count = 3;
    t->op2 = bitRange<30, 31>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto disp15 = tricore_op_imm(bitRange<16, 30>(b).to_ulong(), 15, TRICORE_EXT_SEXT, true);

    switch (i->id) {
        case TRICORE_INS_JEQ_A: // if (A[a] == A[b]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegA(s1);
            t->operands[1] = getRegA(s2);
            t->operands[2] = disp15;
            break;

        default:
            assert(false && TRICORE_OF_BRR);
    }
}

void dismRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_RC;
    t->op_count = 3;
    t->op2 = bitRange<21, 27>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const9 = tricore_op_imm(bitRange<12, 20>(b).to_ulong(), 9, TRICORE_EXT_ZEXT);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_BIT_OPERATIONS1:
            // 0AH : D[c] = D[a] | zero_ext(const9);
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = const9;
            break;

        default:
            assert(false && TRICORE_OF_RC);
    }
}

void dismRCPW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRCR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRCRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRCRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRLC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_RLC;
    t->op_count = 2;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto bConst16 = bitRange<12, 27>(b);
    auto const16 = tricore_op_imm(bConst16.to_ulong(), 16);
    auto const32 = tricore_op_imm((bConst16 << 16).to_ulong(), 32);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
            t->operands[0] = getRegD(d);
            t->operands[1] = {const16, TRICORE_EXT_SEXT};
            break;

        case TRICORE_INS_MOVU: //D[c] = zero_ext(const16);
            t->operands[0] = getRegD(d);
            t->operands[1] = {const16, TRICORE_EXT_ZEXT};
            break;

        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
            t->operands[0] = getRegD(d);
            t->operands[1] = const32;
            break;

        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
            t->operands[0] = getRegA(d);
            t->operands[1] = const32;
            break;

        case TRICORE_INS_MTCR: //CR[const16] = D[a];
            t->operands[0] = tricore_reg(bConst16.to_ulong());
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_MFCR: //D[c] = CR[const16];
            t->operands[0] = getRegD(d);
            t->operands[1] = tricore_reg(bConst16.to_ulong());
            break;

        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
            t->op_count = 3;
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = {const16, TRICORE_EXT_SEXT};
            break;

        default:
            assert(false);
    }
}

void dismRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_RR;
    t->op_count = 3;
    t->op2 = bitRange<20, 27>(b).to_ulong();
    t->n = bitRange<16, 17>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_BIT_OPERATIONS2: //D[c] = D[a] & D[b];
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            break;

        default:
            assert(false && TRICORE_OF_RR);
    }
}

void dismRR1(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRR2(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRRPW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_RRPW;
    t->op_count = 4;
    t->op2 = bitRange<21, 22>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
//     auto s2 = bitRange<12, 15>(b).to_ulong();
    auto width = tricore_op_imm(bitRange<16, 20>(b).to_ulong(), 5);
    auto pos = tricore_op_imm(bitRange<23, 27>(b).to_ulong(), 5);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_EXTR: //D[c] = sign_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = pos;
            t->operands[3] = width;
            break;

        default:
            assert(false);
    }
}

void dismRRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRRR1(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRRR2(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRRRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismRRRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismSYS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

static std::map<std::size_t, void (*)(cs_tricore* t, cs_insn* i, const std::bitset<64>& b)> insToDism = {
    {TRICORE_INS_NOP, &dismNOP},

    {TRICORE_INS_J_8, &dismSB},
    {TRICORE_INS_JNZ_D15, &dismSB},
    {TRICORE_INS_JZ_D15, &dismSB},

    {TRICORE_INS_LOOP, &dismSBR},
    {TRICORE_INS_JZD, &dismSBR},
    {TRICORE_INS_JZA_16, &dismSBR},

    {TRICORE_INS_SUBA10, &dismSC},

    {TRICORE_INS_LDA_PINC, &dismSLR},
    {TRICORE_INS_LDD, &dismSLR},
    {TRICORE_INS_LD_HD_PINC, &dismSLR},

    {TRICORE_INS_LDA, &dismSLRO},

    {TRICORE_INS_JIA, &dismSR},

    {TRICORE_INS_ADDA, &dismSRC},
    {TRICORE_INS_MOVA, &dismSRC},
    {TRICORE_INS_ADDD, &dismSRC},
    {TRICORE_INS_MOVD_A, &dismSRC},
    {TRICORE_INS_SHAD, &dismSRC},
    {TRICORE_INS_SHD, &dismSRC},

    {TRICORE_INS_MOVAA, &dismSRR},
    {TRICORE_INS_MOVAD, &dismSRR},
    {TRICORE_INS_MOVDA, &dismSRR},
    {TRICORE_INS_MOVDD, &dismSRR},
    {TRICORE_INS_ORD, &dismSRR},
    {TRICORE_INS_ANDD, &dismSRR},
    {TRICORE_INS_SUBD, &dismSRR},

    {TRICORE_INS_LD_BUD, &dismSRO},
    {TRICORE_INS_LD_HD, &dismSRO},

    {TRICORE_INS_STA, &dismSSR},
    {TRICORE_INS_STB, &dismSSR},
    {TRICORE_INS_STD, &dismSSR},
    {TRICORE_INS_STW, &dismSSR},
    {TRICORE_INS_STHW, &dismSSR},

    {TRICORE_INS_ST, &dismABS},

    {TRICORE_INS_J_24, &dismB},
    {TRICORE_INS_JL, &dismB},
    {TRICORE_INS_JA, &dismB},
    {TRICORE_INS_CALL_24, &dismB},

    {TRICORE_INS_ST89, &dismBO},
    {TRICORE_INS_LD09, &dismBO},

    {TRICORE_INS_STWA, &dismBOL},
    {TRICORE_INS_LEA, &dismBOL},
    {TRICORE_INS_LDW, &dismBOL},

    {TRICORE_INS_JEQ_15_c, &dismBRC},

    {TRICORE_OF_BRN, &dismBRN},

    {TRICORE_INS_JEQ_A, &dismBRR},

    {TRICORE_INS_BIT_OPERATIONS1, &dismRC},

    {TRICORE_INS_MOVD_C16, &dismRLC},
    {TRICORE_INS_MOVU, &dismRLC},
    {TRICORE_INS_MOVH, &dismRLC},
    {TRICORE_INS_MOVH_A, &dismRLC},
    {TRICORE_INS_MTCR, &dismRLC},
    {TRICORE_INS_MFCR, &dismRLC},
    {TRICORE_INS_ADDI, &dismRLC},

    {TRICORE_INS_BIT_OPERATIONS2, &dismRR},

    {TRICORE_INS_EXTR, &dismRRPW},

};

cs_tricore::cs_tricore(cs_insn* i) : op2(0), n(0) {
    std::bitset<64> b = i->size == 4 ? i->bytes[3] << 24 | i->bytes[2] << 16 | i->bytes[1] << 8 | i->bytes[0] : i->bytes[1] << 8 | i->bytes[0];

     auto fInsToDism = insToDism.find(i->id);
     if (fInsToDism == std::end(insToDism)) {
        assert(false && "Unknown Tricore Instruction");
     } else {
        fInsToDism->second(this, i, b);
     }
}
