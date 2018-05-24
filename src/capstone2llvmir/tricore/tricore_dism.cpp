#include "retdec/capstone2llvmir/tricore/tricore.h"

tricore_reg getRegD(unsigned int n) {
    return tricore_reg(TRICORE_REG_D_0 + n*4);
}

tricore_reg getRegA(unsigned int n) {
    return tricore_reg(TRICORE_REG_A_0 + n*4);
}

template<std::size_t size, std::size_t N>
uint64_t sExt(std::bitset<N> b, uint8_t mult2 = 1) {
    b <<= (mult2 / 2);

    size_t msb = size + (mult2 / 2) - 1;
    if (b.test(msb)) {
        for (std::size_t i = msb + 1; i < N; i++) {
            b.set(i);
        }
    }
    return b.to_ulong();
}

template<std::size_t N>
uint64_t zExt(std::bitset<N> b, uint8_t mult2 = 1) {
    b <<= (mult2 / 2);

    //nothing to do, b is already set to 0
    return b.to_ulong();
}

/**
 * extends b for tricore
 *  from 24 to 32: {b[23:20], 7’b0000000, b[19:0], 1’b0};
 *  from 18 to 32: {off18[17:14], 14b'0, off18[13:0]};
 *  from 16 to 32: const16, 16’h0000
 *  from  4 to 32: {27b’111111111111111111111111111, disp4, 0};
 */
template<std::size_t t, std::size_t N>
uint64_t tExt(std::bitset<N> b) {
    switch (t) {
        case 24: return ((bitRange<20, 23>(b) << 28) | (bitRange<0, 19>(b) << 1)).to_ulong();
        case 18: return ((bitRange<14, 17>(b) << 28) | (bitRange<0, 13>(b))).to_ulong();
        case 16: return (b << 16).to_ulong();
        case  4:
        {
            b <<= 1; // disp4, 0
            for (unsigned i = 4; i < 32; i++) {
                b.set(i);
            }
            return b.to_ulong();
        }
        default:
            assert(false && "Unsupported tExt");
    }
}

template<std::size_t size, std::size_t N>
tricore_op_imm sExtImm(std::bitset<N> b, uint8_t mult2 = 1) {
    return tricore_op_imm(sExt<size>(b, mult2), size, TRICORE_EXT_SEXT_TRUNC);
}

template<std::size_t size, std::size_t N>
tricore_op_imm zExtImm(std::bitset<N> b, uint8_t mult2 = 1) {
    return tricore_op_imm(zExt<>(b, mult2), size, TRICORE_EXT_ZEXT_TRUNC);
}

template<std::size_t size, std::size_t N>
tricore_op_imm tExtImm(std::bitset<N> b, uint8_t mult2 = 1) {
    return tricore_op_imm(tExt<size>(b), 32, TRICORE_EXT_THROW);
}

tricore_op_mem mem(tricore_reg n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return tricore_op_mem(n, tricore_op_imm(0), size, ext, lea);
}

tricore_op_mem mem(tricore_reg n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return tricore_op_mem(n, disp, size, ext, lea);
}

tricore_op_mem memA(uint64_t n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return mem(getRegA(n), size, ext, lea);
}

tricore_op_mem memA(uint64_t n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return mem(getRegA(n), disp, size, ext, lea);
}

tricore_op_mem memD(uint64_t n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return mem(getRegD(n), size, ext, lea);
}

tricore_op_mem memD(uint64_t n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, bool lea = false) {
    return mem(getRegD(n), disp, size, ext, lea);
}






                //////////////////////
                // Tricore2Capstone //
                //////////////////////

void dismNOP(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    //nothing
}

void dismSB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SB;
    t->op_count = 1;

    auto disp8 = bitRange<8, 15>(b);

    switch (i->id) {
        case TRICORE_INS_CALL16:        //too long...
        case TRICORE_INS_J16:           // PC = PC + sign_ext(disp8) * 2;
            t->operands[0] = sExtImm<8>(disp8, 2);
            break;
        case TRICORE_INS_JNZ_D15:       // if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JZ_D15:        // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
            t->op_count = 2;
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = sExtImm<8>(disp8, 2);
            break;
        default:
            assert(false && TRICORE_OF_SB);
    }
}

void dismSBC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
}

void dismSBR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SBR;
    t->op_count = 2;

    auto disp4 = bitRange<8, 11>(b);
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LOOP: // if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
            t->operands[0] = getRegA(s2); //A[b]
            t->operands[1] = tExtImm<4>(disp4);
            break;

        case TRICORE_INS_JZD: // if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JLEZD: // If (D[b] <= 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JGEZD: //if (D[b] >= 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = getRegD(s2);
            t->operands[1] = zExtImm<4>(disp4, 2);
            break;

        case TRICORE_INS_JZA_16: // if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = getRegA(s2);
            t->operands[1] = zExtImm<4>(disp4, 2);
            break;

        default:
            assert(false && TRICORE_OF_SBR);
    }
}

void dismSBRN(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
}

void dismSC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SC;
    t->op_count = 2;

    auto const8 = bitRange<8, 15>(b);

    switch (i->id) {
        case TRICORE_INS_ANDD15: //D[15] = D[15] & zero_ext(const8);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = zExtImm<8>(const8);
            break;

        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
            t->operands[0] = TRICORE_REG_A_10;
            t->operands[1] = zExtImm<8>(const8);
            break;

        case TRICORE_INS_MOVD15: //D[15] = zero_ext(const8);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = zExtImm<8>(const8);
            break;

        default:
            assert(false && TRICORE_OF_SC);
    }
}

void dismSLR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SLR;
    t->op_count = 2;

    auto d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LDA_PINC: //A[c] = M(A[b], word); A[b] = A[b] + 4;
        case TRICORE_INS_LD16A: //A[c] = M(A[b], word);
            t->operands[0] = getRegA(d);
            t->operands[1] = memA(s2);
            break;

        case TRICORE_INS_LDD_PINC: //D[c] = M(A[b], word); A[b] = A[b] + 4;
        case TRICORE_INS_LDD: //D[c] = M(A[b], word);
           t->operands[0] = getRegD(d);
           t->operands[1] = memA(s2);
           break;

        case TRICORE_INS_LD_HD_PINC: //D[c] = sign_ext(M(A[b], half-word));  A[b] = A[b] + 2;
            t->operands[0] = getRegD(d);
            t->operands[1] = memA(s2, HALFWORD, TRICORE_EXT_SEXT_TRUNC);
            break;



        default:
            assert(false && TRICORE_OF_SLR);
    }
}

void dismSLRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SLRO;
    t->op_count = 2;

    auto d = bitRange<8, 11>(b).to_ulong();
    auto off4 = bitRange<12, 15>(b);

    switch (i->id) {
        case TRICORE_INS_LDA: //A[c] = M(A[15] + zero_ext(4 * off4), word);
            t->operands[0] = getRegA(d);
            t->operands[1] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 4));
            break;

        default:
            assert(false && TRICORE_OF_SLRO);
    }
}

void dismSR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SR;
    t->op_count = 1;
    t->op2 = bitRange<12, 15>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
            t->operands[0] = getRegA(s1d);
            break;

        case 0x00:
            switch (t->op2) {
                case 0x00: //NOP
                case 0x09: //RET
                case 0x0A: //DEBUG
                    break;

                default:
                    assert(false && "Unknown op2 for 0x00 ins");
            }
            break;

        default:
            assert(false && TRICORE_OF_SR);
    }
}

void dismSRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SRC;
    t->op_count = 2;

    auto const4 = bitRange<12, 15>(b);
    auto s1d = bitRange<8, 11>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_ADDA: //A[a] = A[a] + sign_ext(const4);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = sExtImm<4>(const4);
            break;

        case TRICORE_INS_MOVA: //A[a] = zero_ext(const4);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = zExtImm<4>(const4);
            break;

        case TRICORE_INS_ADDD_c: //D[a] = sign_ext(const4);
        case TRICORE_INS_MOVD: //D[a] = sign_ext(const4);
        case TRICORE_INS_SHAD: // ... to long //TODO check
        case TRICORE_INS_SHD: //shift_count = sign_ext(const4[3:0]); D[a] = (shift_count >= 0) ? D[a] << shift_count : D[a] >> (-shift_count);
            t->operands[0] = getRegD(s1d);
            t->operands[1] = sExtImm<4>(const4);
            break;

        default:
            assert(false && TRICORE_OF_SRC);
    }
}

void dismSRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SRO;
    t->op_count = 2;

    auto off4 = bitRange<8, 11>(b);
    auto s2 = bitRange<12, 15>(b).to_ulong();

    auto regA = getRegA(s2);

    switch (i->id) {
        case 0xCC: //A[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_A_15;
            t->operands[1] = mem(regA, zExtImm<4>(off4));
            break;

        case TRICORE_INS_LD_BUD15: //D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = mem(regA, zExtImm<4>(off4), BYTE, TRICORE_EXT_ZEXT_TRUNC);
            break;

        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = mem(regA, zExtImm<4>(off4, 2), HALFWORD, TRICORE_EXT_SEXT_TRUNC);
            break;

        case 0x4C: //D[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = mem(regA, zExtImm<4>(off4, 4));
            break;

        case 0xEC: //M(A[b] + zero_ext(4 * off4), word) = A[15];
            t->operands[0] = mem(regA, zExtImm<4>(off4));
            t->operands[1] = TRICORE_REG_A_15;
            break;

        case 0x2C: //M(A[b] + zero_ext(off4), byte) = D[15][7:0]; //TODO TRUNC_AND? D[15][7:0]
            t->operands[0] = mem(regA, zExtImm<4>(off4), BYTE);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case 0xAC: //M(A[b] + zero_ext(2 * off4), half-word) = D[15][15:0];
            t->operands[0] = mem(regA, zExtImm<4>(off4, 2), HALFWORD);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case 0x6C: //M(A[b] + zero_ext(4 * off4), word) = D[15];
            t->operands[0] = mem(regA, zExtImm<4>(off4, 4));
            t->operands[1] = TRICORE_REG_D_15;
            break;

        default:
            assert(false);
    }
}

void dismSRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
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
        case TRICORE_INS_ADDDD: // result = D[a] + D[b]; D[a] = result[31:0];
        case TRICORE_INS_SUBD15: //result = D[a] - D[b]; D[15] = result[31:0];
        case TRICORE_INS_CMOVD: //D[a] = ((D[15] != 0) ? D[b] : D[a]);
        case TRICORE_INS_MULD2: //result = D[a] * D[b]; D[a] = result[31:0];
            t->operands[0] = getRegD(s1d);
            t->operands[1] = getRegD(s2);
            break;

        default:
            assert(false);
    }
}

void dismSRRS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SRRS;
    t->op_count = 3;
    t->n = bitRange<6,7>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_ADDSCA: //A[a] = (A[b] + (D[15] << n));
            t->operands[0] = getRegA(s1d);
            t->operands[1] = getRegA(s2);
            t->operands[2] = TRICORE_REG_D_15;
            break;

        default:
            assert(false);
    }
}

void dismSSR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SSR;
    t->op_count = 2;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();

    auto regAb = getRegA(s2);
    auto regDa = getRegD(s1);

    switch (i->id) {
        case TRICORE_INS_STA: //M(A[b], word) = A[a];
            t->operands[0] = mem(regAb);
            t->operands[1] = getRegA(s1);
            break;

        case TRICORE_INS_STB: //M(A[b], byte) = D[a][7:0];
            t->operands[0] = mem(regAb, BYTE);
            t->operands[1] = regDa;
            break;

        case TRICORE_INS_STD: //M(A[b], word) = D[a];
        case TRICORE_INS_STW: //M(A[b], word) = D[a]; A[b] = A[b] + 4;
            t->operands[0] = mem(regAb);
            t->operands[1] = regDa;
            break;

        case TRICORE_INS_STHW: //M(A[b], half-word) = D[a][15:0]; A[b] = A[b] + 2;
            t->operands[0] = mem(regAb, HALFWORD);
            t->operands[1] = regDa;
            break;

        default:
            assert(false);
    }
}

void dismSSRO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SSRO;
    t->op_count = 2;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto off4 = bitRange<12, 15>(b);

    switch (i->id) {
        case TRICORE_INS_STBA: //M(A[15] + zero_ext(off4), byte) = D[a][7:0];
            t->operands[0] = mem(TRICORE_REG_A_15, zExtImm<4>(off4), BYTE);
            t->operands[1] = getRegD(s1);
            break;

        default:
            assert(false);
    }
}

//32-bit instructions

void dismABS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_ABS;
    t->op_count = 2;
    t->op2 = bitRange<26, 27>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto off18 = (bitRange<12, 15>(b) << 14) | (bitRange<22, 25>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));
    auto ea = tExtImm<18>(off18);

    switch (i->id) {
        case TRICORE_INS_LD: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = M(EA, word);
            switch (t->op2) {
                case 0x00: //EA = {off18[17:14], 14b'0, off18[13:0]}; D[a] = M(EA, word);
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea);
                    break;

                case 0x01: //EA = {off18[17:14], 14b'0, off18[13:0]}; E[a] = M(EA, doubleword);
                    t->operands[0] = {getRegD(s1d), true};
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, DWORD);
                    break;

                case 0x03: //EA = {off18[17:14], 14b'0, off18[13:0]}; P[a] = M(EA, doubleword);
                    t->operands[0] = {getRegA(s1d), true};
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, DWORD);
                    break;

                default:
                    assert(false);
            }
            break;

        case 0xC5: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = EA[31:0];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = ea;
            break;

        case 0x05: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = sign_ext(M(EA, byte));
            t->operands[0] = getRegD(s1d);
            t->operands[1] = mem(TRICORE_REG_INVALID, ea, BYTE, TRICORE_EXT_SEXT_TRUNC);
            break;

        case TRICORE_INS_ST: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = A[a];
            t->operands[0] = mem(TRICORE_REG_INVALID, ea);
            t->operands[1] = getRegA(s1d);
            break;

        case 0x65: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, halfword) = D[a][31:16];
            t->operands[0] = mem(TRICORE_REG_INVALID, ea, HALFWORD);
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
    assert(i->size == 4);
}

void dismB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_B;
    t->op_count = 1;

    auto disp24 = bitRange<8, 15>(b) << 16 | bitRange<16, 31>(b);

    switch (i->id) {
//         case 0x6D:
//         case 0xED:
//         case 0x61: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = PC + sign_ext(2 * disp24); A[11] = ret_addr[31:0]; A[10] = EA[31:0];
//         case 0xE1: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = {disp24[23:20], 7'b0, disp24[19:0], 1'b0}; A[11] = ret_addr[31:0]; A[10] = EA[31:0]
        case TRICORE_INS_J32: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_JL: //A[11] = PC + 4; PC = PC + sign_ext(disp24) * 2;
            t->operands[0] = sExtImm<24>(disp24, 2);
            break;

        case TRICORE_INS_JA: //PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};
            t->operands[0] = tExtImm<24>(disp24);
            break;

        case TRICORE_INS_CALL32: // ... to long
            t->operands[0] = sExtImm<24>(disp24, 2);
            break;

        case TRICORE_INS_FCALL: // ... to long
            t->op_count = 3;
            t->operands[0] = mem(TRICORE_REG_A_10, tricore_op_imm(4, WORD, TRICORE_EXT_ZEXT_TRUNC));
            t->operands[1] = TRICORE_REG_A_11;
            t->operands[2] = sExtImm<24>(disp24, 2);
            break;

        default:
            assert(false && TRICORE_OF_B);
    }
}

void dismBIT(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BIT;
    t->op_count = 5;
    t->op2 = bitRange<21, 22>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto pos1 = bitRange<16, 20>(b);
    auto pos2 = bitRange<23, 27>(b);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_INST:
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            t->operands[3] = zExtImm<5>(pos1);
            t->operands[4] = zExtImm<5>(pos2);
            break;

        default:
            assert(false);
    }
}

void dismBO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BO;
    t->op_count = 4;
    t->op2 = bitRange<22, 27>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto off10 = (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));

    switch (i->id) {
        case TRICORE_INS_ST89:
            t->operands[0] = getRegA(s2); //A[b]
            t->operands[3] = sExtImm<10>(off10);
            switch (t->op2) {
                case 0x05: // EA = A[b]; M(EA, doubleword) = E[a]; A[b] = EA + sign_ext(off10);
                    t->operands[1] = memA(s2, DWORD);
                    t->operands[2] = {getRegD(s1d), true}; //E[a]
                    break;

                case 0x14: // EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
                    t->operands[1] = memA(s2, sExtImm<10>(off10));
                    t->operands[2] = getRegD(s1d); //D[a]
                    break;

                case 0x20: //EA = A[b] + sign_ext(off10); M(EA, byte) = D[a][7:0];
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE);
                    t->operands[2] = getRegD(s1d);
                    break;

                case 0x25: //EA = A[b] + sign_ext(off10); M(EA, doubleword) = E[a];
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD);
                    t->operands[2] = {getRegD(s1d), true};
                    break;

                case 0x26: // EA = A[b] + sign_ext(off10); M(EA, word) = A[a];
                    t->operands[1] = memA(s2, sExtImm<10>(off10));
                    t->operands[2] = getRegA(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_ST89);
            }
            break;

        case TRICORE_INS_LD09:
            t->op_count = 2;

            switch (t->op2) {
                case 0x05: // EA = A[b]; E[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
                    t->op_count = 4;
                    t->operands[0] = getRegA(s2); //A[b]
                    t->operands[1] = memA(s2, DWORD);
                    t->operands[2] = getRegD(s1d); t->operands[2].extended = true;
                    t->operands[3] = sExtImm<10>(off10);
                    break;

                case 0x16: // EA = A[b] + sign_ext(off10); A[a] = M(EA, word); A[b] = EA;
                    t->operands[0] = getRegA(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10));
                    break;

                case 0x20: // EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, byte));
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_SEXT_TRUNC);
                    break;

                case 0x21: //EA = A[b] + sign_ext(off10); D[a] = zero_ext(M(EA, byte));
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_ZEXT_TRUNC);
                    break;

                case 0x25: //EA = A[b] + sign_ext(off10); E[a] = M(EA, doubleword);
                    t->operands[0] = {getRegD(s1d), true};
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD);
                    break;

                default:
                    assert(false && TRICORE_INS_LD09);
            }
            break;

        default:
            assert(false && TRICORE_OF_BO);
    }
}

void dismBOL(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BOL;
    t->op_count = 2;

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto off16 = (bitRange<22, 27>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));

    switch (i->id) {
        case TRICORE_INS_STWA:  // EA = A[b] + sign_ext(off16); M(EA, word) = D[a];
            t->operands[0] = memA(s2, sExtImm<16>(off16));
            t->operands[1] = getRegD(s1d);
            break;

        case TRICORE_INS_LEA:   // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
            t->operands[0] = getRegA(s1d);
            t->operands[1] = memA(s2, sExtImm<16>(off16), WORD, TRICORE_EXT_THROW, true);
            break;

        case TRICORE_INS_LDW:   // EA = A[b] + sign_ext(off16); D[a] = M(EA, word);
            t->operands[0] = getRegD(s1d);
            t->operands[1] = memA(s2, sExtImm<16>(off16));
            break;

        case TRICORE_INS_ST_BA: //EA = A[b] + sign_ext(off16); M(EA, byte) = D[a][7:0];
            t->operands[0] = memA(s2, sExtImm<16>(off16), BYTE);
            t->operands[1] = getRegD(s1d);
            break;

        case TRICORE_INS_LD_BUD: //EA = A[b] + sign_ext(off16); D[a] = zero_ext(M(EA, byte));
            t->operands[0] = getRegD(s1d);
            t->operands[1] = memA(s2, sExtImm<16>(off16), BYTE, TRICORE_EXT_ZEXT_TRUNC);
            break;

        default:
            assert(false && TRICORE_OF_BOL);
    }
}

void dismBRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BRC;
    t->op_count = 3;
    t->op2 = b.test(31) ? 1 : 0;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const4 = bitRange<12, 15>(b);
    auto disp15 = bitRange<16, 30>(b);

    switch (i->id) {
        case TRICORE_INS_JEQ_15_c:  //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                                    //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegD(s1);
            t->operands[1] = sExtImm<4>(const4);
            t->operands[2] = sExtImm<15>(disp15);
            break;

//         case 0xFF:
//         case 0xBF:
//         case 0x9F:
        default:
            assert(false && TRICORE_OF_BRC);
    }
}

void dismBRN(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BRN;
    t->op_count = 2;
    t->op2 = b.test(31) ? 1 : 0;
    t->n = (b.test(7) ? 1 << 3 : 0) | bitRange<12, 15>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto disp15 = bitRange<16, 30>(b);

    switch (i->id) {
        case TRICORE_INS_JNZT: //if (D[a][n]) then PC = PC + sign_ext(disp15) * 2;
                               //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegD(s1);
            t->operands[1] = sExtImm<15>(disp15, 2);
            break;

        default:
            assert(false && TRICORE_OF_BRN);
    }
}

void dismBRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BRR;
    t->op_count = 3;
    t->op2 = b.test(31) ? 1 : 0;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto disp15 = bitRange<16, 30>(b);

    switch (i->id) {
        case TRICORE_INS_JEQA: // if (A[a] == A[b]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegA(s1);
            t->operands[1] = getRegA(s2);
            t->operands[2] = sExtImm<15>(disp15, 2);
            break;

        case TRICORE_INS_JLTD: //if (D[a] < D[b]) then PC = PC + sign_ext(disp15) * 2;
        case TRICORE_INS_JNEQ32: //if (D[a] != D[b]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = getRegD(s1);
            t->operands[1] = getRegD(s2);
            t->operands[2] = sExtImm<15>(disp15, 2);
            break;

        default:
            assert(false && TRICORE_OF_BRR);
    }
}

void dismRC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RC;
    t->op_count = 3;
    t->op2 = bitRange<21, 27>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const9 = bitRange<12, 20>(b);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_BIT_OPERATIONS1:
        case TRICORE_INS_CMP:
            // 0AH : D[c] = D[a] | zero_ext(const9);
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = zExtImm<9>(const9);
            break;

        case TRICORE_INS_MULE: //result = D[a] * sign_ext(const9); E[c] = result[63:0];
            t->operands[0] = {getRegD(d), true};
            t->operands[1] = getRegD(s1);
            t->operands[2] = sExtImm<9>(const9);
            break;

        default:
            assert(false && TRICORE_OF_RC);
    }
}

void dismRCPW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRCR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRCRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRCRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRLC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RLC;
    t->op_count = 2;

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const16 = bitRange<12, 27>(b);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
            t->operands[0] = getRegD(d);
            t->operands[1] = sExtImm<16>(const16);
            break;

        case TRICORE_INS_MOVU: //D[c] = zero_ext(const16);
            t->operands[0] = getRegD(d);
            t->operands[1] = zExtImm<16>(const16);
            break;

        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
            t->operands[0] = getRegD(d);
            t->operands[1] = tExtImm<16>(const16);
            break;

        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
            t->operands[0] = getRegA(d);
            t->operands[1] = tExtImm<16>(const16);
            break;

        case TRICORE_INS_MTCR: //CR[const16] = D[a];
            t->operands[0] = tricore_reg(const16.to_ulong());
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_MFCR: //D[c] = CR[const16];
            t->operands[0] = getRegD(d);
            t->operands[1] = tricore_reg(const16.to_ulong());
            break;

        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
            t->op_count = 3;
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = sExtImm<16>(const16);
            break;

        case TRICORE_INS_ADDIH_A: //A[c] = A[a] + {const16, 16’h0000};
            t->op_count = 3;
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = tExtImm<16>(const16);
            break;

        default:
            assert(false);
    }
}

void dismRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
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

        case TRICORE_INS_DIV:
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);

            switch (t->op2) {
                case 0x1A:
                    t->operands[0].extended = true;

                default:
                    break;
            }
            break;

        case TRICORE_INS_0B:
            switch (t->op2) {
                case 0x00: // result = D[a] + D[b]; D[c] = result[31:0];
                case 0x08: //SUBD result = D[a] - D[b]; D[c] = result[31:0];
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false && TRICORE_OF_RR);
    }
}

void dismRR1(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRR2(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    t->format = TRICORE_OF_RR2;
    t->op_count = 3;
    t->op2 = bitRange<16, 27>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_MULD: //result = D[a] * D[b]; // unsigned D[c] = suov(result, 32);
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);

            switch (t->op2) {
                case 0x6a: //result = D[a] * D[b]; E[c] = result[63:0];
                    t->operands[0].extended = true;
                    break;

                default:
                    break;
            }
            break;

        default:
            assert(false);
    }
}

void dismRRPW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RRPW;
    t->op_count = 5;
    t->op2 = bitRange<21, 22>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();
    auto width = bitRange<16, 20>(b);
    auto pos = bitRange<23, 27>(b);

    switch (i->id) {
        case TRICORE_INS_EXTR: //D[c] = sign_ext((D[a] >> pos)[width-1:0]); If pos + width > 32 or if width = 0, then the results are undefined.
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            t->operands[3] = zExtImm<5>(pos);
            t->operands[4] = zExtImm<5>(width);
            break;

        default:
            assert(false);
    }
}

void dismRRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RRR;
    t->op_count = 4;
    t->op2 = bitRange<20, 23>(b).to_ulong();
    t->n = bitRange<16, 17>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto s3 = bitRange<24, 27>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_DVSTEP:
            switch (t->op2) {
                case 0x03:
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s3);
                    t->operands[2] = getRegD(s1);
                    break;

                default:
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s2);
                    t->operands[2] = {getRegD(s3), true};
            }
            break;

        default:
            assert(false);
    }
}

void dismRRR1(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);

}

void dismRRR2(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRRRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRRRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {

}

void dismSYS(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    //not implemented
    //TRICORE_INS_ISYNC;
}

static std::map<std::size_t, void (*)(cs_tricore* t, cs_insn* i, const std::bitset<64>& b)> insToDism = {
    {TRICORE_INS_CALL16, &dismSB},
    {TRICORE_INS_J16, &dismSB},
    {TRICORE_INS_JNZ_D15, &dismSB},
    {TRICORE_INS_JZ_D15, &dismSB},

    {TRICORE_INS_LOOP, &dismSBR},
    {TRICORE_INS_JZD, &dismSBR},
    {TRICORE_INS_JZA_16, &dismSBR},
    {TRICORE_INS_JLEZD, &dismSBR},
    {TRICORE_INS_JGEZD, &dismSBR},

    {TRICORE_INS_ANDD15, &dismSC},
    {TRICORE_INS_SUBA10, &dismSC},
    {TRICORE_INS_MOVD15, &dismSC},

    {TRICORE_INS_LDA_PINC, &dismSLR},
    {TRICORE_INS_LDD, &dismSLR},
    {TRICORE_INS_LDD_PINC, &dismSLR},
    {TRICORE_INS_LD_HD_PINC, &dismSLR},
    {TRICORE_INS_LD16A, &dismSLR},

    {TRICORE_INS_LDA, &dismSLRO},

    {0x00, &dismSR}, //TRICORE_INS_NOP, TRICORE_INS_RET
    {TRICORE_INS_JIA, &dismSR},

    {TRICORE_INS_ADDA, &dismSRC},
    {TRICORE_INS_MOVA, &dismSRC},
    {TRICORE_INS_ADDD_c, &dismSRC},
    {TRICORE_INS_MOVD, &dismSRC},
    {TRICORE_INS_SHAD, &dismSRC},
    {TRICORE_INS_SHD, &dismSRC},

    {TRICORE_INS_ADDSCA, &dismSRRS},

    {TRICORE_INS_MOVAA, &dismSRR},
    {TRICORE_INS_MOVAD, &dismSRR},
    {TRICORE_INS_MOVDA, &dismSRR},
    {TRICORE_INS_MOVDD, &dismSRR},
    {TRICORE_INS_ORD, &dismSRR},
    {TRICORE_INS_ANDD, &dismSRR},
    {TRICORE_INS_SUBD, &dismSRR},
    {TRICORE_INS_ADDDD, &dismSRR},
    {TRICORE_INS_SUBD15, &dismSRR},
    {TRICORE_INS_CMOVD, &dismSRR},
    {TRICORE_INS_MULD2, &dismSRR},

    {TRICORE_INS_LD_BUD15, &dismSRO},
    {TRICORE_INS_LD_HD, &dismSRO},

    {TRICORE_INS_STA, &dismSSR},
    {TRICORE_INS_STB, &dismSSR},
    {TRICORE_INS_STD, &dismSSR},
    {TRICORE_INS_STW, &dismSSR},
    {TRICORE_INS_STHW, &dismSSR},

    {TRICORE_INS_STBA, &dismSSRO},

    {TRICORE_INS_ST, &dismABS},
    {TRICORE_INS_LD, &dismABS},

    {TRICORE_INS_J32, &dismB},
    {TRICORE_INS_JL, &dismB},
    {TRICORE_INS_JA, &dismB},
    {TRICORE_INS_CALL32, &dismB},
    {TRICORE_INS_FCALL, &dismB},

    {TRICORE_INS_INST, &dismBIT},

    {TRICORE_INS_ST89, &dismBO},
    {TRICORE_INS_LD09, &dismBO},

    {TRICORE_INS_STWA, &dismBOL},
    {TRICORE_INS_LEA, &dismBOL},
    {TRICORE_INS_LDW, &dismBOL},
    {TRICORE_INS_ST_BA, &dismBOL},
    {TRICORE_INS_LD_BUD, &dismBOL},

    {TRICORE_INS_JEQ_15_c, &dismBRC},

    {TRICORE_INS_JNZT, &dismBRN},

    {TRICORE_INS_JEQA, &dismBRR},
    {TRICORE_INS_JLTD, &dismBRR},
    {TRICORE_INS_JNEQ32, &dismBRR},

    {TRICORE_INS_BIT_OPERATIONS1, &dismRC},
    {TRICORE_INS_CMP, &dismRC},
    {TRICORE_INS_MULE, &dismRC},

    {TRICORE_INS_MOVD_C16, &dismRLC},
    {TRICORE_INS_MOVU, &dismRLC},
    {TRICORE_INS_MOVH, &dismRLC},
    {TRICORE_INS_MOVH_A, &dismRLC},
    {TRICORE_INS_MTCR, &dismRLC},
    {TRICORE_INS_MFCR, &dismRLC},
    {TRICORE_INS_ADDI, &dismRLC},
    {TRICORE_INS_ADDIH_A, &dismRLC},

    {TRICORE_INS_BIT_OPERATIONS2, &dismRR},
    {TRICORE_INS_DIV, &dismRR},
    {TRICORE_INS_0B, &dismRR},

    {TRICORE_INS_MULD, &dismRR2},

    {TRICORE_INS_EXTR, &dismRRPW},

    {TRICORE_INS_DVSTEP, &dismRRR},

    {TRICORE_INS_ISYNC, &dismSYS},

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
