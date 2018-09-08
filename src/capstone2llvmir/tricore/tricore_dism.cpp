#include "retdec/capstone2llvmir/tricore/tricore.h"

#include <iostream>

/**
 * @src https://stackoverflow.com/questions/17857596/how-to-convert-a-range-subset-of-bits-in-a-c-bitset-to-a-number
 */
// drop bits outside the range [R, L) == [R, L]
template<std::size_t R, std::size_t L, std::size_t N>
std::bitset<N> bitRange(std::bitset<N> b) {
    if (R > L - 1 || L - 1 >= N) {
        assert(false);
    }

    b <<= (N - L - 1);
    b >>= (N - L + R - 1); // shift to lsb

    return b;
};

tricore_reg getRegD(unsigned int n) {
    return tricore_reg(TRICORE_REG_D_0 + n*4);
}

tricore_reg getRegA(unsigned int n) {
    return tricore_reg(TRICORE_REG_A_0 + n*4);
}

cs_tricore_op getRegE(unsigned int n) {
    return retdec::capstone2llvmir::Capstone2LlvmIrTranslatorTricore::regToExtendedReg(getRegD(n));
}

cs_tricore_op getRegP(unsigned int n) {
    return retdec::capstone2llvmir::Capstone2LlvmIrTranslatorTricore::regToExtendedReg(getRegA(n));
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
        case 24: return (((bitRange<20, 23>(b) << 28) | (bitRange<0, 19>(b))) << 1).to_ulong();
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
    return tricore_op_imm(sExt<size>(b, mult2), size + (mult2 / 2), TRICORE_EXT_SEXT_TRUNC);
}

template<std::size_t size, std::size_t N>
tricore_op_imm zExtImm(std::bitset<N> b, uint8_t mult2 = 1) {
    return tricore_op_imm(zExt<>(b, mult2), size + (mult2 / 2), TRICORE_EXT_ZEXT_TRUNC);
}

template<std::size_t size, std::size_t N>
tricore_op_imm tExtImm(std::bitset<N> b) {
    return tricore_op_imm(tExt<size>(b), 32, TRICORE_EXT_THROW);
}

tricore_op_mem mem(tricore_reg n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return tricore_op_mem(n, tricore_op_imm(0), size, ext, op);
}

tricore_op_mem mem(tricore_reg n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return tricore_op_mem(n, disp, size, ext, op);
}

tricore_op_mem memA(uint64_t n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return mem(getRegA(n), size, ext, op);
}

tricore_op_mem memA(uint64_t n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return mem(getRegA(n), disp, size, ext, op);
}

tricore_op_mem memD(uint64_t n, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return mem(getRegD(n), size, ext, op);
}

tricore_op_mem memD(uint64_t n, tricore_op_imm disp, uint8_t size = WORD, tricore_ext ext = TRICORE_EXT_THROW, tricore_mem_op op = TRICORE_MEM_OP_NOTHING) {
    return mem(getRegD(n), disp, size, ext, op);
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
        case TRICORE_INS_CALL16:        //to long...
        case TRICORE_INS_J16:           // PC = PC + sign_ext(disp8) * 2;
            t->operands[0] = sExtImm<8>(disp8, 2);
            break;

        case TRICORE_INS_JNZ_D15:       // if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
        case TRICORE_INS_JZ_D15:        // if (D[15] == 0) then PC = PC + sign_ext(disp8) * 2;
            t->op_count = 2;
            t->operands[0] = sExtImm<8>(disp8, 2);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        default:
            assert(false && TRICORE_OF_SB);
    }
}

void dismSBC(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SBC;
    t->op_count = 3;

    auto disp4 = bitRange<8, 11>(b);
    auto const4 = bitRange<12, 15>(b);

    switch (i->id) {
        case TRICORE_INS_JNE16_D15: //if (D[15] != sign_ext(const4)) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JEQ16_D15: //if (D[15] == sign_ext(const4)) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = zExtImm<4>(disp4, 2);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = sExtImm<4>(const4);
            break;

        default:
            assert(false);
    }
}

void dismSBR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SBR;
    t->op_count = 2;

    auto disp4 = bitRange<8, 11>(b);
    auto s2 = bitRange<12, 15>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_LOOP16: // if (A[b] != 0) then PC = PC + {27b’111111111111111111111111111, disp4, 0}; A[b] = A[b] - 1;
            t->operands[0] = tExtImm<4>(disp4);
            t->operands[1] = getRegA(s2);
            break;

        case TRICORE_INS_JZD: // if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JLEZD: // If (D[b] <= 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JGEZD: //if (D[b] >= 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JGTZ: //if (D[b] > 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JNZ16: //if (D[b] != 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JLTZ16: //if (D[b] < 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = zExtImm<4>(disp4, 2);
            t->operands[1] = getRegD(s2);
            break;

        case TRICORE_INS_JNZA_16: //if (A[b] != 0) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JZA_16: //if (A[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = zExtImm<4>(disp4, 2);
            t->operands[1] = getRegA(s2);
            break;

        case TRICORE_INS_JEQ16: //if (D[15] == D[b]) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JNE_16_z_r: //if (D[15] != D[b]) then PC = PC + zero_ext(disp4) * 2;
            t->op_count = 3;
            t->operands[0] = zExtImm<4>(disp4, 2);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = getRegD(s2);
            break;

        default:
            assert(false && TRICORE_OF_SBR);
    }
}

void dismSBRN(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 2);
    t->format = TRICORE_OF_SBRN;
    t->op_count = 2;
    t->n = bitRange<12, 15>(b).to_ulong();

    auto disp4 = bitRange<8, 11>(b);

    switch (i->id) {
        case TRICORE_INS_JZT_16: //if (!D[15][n]) then PC = PC + zero_ext(disp4) * 2;
        case TRICORE_INS_JNZT_16: //if (D[15][n]) then PC = PC + zero_ext(disp4) * 2;
            t->operands[0] = zExtImm<4>(disp4, 2);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        default:
            assert(false);
    }
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

        case TRICORE_INS_BISR16: //tmp_FCX = FCX;
            t->op_count = 0;
            break;

        case TRICORE_INS_SUBA10: //A[10] = A[10] - zero_ext(const8);
            t->operands[0] = TRICORE_REG_A_10;
            t->operands[1] = zExtImm<8>(const8);
            break;

        case TRICORE_INS_MOVD15: //D[15] = zero_ext(const8);
        case TRICORE_INS_OR16_D15: //D[15] = D[15] | zero_ext(const8);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = zExtImm<8>(const8);
            break;

        case TRICORE_INS_ST16_D15_A10: //M(A[10] + zero_ext(4 * const8), word) = D[15];
            t->operands[0] = mem(TRICORE_REG_A_10, zExtImm<8>(const8, 4));
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case TRICORE_INS_ST_A10_A15: //M(A[10] + zero_ext(4 * const8), word) = A[15];
            t->operands[0] = mem(TRICORE_REG_A_10, zExtImm<8>(const8, 4));
            t->operands[1] = TRICORE_REG_A_15;
            break;

        case TRICORE_INS_LD16_D15_A10: //D[15] = M(A[10] + zero_ext(4 * const8), word);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = mem(TRICORE_REG_A_10, zExtImm<8>(const8, 4));
            break;

        case TRICORE_INS_LDA16_A15: //A[15] = M(A[10] + zero_ext(4 * const8), word);
            t->operands[0] = TRICORE_REG_A_15;
            t->operands[1] = mem(TRICORE_REG_A_10, zExtImm<8>(const8, 4));
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

        case TRICORE_INS_LDHW16: //D[c] = sign_ext(M(A[b], halfword));
        case TRICORE_INS_LD_HD_PINC: //D[c] = sign_ext(M(A[b], half-word));  A[b] = A[b] + 2;
            t->operands[0] = getRegD(d);
            t->operands[1] = memA(s2, HWORD, TRICORE_EXT_SEXT_TRUNC);
            break;

        case TRICORE_INS_LDB_D_A: //D[c] = zero_ext(M(A[b], byte));
        case TRICORE_INS_LDB_PINC: //D[c] = zero_ext(M(A[b], byte)); A[b] = A[b] + 1;
            t->operands[0] = getRegD(d);
            t->operands[1] = memA(s2, BYTE, TRICORE_EXT_ZEXT_TRUNC);
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

        case TRICORE_INS_LDHW16_REL: //D[c] = sign_ext(M(A[15] + zero_ext(2 * off4), half-word));
            t->operands[0] = getRegD(d);
            t->operands[1] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 2), HWORD, TRICORE_EXT_SEXT_TRUNC);
            break;

        case TRICORE_INS_LDW16: //D[c] = M(A[15] + zero_ext(4 * off4), word);
            t->operands[0] = getRegD(d);
            t->operands[1] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 4));
            break;

        case TRICORE_INS_LDB_REL: //D[c] = zero_ext(M(A[15] + zero_ext(off4), byte));
            t->operands[0] = getRegD(d);
            t->operands[1] = mem(TRICORE_REG_A_15, zExtImm<4>(off4), BYTE, TRICORE_EXT_ZEXT_TRUNC);
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
                case 0x08: //RFE //TODO?
                case 0x09: //RET
                case 0x0A: //DEBUG
                    break;

                default:
                    assert(false && "Unknown op2 for 0x00 ins");
            }
            break;

        case TRICORE_INS_NOT16:
            switch (t->op2) {
                case 0x00:
                    t->operands[0] = getRegD(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_NOT16);
            }
            break;

        case TRICORE_INS_RSUBD: //result = 0 - D[a]; D[a] = result[31:0];
            switch (t->op2) {
                case 0x00: //sat_neg = (D[a] < -80 H ) ? -80 H : D[a]; D[a] = (sat_neg > 7F H ) ? 7F H : sat_neg;
                case 0x01: //D[a] = (D[a] > FF H ) ? FF H : D[a]; // unsigned comparison
                case 0x02: //sat_neg = (D[a] < -8000 H ) ? -8000 H : D[a]; D[a] = (sat_neg > 7FFF H ) ? 7FFF H : sat_neg;
                case 0x03: //D[a] = (D[a] > FFFF H ) ? FFFF H : D[a]; // unsigned comparison
                case 0x05: //result = 0 - D[a]; D[a] = result[31:0];
                    t->operands[0] = getRegD(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_RSUBD);
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

        case TRICORE_INS_CADD16: //condition = (D[15] != 0); result = ((condition) ? D[a] + sign_ext(const4) : D[a]); D[a] = result[31:0];
            t->op_count = 3;
            t->operands[0] = getRegD(s1d);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = sExtImm<4>(const4);
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

        case TRICORE_INS_EQ16: //result = (D[a] == sign_ext(const4)); D[15] = zero_ext(result);
        case TRICORE_INS_ADD16_D15: //result = D[a] + sign_ext(const4); D[15] = result[31:0];
            t->op_count = 3;
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = getRegD(s1d);
            t->operands[2] = sExtImm<4>(const4);
            break;

        case TRICORE_INS_ADD16_D15_c: //result = D[15] + sign_ext(const4); D[a] = result[31:0];
        case TRICORE_INS_CMOVN16: //D[a] = ((D[15] == 0) ? sign_ext(const4) : D[a]);
        case TRICORE_INS_CMOVD_SRC: //D[a] = ((D[15] != 0) ? sign_ext(const4) : D[a]);
            t->op_count = 3;
            t->operands[0] = getRegD(s1d);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = sExtImm<4>(const4);
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

    switch (i->id) {
        case TRICORE_INS_LD16_A15: //A[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_A_15;
            t->operands[1] = memA(s2, zExtImm<4>(off4, 4));
            break;

        case TRICORE_INS_LD_BUD15: //D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = memA(s2, zExtImm<4>(off4), BYTE, TRICORE_EXT_ZEXT_TRUNC);
            break;

        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = memA(s2, zExtImm<4>(off4, 2), HWORD, TRICORE_EXT_SEXT_TRUNC);
            break;

        case TRICORE_INS_LDD15: //D[15] = M(A[b] + zero_ext(4 * off4), word);
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = memA(s2, zExtImm<4>(off4, 4));
            break;

        case TRICORE_INS_STA_16: //M(A[b] + zero_ext(4 * off4), word) = A[15];
            t->operands[0] = memA(s2, zExtImm<4>(off4, 4));
            t->operands[1] = TRICORE_REG_A_15;
            break;

        case TRICORE_INS_STB16: //M(A[b] + zero_ext(off4), byte) = D[15][7:0];
            t->operands[0] = memA(s2, zExtImm<4>(off4), BYTE);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case TRICORE_INS_STHW16_D15: //M(A[b] + zero_ext(2 * off4), half-word) = D[15][15:0];
            t->operands[0] = memA(s2, zExtImm<4>(off4, 2), HWORD);
            t->operands[1] = TRICORE_REG_D_15;
            break;

        case TRICORE_INS_S16_D15: //M(A[b] + zero_ext(4 * off4), word) = D[15];
            t->operands[0] = memA(s2, zExtImm<4>(off4, 4));
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
        case TRICORE_INS_ADD16_D15_DD: //result = D[a] + D[b]; D[15] = result[31:0];
        case TRICORE_INS_EQ16_D15: //result = (D[a] == D[b]); D[15] = zero_ext(result);
            t->op_count = 3;
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = getRegD(s1d);
            t->operands[2] = getRegD(s2);
            break;

        case TRICORE_INS_ADD16:
            t->op_count = 3;
            t->operands[0] = getRegD(s1d);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = getRegD(s2);
            break;

        case TRICORE_INS_ADD16_AA: //A[a] = A[a] + A[b];
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

        case TRICORE_INS_ADD16_SSOV: //result = D[a] + D[b]; D[a] = ssov(result, 32);
        case TRICORE_INS_MOVDD: //D[a] = D[b];
        case TRICORE_INS_ORD: //D[a] = D[a] | D[b];
        case TRICORE_INS_ANDD: //D[a] = D[a] & D[b];
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
        case TRICORE_INS_ADDDD: // result = D[a] + D[b]; D[a] = result[31:0];
        case TRICORE_INS_MULD2: //result = D[a] * D[b]; D[a] = result[31:0];
        case TRICORE_INS_XOR16: //D[a] = D[a] ^ D[b];
            t->operands[0] = getRegD(s1d);
            t->operands[1] = getRegD(s2);
            break;

        case TRICORE_INS_SUBD15: //result = D[a] - D[b]; D[15] = result[31:0];
            t->op_count = 3;
            t->operands[0] = TRICORE_REG_D_15;
            t->operands[1] = getRegD(s1d);
            t->operands[2] = getRegD(s2);
            break;

        case TRICORE_INS_CMOVD: //D[a] = ((D[15] != 0) ? D[b] : D[a]);
        case TRICORE_INS_CMOVD_D15: //D[a] = ((D[15] == 0) ? D[b] : D[a]);
        case TRICORE_INS_SUBD1516: //result = D[15] - D[b]; D[a] = result[31:0];
            t->op_count = 3;
            t->operands[0] = getRegD(s1d);
            t->operands[1] = TRICORE_REG_D_15;
            t->operands[2] = getRegD(s2);
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
        case TRICORE_INS_ADDSCA16: //A[a] = (A[b] + (D[15] << n));
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

    switch (i->id) {
        case TRICORE_INS_STA: //M(A[b], word) = A[a];
            t->operands[0] = memA(s2);
            t->operands[1] = getRegA(s1);
            break;

        case TRICORE_INS_STB_PINC: // M(A[b], byte) = D[a][7:0]; A[b] = A[b] + 1;
        case TRICORE_INS_STB: //M(A[b], byte) = D[a][7:0];
            t->operands[0] = memA(s2, BYTE);
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_STD: //M(A[b], word) = D[a];
        case TRICORE_INS_ST_PINC: //M(A[b], word) = D[a]; A[b] = A[b] + 4;
            t->operands[0] = memA(s2);
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_STHW: //M(A[b], half-word) = D[a][15:0]; A[b] = A[b] + 2;
        case TRICORE_INS_STHW16: //M(A[b], half-word) = D[a][15:0];
            t->operands[0] = memA(s2, HWORD);
            t->operands[1] = getRegD(s1);
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

        case TRICORE_INS_STHW16_A15: //M(A[15] + zero_ext(2 * off4), half-word) = D[a][15:0];
            t->operands[0] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 2), HWORD);
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_ST16_A15_D: //M(A[15] + zero_ext(4 * off4), word) = D[a];
            t->operands[0] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 4));
            t->operands[1] = getRegD(s1);
            break;

        case TRICORE_INS_ST16_A15_A: //M(A[15] + zero_ext(4 * off4), word) = A[a];
            t->operands[0] = mem(TRICORE_REG_A_15, zExtImm<4>(off4, 4));
            t->operands[1] = getRegA(s1);
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
                    t->operands[0] = getRegE(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, DWORD);
                    break;

                case 0x03: //EA = {off18[17:14], 14b'0, off18[13:0]}; P[a] = M(EA, doubleword);
                    t->operands[0] = getRegP(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, DWORD);
                    break;

                default:
                    assert(false && TRICORE_INS_LD);
            }
            break;

        case TRICORE_INS_LEA_ABS: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = EA[31:0];
            switch (t->op2) {
                case 0x00:
                    t->operands[0] = getRegA(s1d);
                    t->operands[1] = ea;
                    break;

                default:
                    assert(false && TRICORE_INS_LEA_ABS);
            }
            break;

        case TRICORE_INS_LDB: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = sign_ext(M(EA, byte));
            switch (t->op2) {
                case 0x00:
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, BYTE, TRICORE_EXT_SEXT_TRUNC);
                    break;

                case 0x01:
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, BYTE, TRICORE_EXT_ZEXT_TRUNC);
                    break;

                case 0x02:
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, HWORD, TRICORE_EXT_SEXT_TRUNC);
                    break;

                case 0x03:
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = mem(TRICORE_REG_INVALID, ea, HWORD, TRICORE_EXT_ZEXT_TRUNC);
                    break;

                default:
                    assert(false && TRICORE_INS_LDB);
            }
            break;

        case TRICORE_INS_ST:
            switch (t->op2) {
                case 0x00: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, word) = D[a];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x01: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, doubleword) = E[a];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea);
                    t->operands[1] = getRegE(s1d);
                    break;

                case 0x02: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = A[a];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea);
                    t->operands[1] = getRegA(s1d);
                    break;

                case 0x03: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, doubleword) = P[a];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea);
                    t->operands[1] = getRegP(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_ST);
            }
            break;

        case TRICORE_INS_STHW_Q: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, halfword) = D[a][31:16];
            switch (t->op2) {
                case 0x00:
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea, HWORD, TRICORE_EXT_TRUNC_H);
                    t->operands[1] = getRegD(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_STHW_Q);
            }
            break;

        case TRICORE_INS_STB_ABS:
            switch (t->op2) {
                case 0x00: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, byte) = D[a][7:0];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea, BYTE);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x02: //EA = {off18[17:14], 14b'0, off18[13:0]}; M(EA, halfword) = D[a][15:0];
                    t->operands[0] = mem(TRICORE_REG_INVALID, ea, HWORD);
                    t->operands[1] = getRegD(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_STB_ABS);
            }
            break;

        default:
            assert(false && TRICORE_OF_ABS);
    }
}

void dismABSB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_ABSB;
    t->op_count = 1;
    t->op2 = bitRange<26, 27>(b).to_ulong();

    auto bitb = b.test(11) ? 1 : 0;
    auto bpos3 = bitRange<8, 10>(b);
    auto off18 = (bitRange<12, 15>(b) << 14) | (bitRange<22, 25>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));

    switch (i->id) {
        case TRICORE_INS_ST_BIT:
            switch (t->op2) {
                case 0x00:
                    t->operands[0] = mem(TRICORE_REG_INVALID, tExtImm<18>(off18), BYTE);
                    t->operands[1] = tricore_op_imm(bitb, 1, TRICORE_EXT_ZEXT_TRUNC);
                    t->operands[2] = zExtImm<3>(bpos3);
                    break;

                default:
                    assert(false && TRICORE_INS_ST_BIT);
            }
            break;

        default:
            assert(false);
    }
}

void dismB(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_B;
    t->op_count = 1;

    auto disp24 = bitRange<8, 15>(b) << 16 | bitRange<16, 31>(b);

    switch (i->id) {
        case TRICORE_INS_J32: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_JL: //A[11] = PC + 4; PC = PC + sign_ext(disp24) * 2;
            t->operands[0] = sExtImm<24>(disp24, 2);
            break;

        case TRICORE_INS_JA: //PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};
            t->operands[0] = tExtImm<24>(disp24);
            break;

        case TRICORE_INS_CALL32: // ... to long
        case TRICORE_INS_CALLABS: // ... to long
            t->operands[0] = sExtImm<24>(disp24, 2);
            break;

        case TRICORE_INS_FCALL: // ... to long
            t->op_count = 3;
            t->operands[0] = mem(TRICORE_REG_SP, tricore_op_imm(4, WORD, TRICORE_EXT_ZEXT_TRUNC), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_LEA);
            t->operands[1] = TRICORE_REG_RA;
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
            switch (t->op2) {
                case 0x00:
                case 0x01:
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    t->operands[3] = zExtImm<5>(pos1);
                    t->operands[4] = zExtImm<5>(pos2);
                    break;

                default:
                    assert(false && TRICORE_INS_INST);
            }

        case TRICORE_INS_NAND:
            switch (t->op2) {
                case 0x00: //result = !(D[a][pos1] AND D[b][pos2]); D[c] = zero_ext(result);
                case 0x01: //result = D[a][pos1] OR !D[b][pos2]; D[c] = zero_ext(result);
                case 0x02: //result = !(D[a][pos1] XOR D[b][pos2]); D[c] = zero_ext(result);
                case 0x03: //result = D[a][pos1] XOR D[b][pos2]; D[c] = zero_ext(result);
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    t->operands[3] = zExtImm<5>(pos1);
                    t->operands[4] = zExtImm<5>(pos2);
                    break;

                default:
                    assert(false && TRICORE_INS_NAND);
            }
            break;

        case TRICORE_INS_NAND_NOR:
            switch (t->op2) {
                case 0x00: //result = D[a][pos1] AND D[b][pos2]; D[c] = zero_ext(result);
                case 0x01: //result = D[a][pos1] OR D[b][pos2]; D[c] = zero_ext(result);
                case 0x02: //result = !(D[a][pos1] OR D[b][pos2]); D[c] = zero_ext(result);
                case 0x03: //result = D[a][pos1] AND !D[b][pos2]; D[c] = zero_ext(result);
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    t->operands[3] = zExtImm<5>(pos1);
                    t->operands[4] = zExtImm<5>(pos2);
                    break;

                default:
                    assert(false && TRICORE_INS_NAND_NOR);
            }
            break;

        default:
            assert(false);
    }
}

void dismBO(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_BO;
    t->op_count = 2;
    t->op2 = bitRange<22, 27>(b).to_ulong();

    auto s1d = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto off10 = (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));

    switch (i->id) {
        case TRICORE_INS_ST89:
            switch (t->op2) {
                case 0x00: //EA = A[b]; M(EA, byte) = D[a][7:0]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x02: //EA = A[b]; M(EA, halfword) = D[a][15:0]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x04: //EA = A[b]; M(EA, word) = D[a]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x05: // EA = A[b]; M(EA, doubleword) = E[a]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegE(s1d);
                    break;

                case 0x06: //EA = A[b]; M(EA, word) = A[a]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegA(s1d);
                    break;

                case 0x07: //EA = A[b]; M(EA, doubleword) = P[a]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegP(s1d);
                    break;

                case 0x08: //EA = A[b]; M(EA, halfword) = D[a][31:16]; A[b] = EA + sign_ext(off10);
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x10: //EA = A[b] + sign_ext(off10); M(EA, byte) = D[a][7:0]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x12: //EA = A[b] + sign_ext(off10); M(EA, halfword) = D[a][15:0]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_TRUNC_L, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x14: //EA = A[b] + sign_ext(off10); M(EA, word) = D[a]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x15: //EA = A[b] + sign_ext(off10); M(EA, doubleword) = E[a]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegE(s1d);
                    break;

                case 0x16: //EA = A[b] + sign_ext(off10); M(EA, word) = A[a]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegA(s1d);
                    break;

                case 0x17: //EA = A[b] + sign_ext(off10); M(EA, doubleword) = P[a]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegP(s1d);
                    break;

                case 0x18: //EA = A[b] + sign_ext(off10); M(EA, halfword) = D[a][31:16]; A[b] = EA;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_TRUNC_H, TRICORE_MEM_OP_PREINC);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x20: //EA = A[b] + sign_ext(off10); M(EA, byte) = D[a][7:0];
                    t->op_count = 2;
                    t->operands[0] = memA(s2, sExtImm<10>(off10), BYTE);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x22: //EA = A[b] + sign_ext(off10); M(EA, halfword) = D[a][15:0];
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_TRUNC_L);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x28: //EA = A[b] + sign_ext(off10); M(EA, halfword) = D[a][31:16];
                    t->operands[0] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_TRUNC_H);
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x24: //EA = A[b] + sign_ext(off10); M(EA, word) = D[a];
                    t->operands[0] = memA(s2, sExtImm<10>(off10));
                    t->operands[1] = getRegD(s1d);
                    break;

                case 0x25: //EA = A[b] + sign_ext(off10); M(EA, doubleword) = E[a];
                    t->operands[0] = memA(s2, sExtImm<10>(off10), DWORD);
                    t->operands[1] = getRegE(s1d);
                    break;

                case 0x26: // EA = A[b] + sign_ext(off10); M(EA, word) = A[a];
                    t->operands[0] = memA(s2, sExtImm<10>(off10));
                    t->operands[1] = getRegA(s1d);
                    break;

                default:
                    assert(false && TRICORE_INS_ST89);
            }
            break;

        case TRICORE_INS_LD09:
            switch (t->op2) {
                case 0x00: // EA = A[b]; D[a] = sign_ext(M(EA, byte)); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_SEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x01: // EA = A[b]; D[a] = zero_ext(M(EA, byte)); A[b] = EA + sign_ext(off10)
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x02: //EA = A[b]; D[a] = sign_ext(M(EA, halfword)); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_SEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x03: //EA = A[b]; D[a] = zero_ext(M(EA, halfword)); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x04: //EA = A[b]; D[a] = M(EA, word); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x05: // EA = A[b]; E[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegE(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x06: //EA = A[b]; A[a] = M(EA, word); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegA(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x07: //EA = A[b]; P[a] = M(EA, doubleword); A[b] = EA + sign_ext(off10);
                    t->operands[0] = getRegP(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_POSTINC);
                    break;

                case 0x11: // EA = A[b] + sign_ext(off10); D[a] = zero_ext(M(EA, byte)); A[b] = EA;
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), BYTE, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x12: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, halfword)); A[b] = EA;
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_SEXT_TRUNC, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x13: //EA = A[b] + sign_ext(off10); D[a] = zero_ext(M(EA, halfword)); A[b] = EA;
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_ZEXT_TRUNC, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x14: //EA = A[b] + sign_ext(off10); D[a] = M(EA, word); A[b] = EA;
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x15: // EA = A[b] + sign_ext(off10); E[a] = M(EA, doubleword); A[b] = EA;
                    t->operands[0] = getRegE(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x16: // EA = A[b] + sign_ext(off10); A[a] = M(EA, word); A[b] = EA;
                    t->operands[0] = getRegA(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x17: //EA = A[b] + sign_ext(off10); P[a] = M(EA, doubleword); A[b] = EA;
                    t->operands[0] = getRegP(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_PREINC);
                    break;

                case 0x26: // EA = A[b] + sign_ext(off10); A[a] = M(EA, word);
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

                case 0x22: //EA = A[b] + sign_ext(off10); D[a] = sign_ext(M(EA, halfword));
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_SEXT_TRUNC);
                    break;

                case 0x23: //EA = A[b] + sign_ext(off10); D[a] = zero_ext(M(EA, halfword));
                    t->operands[0] = getRegD(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), HWORD, TRICORE_EXT_ZEXT_TRUNC);
                    break;

                case 0x25: //EA = A[b] + sign_ext(off10); E[a] = M(EA, doubleword);
                    t->operands[0] = getRegE(s1d);
                    t->operands[1] = memA(s2, sExtImm<10>(off10), DWORD);
                    break;

                case 0x27: //EA = A[b] + sign_ext(off10); P[a] = M(EA, doubleword);
                    t->operands[0] = getRegP(s1d);
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
            t->operands[1] = memA(s2, sExtImm<16>(off16), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_LEA);
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

        case TRICORE_INS_LDA_OFF: //EA = A[b] + sign_ext(off16); A[a] = M(EA, word);
            t->operands[0] = getRegA(s1d);
            t->operands[1] = memA(s2, sExtImm<16>(off16));
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
        case TRICORE_INS_JEQ32:
            switch (t->op2) {
                case 0x00: //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                case 0x01: //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    t->operands[0] = sExtImm<15>(disp15, 2);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = sExtImm<4>(const4);
                    break;

                default:
                    assert(false && TRICORE_INS_JEQ32);
            }
            break;

        case TRICORE_INS_JGE:
            t->operands[0] = sExtImm<15>(disp15, 2);
            t->operands[1] = getRegD(s1);

            switch (t->op2) {
                case 0x00: //if (D[a] >= sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    t->operands[2] = sExtImm<4>(const4);
                    break;

                case 0x01: //if (D[a] >= zero_ext(const4)) then { // unsigned comparison PC = PC + sign_ext(disp15) * 2; }
                    t->operands[2] = zExtImm<4>(const4);
                    break;

                default:
                    assert(false && TRICORE_INS_JGE);
            }
            break;

        case TRICORE_INS_JLT: //if (D[a] < sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = sExtImm<15>(disp15, 2);
            t->operands[1] = getRegD(s1);

            switch (t->op2) {
                case 0x00: //if (D[a] < sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    t->operands[2] = sExtImm<4>(const4);
                    break;

                case 0x01: //if (D[a] < zero_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                    t->operands[2] = zExtImm<4>(const4);
                    break;

                default:
                    assert(false && TRICORE_INS_JLT);
            }
            break;

        case TRICORE_INS_JNE_INC_DEC:
            switch (t->op2) {
                case 0x00: // if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; D[a] = D[a] + 1; The increment is unconditional.
                case 0x01: // if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; D[a] = D[a] - 1; The decrement is unconditional.
                    t->operands[0] = sExtImm<15>(disp15, 2);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = sExtImm<4>(const4);
                    break;

                default:
                    assert(false && TRICORE_INS_JNE_INC_DEC);
            }
            break;

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
        case TRICORE_INS_JNZT:
            switch (t->op2) {
                case 0x00: //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
                case 0x01: //if (D[a][n]) then PC = PC + sign_ext(disp15) * 2;
                    t->operands[0] = sExtImm<15>(disp15, 2);
                    t->operands[1] = getRegD(s1);
                    break;

                default:
                    assert(false && TRICORE_INS_JNZT);
            }
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
        case TRICORE_INS_JZ: //if (A[a] != 0) then PC = PC + sign_ext(disp15) * 2;
            t->op_count = 2;
            t->operands[0] = sExtImm<15>(disp15, 2);
            t->operands[1] = getRegA(s1);
            break;

        case TRICORE_INS_JEQA: // if (A[a] == A[b]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = sExtImm<15>(disp15, 2);
            t->operands[1] = getRegA(s1);
            t->operands[2] = getRegA(s2);
            break;

        case TRICORE_INS_JLTD: //if (D[a] < D[b]) then PC = PC + sign_ext(disp15) * 2;
        case TRICORE_INS_JNEQ32: //if (D[a] != D[b]) then PC = PC + sign_ext(disp15) * 2;
        case TRICORE_INS_JGEDD: //if (D[a] >= D[b]) then PC = PC + sign_ext(disp15) * 2;
            t->operands[0] = sExtImm<15>(disp15, 2);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            break;

        case TRICORE_INS_LOOP:
            switch (t->op2) {
                case 0x00: // //if (A[b] != 0) then PC = PC + sign_ext(2 * disp15); A[b] = A[b] - 1;
                    t->op_count = 2;
                    t->operands[0] = sExtImm<15>(disp15, 2);
                    t->operands[1] = getRegA(s2);
                    break;

                case 0x01: //PC = PC + sign_ext(2 * disp15);
                    t->op_count = 1;
                    t->operands[0] = sExtImm<15>(disp15, 2);
                    break;

                default:
                    assert(false);
            }
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

            switch (t->op2) {
                case 0x13:
                case 0x15:
                case 0x19:
                case 0x1B:
                case 0x23:
                case 0x2A:
                case 0x2C:
                    t->operands[2] = sExtImm<9>(const9);
                    break;

                default:
                    t->operands[2] = zExtImm<9>(const9);
            }
            break;

        case TRICORE_INS_MULE: //result = D[a] * sign_ext(const9); E[c] = result[63:0];
            t->operands[0] = getRegE(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = sExtImm<9>(const9);
            break;

        default:
            assert(false && TRICORE_OF_RC);
    }
}

void dismRCPW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RCPW;
    t->op_count = 5;
    t->op2 = bitRange<21, 22>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const4 = bitRange<12, 15>(b);
    auto width = bitRange<16, 20>(b);
    auto pos = bitRange<23, 27>(b);
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_INSERT_IMASK:
            switch (t->op2) {
                case 0x00: //INSERT
                    //mask = (2^width -1) << pos;
                    //D[c] = (D[a] & ~mask) | ((zero_ext(const4) << pos) & mask);
                    //If pos + width > 32, then the result is undefined.
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = zExtImm<4>(const4);
                    t->operands[3] = zExtImm<5>(width);
                    t->operands[4] = zExtImm<5>(pos);
                    break;

                case 0x01: //IMASK
                    //E[c][63:32] = ((2^width -1) << pos);
                    //E[c][31:0] = (zero_ext(const4) << pos);
                    //If pos + width > 32 the result is undefined.
                    t->op_count = 4;
                    t->operands[0] = getRegE(d);
                    t->operands[1] = zExtImm<4>(const4);
                    t->operands[2] = zExtImm<5>(width);
                    t->operands[3] = zExtImm<5>(pos);
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false && TRICORE_OF_RCPW);
    }
}

void dismRCR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RCR;
    t->op_count = 4;
    t->op2 = bitRange<21, 23>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<24, 27>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();
    auto const9 = bitRange<12, 20>(b);

    switch (i->id) {
        case TRICORE_INS_CADD: //condition = D[d] != 0; result = ((condition) ? D[a] + sign_ext(const9) : D[a]); D[c] = result[31:0];
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = sExtImm<9>(const9);
            t->operands[3] = getRegD(s2);
            break;

        case TRICORE_INS_MADD:
            switch (t->op2) {
                case 0x01: //result = D[d] + (D[a] * sign_ext(const9)); D[c] = result[31:0];
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = sExtImm<9>(const9);
                    t->operands[3] = getRegD(s2);
                    break;

                case 0x02: //result = E[d] + (D[a] * zero_ext(const9)); // unsigned operators E[c] = result[63:0];
                    t->operands[0] = getRegE(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = sExtImm<9>(const9);
                    t->operands[3] = getRegE(s2);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_MSUB:
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = sExtImm<9>(const9);
            t->operands[3] = getRegD(s2);

            switch (t->op2) {
                case 0x02: //result = E[d] - (D[a] * zero_ext(const9)); // unsigned operators E[c] = result[63:0];
                case 0x06: //result = E[d] - (D[a] * zero_ext(const9)); // unsigned operators E[c] = suov(result, 64);
                    t->operands[0] = getRegE(d);
                    t->operands[3] = getRegE(s2);
                    t->operands[2] = zExtImm<9>(const9);
                    break;

                case 0x03: //result = E[d] - (D[a] * sign_ext(const9)); E[c] = result[63:0];
                case 0x07: //result = E[d] - (D[a] * sign_ext(const9)); E[c] = ssov(result, 64);
                    t->operands[0] = getRegE(d);
                    t->operands[3] = getRegD(s2);
                    break;

                case 0x04:
                    t->operands[2] = zExtImm<9>(const9);
                    break;

                default:
                    break;
            }
            break;

        default:
            assert(false);
    }
}

void dismRCRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
}

void dismRCRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RCRW;
    t->op_count = 5;
    t->op2 = bitRange<21, 23>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto const4 = bitRange<12, 15>(b);
    auto width = bitRange<16, 20>(b);
    auto s3 = bitRange<24, 27>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_INSERT:
            switch (t->op2) {
                case 0x00: //mask = (2^width -1) << D[d][4:0]; D[c] = (D[a] & ~mask) | ((zero_ext(const4) << D[d][4:0]) & mask); If D[d][4:0] + width > 32, then the result is undefined.
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s3);
                    t->operands[3] = zExtImm<4>(const4);
                    t->operands[4] = zExtImm<5>(width);
                    break;

                case 0x01: //E[c][63:32] = ((2 width -1) << D[d][4:0]); E[c][31:0] = (zero_ext(const4) << D[d][4:0]); If (D[d][4:0] + width) > 32 the result is undefined.
                default:
                    assert(false && TRICORE_INS_INSERT);
            }
            break;

        default:
            assert(false && TRICORE_OF_RCRW);
    }
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
            t->operands[0] = getRegA(d);
            t->operands[1] = getRegA(s1);
            t->operands[2] = tExtImm<16>(const16);
            break;

        case TRICORE_INS_ADDIH_D: //result = D[a] + {const16, 16’h0000}; D[c] = result[31:0];
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
                case 0x0A:
                case 0x1A:
                case 0x3A:
                    t->operands[0] = getRegE(d);

                default:
                    break;
            }
            break;

        case TRICORE_INS_0B:
            switch (t->op2) {
                case 0x1C: //result = (D[b] >= 0) ? D[b] : (0 - D[b]); D[c] = result[31:0];
                case 0x1D: //result = (D[b] >= 0) ? D[b] : (0 - D[b]); D[c] = ssov(result, 32);
                    t->op_count = 2;
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s2);
                    break;

                case 0x7E: //sat_neg = (D[a] < -8000 H ) ? -8000 H : D[a]; D[c] = (sat_neg > 7FFF H ) ? 7FFF H : sat_neg;
                    t->op_count = 2;
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    break;

                default:
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    break;
            }
            break;

        case TRICORE_INS_ADDSCA:
            switch (t->op2) {
                case 0x01: //A[c] = A[a] + A[b];
                case 0x02: //A[c] = A[a] - A[b];
                    t->operands[0] = getRegA(d);
                    t->operands[1] = getRegA(s1);
                    t->operands[2] = getRegA(s2);
                    break;

                case 0x48: //D[c] = (A[a] == 0);
                case 0x49: //D[c] = (A[a] != 0);
                    t->op_count = 2;
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegA(s1);
                    break;

                case 0x60: //A[c] = A[b] + (D[a] << n);
                    t->operands[0] = getRegA(d);
                    t->operands[1] = getRegA(s2);
                    t->operands[2] = getRegD(s1);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_CALLI: //to long...
            t->op_count = 2;
            t->operands[0] = getRegA(s1);
            t->operands[1] = mem(TRICORE_REG_A_10, sExtImm<3>(std::bitset<64>(4)), WORD, TRICORE_EXT_THROW, TRICORE_MEM_OP_LEA);
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
                case 0x68: //result = D[a] * D[b]; // unsigned E[c] = result[63:0];
                case 0x6a: //result = D[a] * D[b]; E[c] = result[63:0];
                    t->operands[0] = getRegE(d);
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
        case TRICORE_INS_DEXTR: //D[c] = ({D[a], D[b]} << pos)[63:32];
            t->op_count = 4;
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            t->operands[3] = zExtImm<5>(pos);
            break;

        case TRICORE_INS_EXTR:
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
                    t->operands[2] = getRegE(s3);
            }
            break;

        case TRICORE_INS_SELN:
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            t->operands[3] = getRegD(s3);
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
    t->format = TRICORE_OF_RRR2;
    t->op_count = 4;
    t->op2 = bitRange<16, 23>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto s3 = bitRange<24, 27>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_MADD_RRR2: //result = D[d] + (D[a] * D[b]); D[c] = result[31:0];
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);

            switch (t->op2) {
                case 0x0A:
                    t->operands[0] = getRegD(d);
                    t->operands[3] = getRegD(s3);
                    break;

                case 0x68: //result = E[d] + (D[a] * D[b]); // unsigned operators E[c] = result[63:0];
                case 0x6A:
                    t->operands[0] = getRegE(d);
                    t->operands[3] = getRegE(s3);
                    break;

                default:
                    assert(false);
            }
            break;

        case TRICORE_INS_MSUB_RRR2:
            switch (t->op2) {
                case 0x0A: //result = D[d] - (D[a] * D[b]); D[c] = result[31:0];
                case 0x88: //result = D[d] - (D[a] * D[b]); // unsigned operators D[c]= suov(result, 32);
                case 0x8A: //result = D[d] - (D[a] * D[b]); D[c] = ssov(result, 32);
                    t->operands[0] = getRegD(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    t->operands[3] = getRegD(s3);
                    break;

                case 0x68: //result = E[d] - (D[a] * D[b]); // unsigned operators E[c] = result[63:0];
                case 0x6A: //result = E[d] - (D[a] * D[b]); E[c] = result[63:0];
                    t->operands[0] = getRegE(d);
                    t->operands[1] = getRegD(s1);
                    t->operands[2] = getRegD(s2);
                    t->operands[3] = getRegE(s3);
                    break;

                default:
                    assert(false);
            }
            break;

        default:
            assert(false);
    }

}

void dismRRRR(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    t->format = TRICORE_OF_RRRR;
    t->op_count = 4;
    t->op2 = bitRange<21, 23>(b).to_ulong();

    auto s1 = bitRange<8, 11>(b).to_ulong();
    auto s2 = bitRange<12, 15>(b).to_ulong();
    auto s3 = bitRange<24, 27>(b).to_ulong();
    auto d = bitRange<28, 31>(b).to_ulong();

    switch (i->id) {
        case TRICORE_INS_EXTR_INSR:
            t->operands[0] = getRegD(d);
            t->operands[1] = getRegD(s1);
            t->operands[2] = getRegD(s2);
            t->operands[3] = t->op2 == 0x04 ? getRegD(s3) : getRegE(s3);
            break;

        default:
            assert(false && TRICORE_OF_RRRR);
    }
}

void dismRRRW(cs_tricore* t, cs_insn* i, const std::bitset<64>& b) {
    assert(i->size == 4);
    assert(false);
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

    {TRICORE_INS_LOOP16, &dismSBR},
    {TRICORE_INS_JZD, &dismSBR},
    {TRICORE_INS_JZA_16, &dismSBR},
    {TRICORE_INS_JLEZD, &dismSBR},
    {TRICORE_INS_JGEZD, &dismSBR},
    {TRICORE_INS_JGTZ, &dismSBR},
    {TRICORE_INS_JNZ16, &dismSBR},
    {TRICORE_INS_JNZA_16, &dismSBR},
    {TRICORE_INS_JEQ16, &dismSBR},
    {TRICORE_INS_JNE_16_z_r, &dismSBR},
    {TRICORE_INS_JLTZ16, &dismSBR},

    {TRICORE_INS_JZT_16, &dismSBRN},
    {TRICORE_INS_JNZT_16, &dismSBRN},

    {TRICORE_INS_ANDD15, &dismSC},
    {TRICORE_INS_BISR16, &dismSC},
    {TRICORE_INS_SUBA10, &dismSC},
    {TRICORE_INS_MOVD15, &dismSC},
    {TRICORE_INS_ST16_D15_A10, &dismSC},
    {TRICORE_INS_ST_A10_A15, &dismSC},
    {TRICORE_INS_OR16_D15, &dismSC},
    {TRICORE_INS_LD16_D15_A10, &dismSC},
    {TRICORE_INS_LDA16_A15, &dismSC},

    {TRICORE_INS_LDA_PINC, &dismSLR},
    {TRICORE_INS_LDD, &dismSLR},
    {TRICORE_INS_LDD_PINC, &dismSLR},
    {TRICORE_INS_LD_HD_PINC, &dismSLR},
    {TRICORE_INS_LD16A, &dismSLR},
    {TRICORE_INS_LDHW16, &dismSLR},
    {TRICORE_INS_LDB_PINC, &dismSLR},
    {TRICORE_INS_LDB_D_A, &dismSLR},

    {TRICORE_INS_LDA, &dismSLRO},
    {TRICORE_INS_LDHW16_REL, &dismSLRO},
    {TRICORE_INS_LDW16, &dismSLRO},
    {TRICORE_INS_LDB_REL, &dismSLRO},

    {0x00, &dismSR}, //TRICORE_INS_NOP, TRICORE_INS_RET
    {TRICORE_INS_JIA, &dismSR},
    {TRICORE_INS_NOT16, &dismSR},
    {TRICORE_INS_RSUBD, &dismSR},

    {TRICORE_INS_ADDA, &dismSRC},
    {TRICORE_INS_CADD16, &dismSRC},
    {TRICORE_INS_ADD16_D15, &dismSRC},
    {TRICORE_INS_ADD16_D15_c, &dismSRC},
    {TRICORE_INS_MOVA, &dismSRC},
    {TRICORE_INS_ADDD_c, &dismSRC},
    {TRICORE_INS_MOVD, &dismSRC},
    {TRICORE_INS_SHAD, &dismSRC},
    {TRICORE_INS_SHD, &dismSRC},
    {TRICORE_INS_EQ16, &dismSRC},
    {TRICORE_INS_CMOVN16, &dismSRC},
    {TRICORE_INS_CMOVD_SRC, &dismSRC},

    {TRICORE_INS_ADDSCA16, &dismSRRS},

    {TRICORE_INS_ADD16_AA, &dismSRR},
    {TRICORE_INS_ADD16_D15_DD, &dismSRR},
    {TRICORE_INS_ADD16, &dismSRR},
    {TRICORE_INS_ADD16_SSOV, &dismSRR},
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
    {TRICORE_INS_CMOVD_D15, &dismSRR},
    {TRICORE_INS_MULD2, &dismSRR},
    {TRICORE_INS_SUBD1516, &dismSRR},
    {TRICORE_INS_EQ16_D15, &dismSRR},
    {TRICORE_INS_XOR16, &dismSRR},

    {TRICORE_INS_LD16_A15, &dismSRO},
    {TRICORE_INS_LD_BUD15, &dismSRO},
    {TRICORE_INS_LD_HD, &dismSRO},
    {TRICORE_INS_STHW16_D15, &dismSRO},
    {TRICORE_INS_LDD15, &dismSRO},
    {TRICORE_INS_STA_16, &dismSRO},
    {TRICORE_INS_S16_D15, &dismSRO},
    {TRICORE_INS_STB16, &dismSRO},

    {TRICORE_INS_STA, &dismSSR},
    {TRICORE_INS_STB, &dismSSR},
    {TRICORE_INS_STB_PINC, &dismSSR},
    {TRICORE_INS_STD, &dismSSR},
    {TRICORE_INS_ST_PINC, &dismSSR},
    {TRICORE_INS_STHW, &dismSSR},
    {TRICORE_INS_STHW16, &dismSSR},

    {TRICORE_INS_STBA, &dismSSRO},
    {TRICORE_INS_STHW16_A15, &dismSSRO},
    {TRICORE_INS_ST16_A15_D, &dismSSRO},
    {TRICORE_INS_ST16_A15_A, &dismSSRO},

    {TRICORE_INS_ST, &dismABS},
    {TRICORE_INS_LD, &dismABS},
    {TRICORE_INS_LDB, &dismABS},
    {TRICORE_INS_STB_ABS, &dismABS},
    {TRICORE_INS_LEA_ABS, &dismABS},

    {TRICORE_INS_ST_BIT, &dismABSB},

    {TRICORE_INS_J32, &dismB},
    {TRICORE_INS_JL, &dismB},
    {TRICORE_INS_JA, &dismB},
    {TRICORE_INS_CALL32, &dismB},
    {TRICORE_INS_CALLABS, &dismB},
    {TRICORE_INS_FCALL, &dismB},

    {TRICORE_INS_INST, &dismBIT},
    {TRICORE_INS_NAND, &dismBIT},
    {TRICORE_INS_NAND_NOR, &dismBIT},

    {TRICORE_INS_ST89, &dismBO},
    {TRICORE_INS_LD09, &dismBO},

    {TRICORE_INS_STWA, &dismBOL},
    {TRICORE_INS_LEA, &dismBOL},
    {TRICORE_INS_LDW, &dismBOL},
    {TRICORE_INS_ST_BA, &dismBOL},
    {TRICORE_INS_LD_BUD, &dismBOL},
    {TRICORE_INS_LDA_OFF, &dismBOL},

    {TRICORE_INS_JEQ32, &dismBRC},
    {TRICORE_INS_JGE, &dismBRC},
    {TRICORE_INS_JLT, &dismBRC},
    {TRICORE_INS_JNE_INC_DEC, &dismBRC},

    {TRICORE_INS_JNZT, &dismBRN},

    {TRICORE_INS_JNE16_D15, &dismSBC},
    {TRICORE_INS_JEQ16_D15, &dismSBC},

    {TRICORE_INS_JZ, &dismBRR},
    {TRICORE_INS_JEQA, &dismBRR},
    {TRICORE_INS_JLTD, &dismBRR},
    {TRICORE_INS_JNEQ32, &dismBRR},
    {TRICORE_INS_JGEDD, &dismBRR},
    {TRICORE_INS_LOOP, &dismBRR},

    {TRICORE_INS_BIT_OPERATIONS1, &dismRC},
    {TRICORE_INS_CMP, &dismRC},
    {TRICORE_INS_MULE, &dismRC},

    {TRICORE_INS_INSERT_IMASK, &dismRCPW},

    {TRICORE_INS_CADD, &dismRCR},
    {TRICORE_INS_MADD, &dismRCR},
    {TRICORE_INS_MSUB, &dismRCR},

    {TRICORE_INS_INSERT, &dismRCRW},

    {TRICORE_INS_MOVD_C16, &dismRLC},
    {TRICORE_INS_MOVU, &dismRLC},
    {TRICORE_INS_MOVH, &dismRLC},
    {TRICORE_INS_MOVH_A, &dismRLC},
    {TRICORE_INS_MTCR, &dismRLC},
    {TRICORE_INS_MFCR, &dismRLC},
    {TRICORE_INS_ADDI, &dismRLC},
    {TRICORE_INS_ADDIH_A, &dismRLC},
    {TRICORE_INS_ADDIH_D, &dismRLC},

    {TRICORE_INS_BIT_OPERATIONS2, &dismRR},
    {TRICORE_INS_DIV, &dismRR},
    {TRICORE_INS_0B, &dismRR},
    {TRICORE_INS_ADDSCA, &dismRR},
    {TRICORE_INS_CALLI, &dismRR},

    {TRICORE_INS_MULD, &dismRR2},

    {TRICORE_INS_DEXTR, &dismRRPW},
    {TRICORE_INS_EXTR, &dismRRPW},

    {TRICORE_INS_DVSTEP, &dismRRR},
    {TRICORE_INS_SELN, &dismRRR},

    {TRICORE_INS_MADD_RRR2, &dismRRR2},
    {TRICORE_INS_MSUB_RRR2, &dismRRR2},

    {TRICORE_INS_EXTR_INSR, &dismRRRR},

    {TRICORE_INS_ISYNC, &dismSYS},

};

#define SRRSMASK 0b111111
bool isSrrsFormat(unsigned int ins) {
    switch (ins & SRRSMASK) {
        case TRICORE_INS_ADDSCA16:
            return true;

        default:
            return false;
    }
};

#define BRRNMASK 0b1111111
bool isBrrnFormat(unsigned int ins) {
    switch (ins & BRRNMASK) {
        case TRICORE_INS_JNZT:
            return true;

        default:
            return false;
    }
};

cs_tricore::cs_tricore(cs_insn* i) : op2(0), n(0) {
    std::bitset<64> b = i->size == 4 ? i->bytes[3] << 24 | i->bytes[2] << 16 | i->bytes[1] << 8 | i->bytes[0] : i->bytes[1] << 8 | i->bytes[0];

    // update the id = op1
    i->id = i->bytes[0]; // default sizeof(op1) == 1 Byte
    if (isSrrsFormat(i->id)) { //Check if SRRS op format
        i->id = i->id & SRRSMASK;
    } else if (isBrrnFormat(i->id)) { //Check if BRRN op format
        i->id = i->id & BRRNMASK;
    }

    auto fInsToDism = insToDism.find(i->id);
    if (fInsToDism == std::end(insToDism)) {
        std::cout << "Disassemble of unhandled instruction: " << i->id << " @ " << std::hex << i->address << std::endl;
        if (i->size == 4) {
            std::cout << static_cast<unsigned>(i->bytes[3]) << " " << static_cast<unsigned>(i->bytes[2]) << " " << static_cast<unsigned>(i->bytes[1]) << " " << static_cast<unsigned>(i->bytes[0]) << std::endl;
        } else if (i->size == 2) {
            std::cout << static_cast<unsigned>(i->bytes[1]) << " " << static_cast<unsigned>(i->bytes[0]) << std::endl;
        }

        assert(false && "Unknown Tricore Instruction");
    } else {
        fInsToDism->second(this, i, b);
    }
}
