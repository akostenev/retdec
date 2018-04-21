#include "retdec/capstone2llvmir/tricore/tricore.h"

namespace retdec {
namespace capstone2llvmir {

void Capstone2LlvmIrTranslatorTricore::translateJ(cs_insn* i, const std::bitset<64>& b, llvm::IRBuilder<>& irb) {
    cs_tricore mi;

    if (i->id == TRICORE_INS_J_24 && i->size == 4) {
        //31        16 15            8 7        0
        //disp24[15:0]        disp24[23:16]        1DH
        //PC = PC + sign_ext(disp24) * 2;
        auto disp24 = (bitRange<16, 31>(b) | (bitRange<8, 15>(b) << 16));
        disp24 <<= 1; // *2

        mi.setOp({disp24.to_ulong()});

    } else if (i->id == TRICORE_INS_J_8 && i->size == 2) {
        //15        8 7        0
        //    disp8        3CH
        //PC = PC + sign_ext(disp8) * 2;
        auto disp8 = bitRange<8, 15>(b);
        disp8 <<= 1; // * 2
        mi.setOp({disp8.to_ullong()});

    } else if (i->id == TRICORE_INS_JA && i->size == 4) {
        //31            16 15            8 7        0
        //    disp24[15:0]        disp24[23:16]        9DH
        //PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};

        auto disp24 = (bitRange<8, 15>(b) << 16) | bitRange<16, 31>(b);
        auto pc = (bitRange<20, 23>(disp24) << 28) | (bitRange<0, 19>(disp24) << 1);
        mi.setOp(pc.to_ulong());
    }

    op0 = loadOpUnary(&mi, irb);
    generateBranchFunctionCall(irb, op0);
}

void Capstone2LlvmIrTranslatorTricore::translateConditionalJ(cs_insn* i, const std::bitset<64>& b, llvm::IRBuilder<>& irb) {
    cs_tricore mi;

    if (i->id == TRICORE_INS_JEQ_15_c && i->size == 4) {
        //H00 == TRICORE_INS_JEQ_15_c, H01 == TRICORE_INS_JNE_c
        //31    30      16 15      12 11 8 7   0
        // H00    disp15     const4     a   DFH
        //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; TRICORE_INS_JEQ_15_c
        //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2; TRICORE_INS_JNE_c

        mi.setOp({getRegDByNumber(bitRange<8, 11>(b).to_ulong())}, 0); // a
        mi.setOp({bitRange<12, 15>(b).to_ulong()}, 1); // const 4
        mi.setOp({(bitRange<16, 30>(b) << 1).to_ulong()}, 2); // disp15 * 2

        std::tie(op0, op1, op2) = loadOpTernary(&mi, irb);
        op1 = irb.CreateZExtOrTrunc(op1, op0->getType());


        llvm::Value* cond = nullptr;
        if (b.test(31)) { // TRICORE_INS_JNE_c
            cond = irb.CreateICmpNE(op0, op1);
        } else { // TRICORE_INS_JEQ_15_c
            cond = irb.CreateICmpEQ(op0, op1);
        }

        generateCondBranchFunctionCall(irb, cond, op2);
    }
}

void Capstone2LlvmIrTranslatorTricore::translateLd(cs_insn* i, const std::bitset<64>& b, llvm::IRBuilder<>& irb) {
    cs_tricore mi;

    if (i->id == TRICORE_INS_LD_HD && i->size == 2) {

        //15 12 11    8 7   0
        //  b     off4   8CH
        //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));


        mi.setOp({TRICORE_REG_D_15}, 0); // D[15]
        mi.setOp({getRegAByNumber(bitRange<12, 15>(b).to_ulong()), (bitRange<8, 11>(b) << 1).to_ulong()}, 1); // M(A[b] + zero_ext(2 * off4)

        llvm::Type* ty = irb.getInt16Ty(); //half-word
        eOpConv ct = eOpConv::ZEXT_TRUNC; //zero_ext

        op1 = loadOpBinaryOp1(&mi, irb, ty);
        storeOp(mi.operands[0], op1, irb, ct);
    }

}

void Capstone2LlvmIrTranslatorTricore::translateNop(cs_insn* i, const std::bitset<64>& b, llvm::IRBuilder<>& irb) {
    if (i->id != TRICORE_INS_NOP) {
        throw Capstone2LlvmIrError("Should be 0x00 TRICORE NOP Instruction, but was " + std::to_string(i->id));
    }
}


} // namespace capstone2llvmir
} // namespace retdec
