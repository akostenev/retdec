#include "retdec/capstone2llvmir/tricore/tricore.h"

#include <iostream>

namespace retdec {
namespace capstone2llvmir {

Capstone2LlvmIrTranslatorTricore::Capstone2LlvmIrTranslatorTricore(llvm::Module* m, cs_mode basic, cs_mode extra)
    : Capstone2LlvmIrTranslator(CS_ARCH_ALL, basic, extra, m) {

    initializeRegNameMap();
    initializeRegTypeMap();
    initializeArchSpecific();

    generateEnvironment();
}

Capstone2LlvmIrTranslatorTricore::~Capstone2LlvmIrTranslatorTricore()
{
    // Nothing specific to TriCore.
}

Capstone2LlvmIrTranslator::TranslationResult Capstone2LlvmIrTranslatorTricore::translate(const std::vector<uint8_t>& bytes,
    retdec::utils::Address a, llvm::IRBuilder<>& irb, bool stopOnBranch) {

    TranslationResult res;

    _branchGenerated = nullptr;
    _inCondition = false;
    uint64_t address = a;

    /**
     * Build tricore2capstone (light)
     */
    for (auto it = std::begin(bytes), end = std::end(bytes); it != end; ) {
        cs_insn i;
        i.id = (*it); // op1
        i.address = address;

        if ((*it) & 1) { // 32-Bit instruction
            i.size = 4;
            i.bytes[0] = *it++;
            i.bytes[1] = *it++;
            i.bytes[2] = *it++;
            i.bytes[3] = *it++;
        } else { // 16-bit instruction
            i.size = 2;
            i.bytes[0] = *it++;
            i.bytes[1] = *it++;
        }

        address += i.size;

        auto* a2l = generateSpecialAsm2LlvmInstr(irb, &i);
        if (res.first == nullptr) {
                res.first = a2l;
        }
        res.last = a2l;
        res.size = (i.address + i.size) - a;

        // and translate it
        translateInstruction(&i, irb);

        if (_branchGenerated && stopOnBranch) {
            res.branchCall = _branchGenerated;
            res.inCondition = _inCondition;
            return res;
        }

    }

    return res;
}

void Capstone2LlvmIrTranslatorTricore::translateInstruction(cs_insn* i, llvm::IRBuilder<>& irb) {
    _insn = i;

    auto fIt = _i2fm.find(i->id);
    if (fIt != _i2fm.end() && fIt->second != nullptr) {
        auto f = fIt->second;
        (this->*f)(i, irb);
    } else {
        std::cout << "Translation of unhandled instruction: " << i->id << std::endl;
        if (i->size == 4) {
            std::cout << static_cast<unsigned>(i->bytes[3]) << " " << static_cast<unsigned>(i->bytes[2]) << " " << static_cast<unsigned>(i->bytes[1]) << " " << static_cast<unsigned>(i->bytes[0]) << std::endl;
        } else if (i->size == 2) {
            std::cout << static_cast<unsigned>(i->bytes[1]) << " " << static_cast<unsigned>(i->bytes[0]) << std::endl;
        }

        std::stringstream msg;
        msg << "Translation of unhandled instruction: " << i->id << std::endl;
        throw Capstone2LlvmIrError(msg.str());
    }
}

llvm::IntegerType* Capstone2LlvmIrTranslatorTricore::getDefaultType() {
    return llvm::Type::getInt32Ty(_module->getContext());
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadRegister(uint32_t r, llvm::IRBuilder<>& irb) {
    if (r == TRICORE_REG_INVALID) {
        return nullptr;
    }

    if (r == TRICORE_REG_PC) {
        return getCurrentPc(_insn);
    }

    if (r == TRICORE_REG_ZERO) {
        return llvm::ConstantInt::getSigned(getDefaultType(), 0);
    }

//TODO
//     if (cs_insn_group(_handle, _insn, MIPS_GRP_NOTFP64BIT)
//             && MIPS_REG_F0 <= r
//             && r <= MIPS_REG_F31)
//     {
//         r = singlePrecisionToDoublePrecisionFpRegister(r);
//     }

    auto* llvmReg = getRegister(r);
    if (llvmReg == nullptr) {
        throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
    }
    return irb.CreateLoad(llvmReg);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb, llvm::Type* ty) {
    switch (op.type) {
        case TRICORE_OP_REG:
            return loadRegister(op.reg, irb);

        case TRICORE_OP_IMM:
                // TODO: Maybe this will cause problems.
                // In 32-bit MIPS, imms are 16 bits (always?).
                // What if number will be negative on 16 bits, but because we
                // take it here and create 32 bit, it loses it negativity?
                // The same in 64-bit MIPS.
                // However, maybe it will be ok, because cs_mips_op.imm is signed
                // int64_t, so if Capstone interprets it ok for us, then we probably
                // do not need to bother with it.
            return llvm::ConstantInt::getSigned(getDefaultType(), op.imm);

        case TRICORE_OP_MEM: {
            auto* baseR = loadRegister(op.mem.base, irb);
            auto* t = getDefaultType();
            llvm::Value* disp = llvm::ConstantInt::getSigned(t, op.mem.disp);

            llvm::Value* addr = nullptr;
            if (baseR == nullptr) {
                addr = disp;
            }
            else {
                if (op.mem.disp == 0) {
                    addr = baseR;
                } else {
                    disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
                    addr = irb.CreateAdd(baseR, disp);
                }
            }

            auto* lty = ty ? ty : t;
            auto* pt = llvm::PointerType::get(lty, 0);
            addr = irb.CreateIntToPtr(addr, pt);
            return irb.CreateLoad(addr);
        }
        case TRICORE_OP_INVALID:
        default:
            assert(false && "should not be possible");
            return nullptr;
    }
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOpUnary(cs_tricore* mi, llvm::IRBuilder<>& irb) {
    if (mi->op_count != 1) {
        throw Capstone2LlvmIrError("This is not a unary instruction.");
    }

    return loadOp(mi->operands[0], irb);
}

std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOpBinary(cs_tricore* mi, llvm::IRBuilder<>& irb, eOpConv ct) {
    if (mi->op_count != 2) {
        throw Capstone2LlvmIrError("This is not a binary instruction.");
    }

    auto* op0 = loadOp(mi->operands[0], irb);
    auto* op1 = loadOp(mi->operands[1], irb);
    if (op0 == nullptr || op1 == nullptr) {
        throw Capstone2LlvmIrError("Operands loading failed.");
    }

    if (op0->getType() != op1->getType()) {
        switch (ct) {
            case eOpConv::SECOND_SEXT:
                op1 = irb.CreateSExtOrTrunc(op1, op0->getType());
                break;
            case eOpConv::SECOND_ZEXT:
                op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
                break;
            case eOpConv::NOTHING:
                break;
            default:
                case eOpConv::THROW:
                    throw Capstone2LlvmIrError("Binary operands' types not equal.");
        }
    }

    return std::make_pair(op0, op1);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOpBinaryOp1(cs_tricore* mi, llvm::IRBuilder<>& irb, llvm::Type* ty) {
        if (mi->op_count != 2) {
            throw Capstone2LlvmIrError("This is not a binary instruction.");
        }
        return loadOp(mi->operands[1], irb, ty);
}

std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOpTernary(cs_tricore* mi, llvm::IRBuilder<>& irb) {
    if (mi->op_count != 3) {
        throw Capstone2LlvmIrError("This is not a ternary instruction.");
    }

    auto* op0 = loadOp(mi->operands[0], irb);
    auto* op1 = loadOp(mi->operands[1], irb);
    auto* op2 = loadOp(mi->operands[2], irb);
    if (op0 == nullptr || op1 == nullptr || op2 == nullptr) {
        throw Capstone2LlvmIrError("Operands loading failed.");
    }

    return std::make_tuple(op0, op1, op2);
}

std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOp1Op2(cs_tricore* mi, llvm::IRBuilder<>& irb, eOpConv ct) {
    if (mi->op_count != 3) {
        throw Capstone2LlvmIrError("This is not a ternary instruction.");
    }

    auto* op1 = loadOp(mi->operands[1], irb);
    auto* op2 = loadOp(mi->operands[2], irb);
    if (op1 == nullptr || op2 == nullptr) {
            throw Capstone2LlvmIrError("Operands loading failed.");
    }

    if (op1->getType() != op2->getType()) {
        switch (ct) {
            case eOpConv::SECOND_SEXT:
            {
                    op2 = irb.CreateSExtOrTrunc(op2, op1->getType());
                    break;
            }
            case eOpConv::SECOND_ZEXT:
            {
                    op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
                    break;
            }
            case eOpConv::NOTHING:
            {
                    break;
            }
            default:
            case eOpConv::THROW:
            {
                    throw Capstone2LlvmIrError("Binary operands' types not equal.");
            }
        }
    }

    return std::make_pair(op1, op2);
}


/**
 * @a ct is used when storing a value to register with a different type.
 * When storing to memory, value type is used -- therefore it needs to be
 * converted to the desired type prior to @c storeOp() call.
 * // TODO: use this, instead of default sext for registers.
 */
llvm::Instruction* Capstone2LlvmIrTranslatorTricore::storeOp(cs_tricore_op& op, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct) {
    switch (op.type) {
        case TRICORE_OP_REG:
            return storeRegister(op.reg, val, irb, ct);
        case TRICORE_OP_MEM: {
            auto* baseR = loadRegister(op.mem.base, irb);
            auto* t = getDefaultType();
            llvm::Value* disp = llvm::ConstantInt::getSigned(t, op.mem.disp);

            llvm::Value* addr = nullptr;
            if (baseR == nullptr) {
                    addr = disp;
            } else {
                if (op.mem.disp == 0) {
                    addr = baseR;
                } else {
                    disp = irb.CreateSExtOrTrunc(disp, baseR->getType());
                    addr = irb.CreateAdd(baseR, disp);
                }
            }

            auto* pt = llvm::PointerType::get(val->getType(), 0);
            addr = irb.CreateIntToPtr(addr, pt);
            return irb.CreateStore(val, addr);
        }
        case MIPS_OP_IMM:
        case MIPS_OP_INVALID:
        default:
            assert(false && "should not be possible");
            return nullptr;
    }
}

llvm::StoreInst* Capstone2LlvmIrTranslatorTricore::storeRegister(uint32_t r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct) {
    if (r == TRICORE_REG_INVALID) {
        return nullptr;
    }
    // These registers should not be stored, or their store has no effect.
    //
    if (r == TRICORE_REG_PC || r == TRICORE_REG_ZERO) {
        return nullptr;
    }

    //TODO
    //         if (cs_insn_group(_handle, _insn, MIPS_GRP_NOTFP64BIT) && MIPS_REG_F0 <= r && r <= MIPS_REG_F31) {
    //             r = singlePrecisionToDoublePrecisionFpRegister(r);
    //         }

    auto* llvmReg = getRegister(r);
    auto* regT = getRegisterType(r);
    if (llvmReg == nullptr) {
        throw Capstone2LlvmIrError("storeRegister() unhandled reg.");
    }

    if (val->getType() != llvmReg->getValueType()) {
        switch (ct) {
            case eOpConv::SEXT_TRUNC:
                if (val->getType()->isIntegerTy()) {
                    val = irb.CreateSExtOrTrunc(val, regT);
                } else if (val->getType()->isFloatingPointTy()) {
                    val = irb.CreateFPCast(val, regT);
                } else {
                    assert(false && "unhandled value type");
                }
                break;
            case eOpConv::ZEXT_TRUNC:
                val = irb.CreateZExtOrTrunc(val, regT);
                break;
            case eOpConv::FP_CAST:
                val = irb.CreateFPCast(val, regT);
                break;
            default:
                throw Capstone2LlvmIrError("Unhandled eOpConv type.");
        }
    }

    return irb.CreateStore(val, llvmReg);
}


llvm::Value* Capstone2LlvmIrTranslatorTricore::getCurrentPc(cs_insn* i) {
    return getNextInsnAddress(i);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getNextInsnAddress(cs_insn* i) {
    return llvm::ConstantInt::get(getDefaultType(), i->address + i->size);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getNextNextInsnAddress(cs_insn* i) {
    return llvm::ConstantInt::get(llvm::Type::getInt32Ty(_module->getContext()), i->address + (2 * i->size));
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedBasicMode(cs_mode m) {
    return m == CS_MODE_THUMB; // there is no CS_MODE_TRICORE...
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedExtraMode(cs_mode m) {
    return m == CS_MODE_LITTLE_ENDIAN || m == CS_MODE_BIG_ENDIAN;
}

void Capstone2LlvmIrTranslatorTricore::modifyBasicMode(cs_mode m) {
    // unsupported
}

void Capstone2LlvmIrTranslatorTricore::modifyExtraMode(cs_mode m) {
    // unsupported
}

void Capstone2LlvmIrTranslatorTricore::generateEnvironmentArchSpecific() {
    // Nothing.
}

void Capstone2LlvmIrTranslatorTricore::generateDataLayout() {
    /**
     * @src http://llvm.org/docs/LangRef.html#data-layout
     * e little endian
     * m:e ELF mangling
     * p:32:32 32 bit pointer
     * TODO floting point registers? f32 f64 f80 f128?
     * n:32 native integer widths
     * S:64 @src Tricore 1.6 Vol 1: 2.2.1 Table 2-1
     */
    _module->setDataLayout("e-m:e-p:32:32-n32-S64");
}

uint32_t Capstone2LlvmIrTranslatorTricore::getArchByteSize() {
    return 4;
}

uint32_t Capstone2LlvmIrTranslatorTricore::getArchBitSize() {
    return getArchByteSize() * 8;
}

std::string Capstone2LlvmIrTranslatorTricore::getRegisterName(uint32_t r) const {
    auto fIt = _reg2name.find(r);
    if (fIt != _reg2name.end()) {
        return fIt->second;
    } else {
        throw Capstone2LlvmIrError(
            "Missing name for register number: " + std::to_string(r));
    }
}

/**
 * TODO
 */
void Capstone2LlvmIrTranslatorTricore::generateRegisters() {
    createRegister(TRICORE_REG_PC, _regLt);
    createRegister(TRICORE_REG_SYSCON, _regLt);
    createRegister(TRICORE_REG_CPU_ID, _regLt);
    createRegister(TRICORE_REG_BIV, _regLt);
    createRegister(TRICORE_REG_BTV, _regLt);
    createRegister(TRICORE_REG_ISP, _regLt);
    createRegister(TRICORE_REG_ICR, _regLt);
    createRegister(TRICORE_REG_FCX, _regLt);
    createRegister(TRICORE_REG_LCX, _regLt);
    createRegister(TRICORE_REG_COMPAT, _regLt);

    createRegister(TRICORE_REG_D_0, _regLt);
    createRegister(TRICORE_REG_D_1, _regLt);
    createRegister(TRICORE_REG_D_2, _regLt);
    createRegister(TRICORE_REG_D_3, _regLt);
    createRegister(TRICORE_REG_D_4, _regLt);
    createRegister(TRICORE_REG_D_5, _regLt);
    createRegister(TRICORE_REG_D_6, _regLt);
    createRegister(TRICORE_REG_D_7, _regLt);
    createRegister(TRICORE_REG_D_8, _regLt);
    createRegister(TRICORE_REG_D_9, _regLt);
    createRegister(TRICORE_REG_D_10, _regLt);
    createRegister(TRICORE_REG_D_11, _regLt);
    createRegister(TRICORE_REG_D_12, _regLt);
    createRegister(TRICORE_REG_D_13, _regLt);
    createRegister(TRICORE_REG_D_14, _regLt);
    createRegister(TRICORE_REG_D_15, _regLt);

    createRegister(TRICORE_REG_A_0, _regLt);
    createRegister(TRICORE_REG_A_1, _regLt);
    createRegister(TRICORE_REG_A_2, _regLt);
    createRegister(TRICORE_REG_A_3, _regLt);
    createRegister(TRICORE_REG_A_4, _regLt);
    createRegister(TRICORE_REG_A_5, _regLt);
    createRegister(TRICORE_REG_A_6, _regLt);
    createRegister(TRICORE_REG_A_7, _regLt);
    createRegister(TRICORE_REG_A_8, _regLt);
    createRegister(TRICORE_REG_A_9, _regLt);
    createRegister(TRICORE_REG_A_10, _regLt);
    createRegister(TRICORE_REG_A_11, _regLt);
    createRegister(TRICORE_REG_A_12, _regLt);
    createRegister(TRICORE_REG_A_13, _regLt);
    createRegister(TRICORE_REG_A_14, _regLt);
    createRegister(TRICORE_REG_A_15, _regLt);
}

tricore_reg Capstone2LlvmIrTranslatorTricore::getRegDByNumber(unsigned int n) {
    return tricore_reg(0xFF00 + n*4);
}

tricore_reg Capstone2LlvmIrTranslatorTricore::getRegAByNumber(unsigned int n) {
        return tricore_reg(0xFF80 + n*4);
}

} // namespace capstone2llvmir
} // namespace retdec

//////////////////////
// Capstone2Tricore //
//////////////////////

cs_tricore::cs_tricore(cs_insn* i) : op2(0), brnN(0) {
    std::bitset<64> b = i->size == 4 ? i->bytes[3] << 24 | i->bytes[2] << 16 | i->bytes[1] << 8 | i->bytes[0] : i->bytes[1] << 8 | i->bytes[0];

    switch (i->id) {
//         case 0x5C:
        case TRICORE_INS_J_8: // PC = PC + sign_ext(disp8) * 2;
//         case 0x6e:
        case TRICORE_INS_JNZD: // if (D[15] != 0) then PC = PC + sign_ext(disp8) * 2;
            format = TRICORE_OF_SB;
            op_count = 1;
            operands[0] = cs_tricore_op(bitRange<8, 15>(b).to_ulong() * 2);
            break;

        case TRICORE_INS_JZD: // if (D[b] == 0) then PC = PC + zero_ext(disp4) * 2;
            format = TRICORE_OF_SBR;
            op_count = 2;

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<12, 15>(b).to_ulong() * 4)); //D[b]
            operands[1] = cs_tricore_op(bitRange<8, 11>(b).to_ulong() * 2); //zero_ext(disp4) * 2;
            break;

        case TRICORE_INS_JIA: //PC = {A[a][31:1], 1’b0};
            format = TRICORE_OF_SR;
            op_count = 1;
            op2 = bitRange<12, 15>(b).to_ulong();

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + bitRange<8, 11>(b).to_ulong() * 4)); //A[a]
            break;

        case TRICORE_INS_ADDD: //D[a] = sign_ext(const4);
        case TRICORE_INS_MOVD_A: //D[a] = sign_ext(const4);
        case TRICORE_INS_SHAD: // ... to long
            format = TRICORE_OF_SRC;
            op_count = 2;

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4)); //D[a]
            operands[1] = cs_tricore_op(bitRange<12, 15>(b).to_ulong()); //const4 //TODO check sign_ext
            break;

//         case 0xCC: //A[15] = M(A[b] + zero_ext(4 * off4), word);
        case TRICORE_INS_LD_BUD: //D[15] = zero_ext(M(A[b] + zero_ext(off4), byte));
        case TRICORE_INS_LD_HD: //D[15] = sign_ext(M(A[b] + zero_ext(2 * off4), half-word));
//         case 0x4C: //D[15] = M(A[b] + zero_ext(4 * off4), word);
//         case 0xEC: //M(A[b] + zero_ext(4 * off4), word) = A[15];
//         case 0x2C: //M(A[b] + zero_ext(off4), byte) = D[15][7:0];
//         case 0xAC: //M(A[b] + zero_ext(2 * off4), half-word) = D[15][15:0];
//         case 0x6C: //M(A[b] + zero_ext(4 * off4), word) = D[15];
        {
            format = TRICORE_OF_SRO;
            op_count = 2;

            uint8_t off4 = bitRange<8, 11>(b).to_ulong();
            tricore_reg ab = tricore_reg(TRICORE_REG_A_0 + bitRange<12, 15>(b).to_ulong() * 4);

            switch (i->id) {
                case 0xCC:
                    operands[0] = cs_tricore_op(TRICORE_REG_A_15);
                    operands[1] = cs_tricore_op(ab, off4 * 4);
                    break;
                case TRICORE_INS_LD_BUD:
                    operands[0] = cs_tricore_op(TRICORE_REG_D_15);
                    operands[1] = cs_tricore_op(ab, off4);
                    break;
                case TRICORE_INS_LD_HD:
                    operands[0] = cs_tricore_op(TRICORE_REG_D_15);
                    operands[1] = cs_tricore_op(ab, off4 * 2);
                    break;
                case 0x4C:
                    operands[0] = cs_tricore_op(TRICORE_REG_D_15);
                    operands[1] = cs_tricore_op(ab, off4 * 4);
                    break;
                case 0xEC:
                    operands[0] = cs_tricore_op(ab, off4 * 4);
                    operands[1] = cs_tricore_op(TRICORE_REG_A_15);
                    break;
                case 0x2C:
                    operands[0] = cs_tricore_op(ab, off4);
                    operands[1] = cs_tricore_op(TRICORE_REG_D_15);
                    break;
                case 0xAC:
                    operands[0] = cs_tricore_op(ab, off4 * 2);
                    operands[1] = cs_tricore_op(TRICORE_REG_D_15);
                    break;
                case 0x6C:
                    operands[0] = cs_tricore_op(ab, off4 * 4);
                    operands[1] = cs_tricore_op(TRICORE_REG_D_15);
                    break;
                default:
                    assert(false);
            }
            break;
        }

        case TRICORE_INS_MOVAD: //A[a] = D[b];
        case TRICORE_INS_MOVDA: //D[a] = A[b];
        case TRICORE_INS_ORD: //D[a] = D[a] | D[b];
        case TRICORE_INS_ANDD: //D[a] = D[a] & D[b];
        case TRICORE_INS_SUBD: //result = D[a] - D[b]; D[a] = result[31:0];
            format = TRICORE_OF_SRR;
            op_count = 2;

            switch (i->id) {
                case TRICORE_INS_MOVAD:
                    operands[0] = tricore_reg(TRICORE_REG_A_0 + bitRange<8, 11>(b).to_ulong() * 4); //A[a]
                    operands[1] = tricore_reg(TRICORE_REG_D_0 + bitRange<12, 15>(b).to_ulong() * 4); //D[b]
                    break;
                case TRICORE_INS_MOVDA:
                    operands[0] = tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4); //D[a]
                    operands[1] = tricore_reg(TRICORE_REG_A_0 + bitRange<12, 15>(b).to_ulong() * 4); //A[b]
                    break;
                case TRICORE_INS_ORD:
                case TRICORE_INS_ANDD:
                case TRICORE_INS_SUBD:
                    operands[0] = tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4); //D[a]
                    operands[1] = tricore_reg(TRICORE_REG_D_0 + bitRange<12, 15>(b).to_ulong() * 4); //D[b]
                    break;
                default:
                    assert(false);
            }
            break;

//         case 0x6D:
//         case 0xED:
//         case 0x61: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = PC + sign_ext(2 * disp24); A[11] = ret_addr[31:0]; A[10] = EA[31:0];
//         case 0xE1: //ret_addr = PC + 4; EA = A[10] - 4; M(EA,word) = A[11]; PC = {disp24[23:20], 7'b0, disp24[19:0], 1'b0}; A[11] = ret_addr[31:0]; A[10] = EA[31:0]
        case TRICORE_INS_J_24: //PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_JA: //PC = {disp24[23:20], 7’b0000000, disp24[19:0], 1’b0};
        case TRICORE_INS_JL: //A[11] = PC + 4; PC = PC + sign_ext(disp24) * 2;
        case TRICORE_INS_CALL_24: // ... to long
        case 0xDD:
        {
            format = TRICORE_OF_B;
            op_count = 1;

            std::bitset<64> disp24 = ((bitRange<8, 15>(b) << 16) | (bitRange<16, 31>(b))).to_ulong();
            std::bitset<64> exDisp24 = (bitRange<20, 23>(disp24) << 28) | (bitRange<0, 19>(disp24) << 1);

            switch (i->id) {
                case TRICORE_INS_J_24:
                case TRICORE_INS_JL:
                    operands[0] = disp24.to_ulong() * 2;
                    break;
                case TRICORE_INS_JA:
                    operands[0] = exDisp24.to_ulong() * 2;
                    break;
                case TRICORE_INS_CALL_24:
                    operands[0] = exDisp24.to_ulong();
                    break;
                default:
                    assert(false);
            }

            operands[0] = cs_tricore_op(((bitRange<16, 23>(b) << 16) | bitRange<0, 15>(b)).to_ulong() * 2);
            break;
        }
        case TRICORE_INS_JEQ_15_c:  //if (D[a] == sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
                                    //if (D[a] != sign_ext(const4)) then PC = PC + sign_ext(disp15) * 2;
//         case 0xFF:
//         case 0xBF:
//         case 0x9F:
            format = TRICORE_OF_BRC;
            op_count = 3;

            op2 = bitRange<30, 31>(b).to_ulong();
            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4)); // D[A]
            operands[1] = cs_tricore_op(bitRange<12, 15>(b).to_ulong()); // const4
            operands[2] = cs_tricore_op(bitRange<16, 29>(b).to_ulong() * 2); // sign_ext(disp15) * 2
            break;

        case 0x85: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = M(EA, word);
        case 0x05: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = sign_ext(M(EA, byte));
//         case 0xE5: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = (M(EA, word) & ~E[a][63:32]) | (E[a][31:0] & E[a][63:32]);
//         case 0x15: // EA = {off18[17:14], 14b'0, off18[13:0]};  {dummy, dummy, A[10:11], D[8:11], A[12:15], D[12:15]} = M(EA, 16-word);
        case TRICORE_INS_ST_A: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, word) = A[a];
        case 0x65: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, halfword) = D[a][31:16];
//         case 0x25: // EA = {off18[17:14], 14b'0, off18[13:0]};  M(EA, byte) = D[a][7:0];
        case 0xC5: // EA = {off18[17:14], 14b'0, off18[13:0]};  A[a] = EA[31:0];
//         case 0x45: // EA = {off18[17:14], 14b'0, off18[13:0]};  D[a] = {M(EA, halfword), 16’h0000};
        {
            format = TRICORE_OF_ABS;
            op_count = 2;

            uint8_t s1_d = bitRange<8, 11>(b).to_ulong();
            std::bitset<64> off18 = (bitRange<12, 15>(b) << 14) | (bitRange<22, 25>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b));
            uint32_t ea = ((bitRange<14, 17>(off18) << 28) | (bitRange<0, 13>(b))).to_ulong();

            switch (i->id) {
                case 0x85:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + s1_d * 4)); //A[a]
                    operands[1] = cs_tricore_op(TRICORE_REG_INVALID, ea);
                    break;
                case 0xC5:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + s1_d * 4)); //A[a]
                    operands[1] = cs_tricore_op(ea);
                    break;
                case 0x05:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + s1_d * 4)); //D[a]
                    operands[1] = cs_tricore_op(TRICORE_REG_INVALID, ea);
                    break;
                case TRICORE_INS_ST_A:
                    operands[0] = cs_tricore_op(TRICORE_REG_INVALID, ea);
                    operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + s1_d * 4)); //A[a]
                    break;
                case 0x65:
                    operands[0] = cs_tricore_op(TRICORE_REG_INVALID, ea);
                    operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + s1_d * 4)); //D[a]
                    break;
                default: //M(EA)
                    assert(false);
            }
            break;
        }

        case TRICORE_INS_JNZT: //if (D[a][n]) then PC = PC + sign_ext(disp15) * 2;
                               //if (!D[a][n]) then PC = PC + sign_ext(disp15) * 2;
            format = TRICORE_OF_BRN;
            brnN = (bitRange<6, 7>(b) << 3 | bitRange<12, 15>(b)).to_ulong();
            op2 = bitRange<30, 31>(b).to_ulong();

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4)); //D[a]
            operands[1] = cs_tricore_op(bitRange<16, 29>(b).to_ulong() * 2); // sign_ext
            break;

        case TRICORE_INS_MOVD_C16: // D[c] = sign_ext(const16);
        case TRICORE_INS_MOVH: // D[c] = {const16, 16’h0000};
        case TRICORE_INS_MOVH_A: // A[c] = {const16, 16’h0000};
        case TRICORE_INS_MTCR: //CR[const16] = D[a];
        case TRICORE_INS_MFCR: //D[c] = CR[const16];
        case TRICORE_INS_MOVU: //D[c] = zero_ext(const16);
        {
            format = TRICORE_OF_RLC;
            op_count = 2;
            std::bitset<64> const16 = (bitRange<12, 27>(b));
            std::bitset<64> c = bitRange<28, 31>(b);
            std::bitset<64> s1 = bitRange<8, 11>(b);

            switch (i->id) {
                case TRICORE_INS_MOVH:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + c.to_ulong() * 4)); //D[c]
                    operands[1] = cs_tricore_op((const16 << 16).to_ulong()); // const16
                    break;
                case TRICORE_INS_MOVH_A:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + c.to_ulong() * 4)); //A[c]
                    operands[1] = cs_tricore_op((const16 << 16).to_ulong()); // const16
                    break;
                case TRICORE_INS_MTCR:
                    operands[0] = cs_tricore_op(tricore_reg(const16.to_ulong())); //CR[const16]
                    operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + s1.to_ullong() * 4)); //D[a]
                    break;
                case TRICORE_INS_MFCR:
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + c.to_ullong() * 4)); //D[c]
                    operands[1] = cs_tricore_op(tricore_reg(const16.to_ulong())); //CR[const16]
                    break;
                case TRICORE_INS_MOVD_C16: //sign_ext
                case TRICORE_INS_MOVU: //zero_ext
                    operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + c.to_ullong() * 4)); //D[c]
                    operands[1] = cs_tricore_op(const16.to_ulong()); //zero_ext(const16);
                    break;
                default:
                    assert(false);
            }
            operands[1] = cs_tricore_op((const16 << 16).to_ulong()); // const16

            break;
        }
        case TRICORE_INS_BIT_OPERATIONS1:
        {
            format = TRICORE_OF_RC;
            op_count = 3;

            // 0AH : D[c] = D[a] | zero_ext(const9);
            op2 = bitRange<21, 27>(b).to_ulong();
            std::bitset<64> c = bitRange<28, 31>(b);
            std::bitset<64> a = bitRange<8, 11>(b);
            std::bitset<64> const9 = bitRange<12, 20>(b);

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + c.to_ulong() * 4)); // D[c]
            operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + a.to_ulong() * 4)); // D[a]
            operands[2] = cs_tricore_op(const9.to_ulong()); // const9
            break;
        }
        case TRICORE_INS_ADDI: //result = D[a] + sign_ext(const16); D[c] = result[31:0];
            format = TRICORE_OF_RLC;
            op_count = 3;

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<28, 31>(b).to_ulong() * 4)); // D[c]
            operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4)); // D[a]
            operands[2] = cs_tricore_op(bitRange<12, 27>(b).to_ulong()); // const16

            break;
        case TRICORE_INS_LEA: // EA = A[b] + sign_ext(off16); A[a] = EA[31:0];
            format = TRICORE_OF_BOL;
            op_count = 3;
            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + bitRange<8, 11>(b).to_ulong() * 4)); // A[a]
            operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_A_0 + bitRange<12, 15>(b).to_ulong() * 4)); // A[b]
            operands[2] = cs_tricore_op(((bitRange<22, 27>(b) << 10) | (bitRange<28, 31>(b) << 6) | (bitRange<16, 21>(b))).to_ulong()); //off16

            break;

        case TRICORE_INS_BIT_OPERATIONS2: //D[c] = D[a] & D[b];
            format = TRICORE_OF_RR;
            op_count = 3;
            op2 = bitRange<20, 27>(b).to_ulong();

            operands[0] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<28, 31>(b).to_ulong() * 4)); // D[c]
            operands[1] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<8, 11>(b).to_ulong() * 4)); // D[a]
            operands[2] = cs_tricore_op(tricore_reg(TRICORE_REG_D_0 + bitRange<12, 15>(b).to_ulong() * 4)); // D[b]
            break;
        default:
            assert(false);
    };
}
