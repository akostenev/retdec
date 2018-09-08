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

Capstone2LlvmIrTranslator::TranslationResult Capstone2LlvmIrTranslatorTricore::translate(const std::vector<uint8_t>& bytes,
    retdec::utils::Address a, llvm::IRBuilder<>& irb, bool stopOnBranch) {

    TranslationResult res;

    _branchGenerated = nullptr;
    _inCondition = false;
    uint64_t address = a;

    if (address & 1) { //unaligned address, error, return
        return res;
    }

    /**
     * Build instructions and translate them
     */
    for (auto it = std::begin(bytes), end = std::end(bytes); it != end; ) {
        cs_insn i;
        i.address = address;

        if ((*it) & 1) { // 32-Bit instruction
            i.size = 4;
            i.bytes[0] = *it++;
            if (it == end) {
                return res;
            }
            i.bytes[1] = *it++;
            if (it == end) {
                return res;
            }
            i.bytes[2] = *it++;
            if (it == end) {
                return res;
            }
            i.bytes[3] = *it++;
        } else { // 16-bit instruction
            i.size = 2;
            i.bytes[0] = *it++;
            if (it == end) {
                return res;
            }
            i.bytes[1] = *it++;
            i.bytes[2] = 0;
            i.bytes[3] = 0;
        }

        address += i.size;

        auto* a2l = generateSpecialAsm2LlvmInstr(irb, &i);
        if (res.first == nullptr) {
            res.first = a2l;
        }
        res.last = a2l;
        res.size = (i.address + i.size) - a;

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

    cs_tricore t(i); // disassemble with Tricore2Captstone

    auto fIt = _i2fm.find(i->id);
    if (fIt != _i2fm.end() && fIt->second != nullptr) {
        auto f = fIt->second;
        (this->*f)(i, &t, irb); // translate to LLVM-IR

    } else {
        std::cout << "Translation of unhandled instruction: " << i->id << " @ " << std::hex << i->address << std::endl;
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

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb, llvm::Type* ty) {

    if (!ty) {
        ty = llvm::Type::getInt32Ty(_module->getContext());



//         if (op.reg >= TRICORE_REG_E_0) {
//             ty = llvm::Type::getInt64Ty(_module->getContext());
//         } else {
//             ty = llvm::Type::getInt32Ty(_module->getContext());
//         }
    }

    switch (op.type) {
        case TRICORE_OP_REG:
            return loadRegister(op.reg, irb);

        case TRICORE_OP_IMM:
        {
            auto* immValue = llvm::ConstantInt::get(llvm::Type::getIntNTy(_module->getContext(), op.imm.sizeInBit), op.imm.value);
            switch (op.imm.ext) {
                case TRICORE_EXT_SEXT_TRUNC:
                    return irb.CreateSExtOrTrunc(immValue, ty);

                case TRICORE_EXT_ZEXT_TRUNC:
                    return irb.CreateZExtOrTrunc(immValue, ty);

                default:
                    if (immValue->getType() == ty) {
                        return immValue;
                    } else {
                        assert(false);
                    }
            }
        }
        case TRICORE_OP_MEM: {
            auto* baseR = loadRegister(op.mem.base, irb);

            llvm::Value* disp = nullptr;
            switch (op.mem.disp.ext) {
                case TRICORE_EXT_SEXT_TRUNC:
                    disp = llvm::ConstantInt::getSigned(ty, op.mem.disp.value);
                    break;

                default:
                    disp = llvm::ConstantInt::get(ty, op.mem.disp.value);
            }

            llvm::Value* addr = nullptr;
            if (baseR == nullptr) {
                addr = disp;
            } else {
                if (op.mem.disp.value == 0) {
                    addr = baseR;
                } else { // base register and disp is set
                    if (op.mem.op == TRICORE_MEM_OP_NOTHING) { //default mem(A[a], disp): load mem(A[a], disp)
                        addr = irb.CreateAdd(baseR, disp);

                    } else if (op.mem.op == TRICORE_MEM_OP_POSTINC) { // mem(A[a], disp): load mem(A[a]) and pinc A[a] += disp
                        addr = baseR;
                        storeRegister(op.mem.base, irb.CreateAdd(baseR, disp), irb); //pinc A[a] += disp)

                    } else if (op.mem.op == TRICORE_MEM_OP_PREINC) { // mem(A[a], disp): load mem(A[a], disp) and pinc A[a] += disp
                        addr = irb.CreateAdd(baseR, disp);
                        storeRegister(op.mem.base, addr, irb); //pinc A[a] += disp)

                    } else if (op.mem.op == TRICORE_MEM_OP_LEA) { // mem(A[a], disp): load EA = A[a] + disp
                        return irb.CreateAdd(baseR, disp, "lea");

                    } else {
                        assert(false && "UNKNOWN OP FOR LOAD TRICORE_MEM");
                    }
                }
            }

            auto* pt = llvm::PointerType::get(getType(op.mem.size), 0);
            addr = irb.CreateIntToPtr(addr, pt);
            return irb.CreateLoad(addr);
        }
        case TRICORE_OP_INVALID:
        default:
            assert(false && "should not be possible");
            return nullptr;
    }
}

/**
 * @a ct is used when storing a value to register with a different type.
 * When storing to memory, value type is used -- therefore it needs to be
 * converted to the desired type prior to @c storeOp() call.
 */
llvm::Instruction* Capstone2LlvmIrTranslatorTricore::storeOp(cs_tricore_op& op, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct) {
    switch (op.type) {
        case TRICORE_OP_REG:
            return storeRegister(op.reg, val, irb, ct);

        case TRICORE_OP_MEM: {
            auto* baseR = loadRegister(op.mem.base, irb);

            llvm::Value* disp = nullptr;
            switch (op.mem.disp.ext) {
                case TRICORE_EXT_SEXT_TRUNC:
                    disp = llvm::ConstantInt::getSigned(getType(), op.mem.disp.value);
                    break;

                default:
                    disp = llvm::ConstantInt::get(getType(), op.mem.disp.value);
            }

            llvm::Value* addr = nullptr;
            if (baseR == nullptr) {
                    addr = disp;
            } else {
                if (op.mem.disp.value == 0) {
                    addr = baseR;
                } else {
                    if (op.mem.op == TRICORE_MEM_OP_NOTHING) { //default mem(A[a], disp): load mem(A[a], disp)
                        addr = irb.CreateAdd(baseR, disp);

                    } else if (op.mem.op == TRICORE_MEM_OP_POSTINC) { // mem(A[a], disp): load mem(A[a]) and pinc A[a] += disp
                        addr = baseR;
                        storeRegister(op.mem.base, irb.CreateAdd(baseR, disp), irb); //pinc A[a] += disp)

                    } else if (op.mem.op == TRICORE_MEM_OP_PREINC) { // mem(A[a], disp): load mem(A[a], disp) and pinc A[a] += disp
                        addr = irb.CreateAdd(baseR, disp);
                        storeRegister(op.mem.base, addr, irb); //pinc A[a] += disp)

                    } else {
                        assert(false && "UNKNOWN OP FOR STORE TRICORE_MEM");
                    }
                }
            }

            auto* v = val;
            if (op.mem.ext == TRICORE_EXT_TRUNC_H) { //higher half
                v = irb.CreateAnd(irb.CreateLShr(val, op.mem.size / 2), ~(~0 << op.mem.size / 2));
                v = irb.CreateTrunc(v, getType(op.mem.size));

            } else if (op.mem.ext == TRICORE_EXT_TRUNC_L) { //lower half
                v = irb.CreateAnd(val, ~(~0 << op.mem.size / 2));
                v = irb.CreateTrunc(v, getType(op.mem.size));

            } else if (op.mem.ext == TRICORE_EXT_SEXT_TRUNC) {
                v = irb.CreateSExtOrTrunc(v, getType(op.mem.size));

            } else if (op.mem.ext == TRICORE_EXT_ZEXT_TRUNC) {
                v = irb.CreateZExtOrTrunc(v, getType(op.mem.size));
            }

            auto* pt = llvm::PointerType::get(v->getType(), 0);
            addr = irb.CreateIntToPtr(addr, pt);
            return irb.CreateStore(v, addr);
        }
        case TRICORE_OP_IMM:
        case TRICORE_OP_INVALID:
        default:
            assert(false && "should not be possible");
            return nullptr;
    }
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadRegister(tricore_reg r, llvm::IRBuilder<>& irb) {
    if (r == TRICORE_REG_INVALID) {
        return nullptr;
    }

    if (r == TRICORE_REG_PC) {
        return getCurrentPc(_insn);
    }

    if (r == TRICORE_REG_ZERO) {
        return llvm::ConstantInt::getSigned(getType(), 0);
    }

    auto* llvmReg = getRegister(r);
    if (llvmReg == nullptr) {
        assert(false && "loadRegister() unhandled reg.");
    }


    return irb.CreateLoad(llvmReg);
}

llvm::StoreInst* Capstone2LlvmIrTranslatorTricore::storeRegister(tricore_reg r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct) {
    // These registers should not be stored, or their store has no effect.
    if (r == TRICORE_REG_INVALID || r == TRICORE_REG_PC || r == TRICORE_REG_ZERO) {
        return nullptr;
    }

    auto* llvmReg = getRegister(r);
    auto* regT = getRegisterType(r);

    if (llvmReg == nullptr) {
        assert(llvmReg != nullptr && "storeRegister() unhandled reg.");
    }

    if (val->getType() != llvmReg->getValueType()) {
        switch (ct) {
            case eOpConv::SEXT_TRUNC:
                val = irb.CreateSExtOrTrunc(val, regT);
                break;

            case eOpConv::ZEXT_TRUNC:
                val = irb.CreateZExtOrTrunc(val, regT);
                break;

            default:
                llvmReg->getValueType()->dump();
                val->getType()->dump();
                assert(false && "Unhandled eOpConv type.");
        }
    }


    if (r >= TRICORE_REG_E_0 && r <= TRICORE_REG_P_14) { // extended reg, update childs
        std::pair<tricore_reg, tricore_reg> pRegs = extendedRegToRegs(r);

        auto* lReg = getRegister(pRegs.first);
        auto* lType = getRegisterType(pRegs.first);

        auto* hReg = getRegister(pRegs.second);
        auto* hType = getRegisterType(pRegs.second);

        auto* lVal = irb.CreateTrunc(val, lType);
        auto* hVal = irb.CreateTrunc(irb.CreateLShr(val, 32), hType);

        irb.CreateStore(lVal, lReg);
        irb.CreateStore(hVal, hReg);

    } else { //Update parent register
//         auto extReg = regToExtendedReg(r);
//
//         if (extReg != TRICORE_REG_INVALID) { // child reg, update extended parent reg
//             auto *extRegVal = loadRegister(extReg, irb);
//             std::pair<uint32_t, uint32_t> pRegs = extendedRegToRegs(extReg); // first = low, second = high
//
//             if (pRegs.first == r) {
//                 extRegVal = irb.CreateAnd(extRegVal, irb.getInt64(0xffffffff00000000));
//                 extRegVal = irb.CreateOr(extRegVal, irb.CreateZExt(val, extRegVal->getType()));
//
//             } else if (pRegs.second == r) {
//                 extRegVal = irb.CreateAnd(extRegVal, irb.getInt64(0x00000000ffffffff));
//                 extRegVal = irb.CreateOr(extRegVal, irb.CreateShl(irb.CreateZExt(val, extRegVal->getType()), 32));
//
//             } else {
//                 assert(false);
//             }
//
//             irb.CreateStore(extRegVal, getRegister(extReg));
//         }
    }

    return irb.CreateStore(val, llvmReg);
}

void Capstone2LlvmIrTranslatorTricore::genCarry(llvm::Value *v, llvm::IRBuilder<llvm::ConstantFolder> &irb) {
    storeRegister(TRICORE_REG_CF, irb.CreateICmpNE(irb.CreateAnd(v, 0x80000000), constInt<0>(v)), irb);
}

llvm::CallInst* Capstone2LlvmIrTranslatorTricore::generateBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative) {
    auto* a1t = _branchFunction->getArgumentList().front().getType();

    if (relative) {
        auto* pc = llvm::ConstantInt::get(getType(), i->address);
        t = irb.CreateAdd(pc, t);
    }

    t = irb.CreateSExtOrTrunc(t, a1t);
    _branchGenerated = irb.CreateCall(_branchFunction, {t});
    return _branchGenerated;
}

llvm::CallInst* Capstone2LlvmIrTranslatorTricore::generateCallFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative) {
    auto* a1t = _callFunction->getArgumentList().front().getType();

    if (relative) {
        auto* pc = llvm::ConstantInt::get(getType(), i->address);
        t = irb.CreateAdd(pc, t);
    }

    t = irb.CreateSExtOrTrunc(t, a1t);
    _branchGenerated = irb.CreateCall(_callFunction, {t});
    return _branchGenerated;
}

llvm::CallInst* Capstone2LlvmIrTranslatorTricore::generateCondBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* cond, llvm::Value* t, bool relative) {
    auto* a1t = _condBranchFunction->getArgumentList().back().getType();

    if (relative) {
        auto* pc = llvm::ConstantInt::get(getType(), i->address);
        t = irb.CreateAdd(pc, t);
    }

    t = irb.CreateSExtOrTrunc(t, a1t);
    _branchGenerated = irb.CreateCall(_condBranchFunction, {cond, t});
    return _branchGenerated;
}

llvm::CallInst* Capstone2LlvmIrTranslatorTricore::generateReturnFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative) {
    auto* a1t = _returnFunction->getArgumentList().front().getType();

    if (relative) {
        auto* pc = llvm::ConstantInt::get(getType(), i->address);
        t = irb.CreateAdd(pc, t);
    }

    t = irb.CreateSExtOrTrunc(t, a1t);
    _branchGenerated = irb.CreateCall(_returnFunction, {t});
    return _branchGenerated;
}

llvm::StoreInst* Capstone2LlvmIrTranslatorTricore::generateSpecialAsm2LlvmInstr(llvm::IRBuilder<>& irb, cs_insn* i) {
    retdec::utils::Address a = i->address;
    auto* gv = getAsm2LlvmMapGlobalVariable();
    auto* ci = llvm::ConstantInt::get(gv->getValueType(), a, false);
    auto* s = irb.CreateStore(ci, gv, true);

    auto* addr = llvm::ConstantInt::get(irb.getInt64Ty(), i->address);
    std::bitset<64> b = i->size == 4 ? i->bytes[3] << 24 | i->bytes[2] << 16 | i->bytes[1] << 8 | i->bytes[0] : i->bytes[1] << 8 | i->bytes[0];
    auto* bytes = llvm::ConstantInt::get(irb.getInt64Ty(), b.to_ulong());

    auto mAddr = llvm::ConstantAsMetadata::get(addr);
    auto* mBytes = llvm::ConstantAsMetadata::get(bytes);
    auto* mdn = llvm::MDNode::get(_module->getContext(), {mAddr, mBytes});
    s->setMetadata("asm-tricore", mdn);
    return s;
}

llvm::IntegerType* Capstone2LlvmIrTranslatorTricore::getType(uint8_t bitSize) {
    switch (bitSize) {
        case 64: return llvm::Type::getInt64Ty(_module->getContext());
        case 32: return llvm::Type::getInt32Ty(_module->getContext());
        case 16: return llvm::Type::getInt16Ty(_module->getContext());
        case 8: return llvm::Type::getInt8Ty(_module->getContext());
        case 1: return llvm::Type::getInt1Ty(_module->getContext());
        default: return llvm::Type::getIntNTy(_module->getContext(), bitSize);
    }
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getCurrentPc(cs_insn* i) {
//     return getNextInsnAddress(i);
    return llvm::ConstantInt::get(getType(), i->address);
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::getNextInsnAddress(cs_insn* i) {
    return llvm::ConstantInt::get(getType(), i->address + i->size);
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedBasicMode(cs_mode m) {
    return m == CS_MODE_THUMB; // there is no CS_MODE_TRICORE...
}

bool Capstone2LlvmIrTranslatorTricore::isAllowedExtraMode(cs_mode m) {
    return m == CS_MODE_LITTLE_ENDIAN; //TODO || m == CS_MODE_BIG_ENDIAN;
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
        assert(false); // & "Missing name for register number: " + std::to_string(r));
    }
}

} // namespace capstone2llvmir
} // namespace retdec
