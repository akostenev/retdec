#include "retdec/capstone2llvmir/tricore/tricore.h"

#include <iostream>

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

    if (address & 1) { //unaligned address, error, return
        return res;
    }

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
            if (it == end) {
                return res;
//                 assert(false);
            }
            i.bytes[1] = *it++;
            if (it == end) {
                return res;
//                 assert(false);
            }
            i.bytes[2] = *it++;
            if (it == end) {
                return res;
//                 assert(false);
            }
            i.bytes[3] = *it++;
        } else { // 16-bit instruction
            i.size = 2;
            i.bytes[0] = *it++;
            if (it == end) {
                return res;
//                 assert(false);
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

        cs_tricore t(i); // dism to capstone-tricore
        (this->*f)(i, &t, irb); // translate to LLVM-IR

    } else {

        if (isSrrsFormat(i->id)) { //Check if SRRS op format
            i->id = i->id & SRRSMASK;
            translateInstruction(i, irb);
            return;
        } else if (isBrrnFormat(i->id)) { //Check if BRRN op format
            i->id = i->id & BRRNMASK;
            translateInstruction(i, irb);
            return;
        }

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
        if (op.extended) {
            ty = llvm::Type::getInt64Ty(_module->getContext());
        } else {
            ty = llvm::Type::getInt32Ty(_module->getContext());
        }
    }

    switch (op.type) {
        case TRICORE_OP_REG:
            return loadRegister(op.reg, irb, op.extended);

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
            auto* baseR = loadRegister(op.mem.base, irb, op.extended);

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
                        if (replaceWithGlobalVal(op.mem.base)) {
                            return irb.CreateLoad(getMemToGlobalValue(op.mem.base, op.mem.disp.value, op.mem.size));
                        }

                        return irb.CreateAdd(baseR, disp, "lea");

                    } else {
                        assert(false && "UNKNOWN OP FOR LOAD TRICORE_MEM");
                    }
                }
            }

            if (baseR && replaceWithGlobalVal(op.mem.base)) {
                return irb.CreateLoad(getMemToGlobalValue(op.mem.base, op.mem.disp.value, op.mem.size));
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
            return storeRegister(op.reg, val, irb, ct, op.extended);

        case TRICORE_OP_MEM: {
            auto* baseR = loadRegister(op.mem.base, irb, op.extended);

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

            if (baseR && replaceWithGlobalVal(op.mem.base)) {
                return irb.CreateStore(v, getMemToGlobalValue(op.mem.base, op.mem.disp.value, op.mem.size));
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

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadRegister(uint32_t r, llvm::IRBuilder<>& irb, bool extended) {
    if (r == TRICORE_REG_INVALID) {
        return nullptr;
    }

    if (r == TRICORE_REG_PC) {
        return getCurrentPc(_insn);
    }

    if (r == TRICORE_REG_ZERO) {
        return llvm::ConstantInt::getSigned(getType(), 0);
    }

    if (extended) {
        r = regToExtendedReg(r);
    }

    auto* llvmReg = getRegister(r);
    if (llvmReg == nullptr) {
        assert(false && "loadRegister() unhandled reg.");
    }

    if (llvmReg->getValueType()->isPointerTy()) {
        return irb.CreateLoad(irb.CreateLoad(llvmReg));
    }

    return irb.CreateLoad(llvmReg);
}

llvm::StoreInst* Capstone2LlvmIrTranslatorTricore::storeRegister(uint32_t r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct, bool extended) {
    // These registers should not be stored, or their store has no effect.
    if (r == TRICORE_REG_INVALID || r == TRICORE_REG_PC || r == TRICORE_REG_ZERO) {
        return nullptr;
    }

    std::pair<uint32_t, uint32_t> pRegs;
//     uint32_t extR = 0;
    if (extended) {
        pRegs = extendedRegToRegs(r);
        r = regToExtendedReg(r);
    }
//     else {
//         extR = regToExtendedReg(r);
//         if (extR != TRICORE_REG_INVALID) {
//             pRegs = extendedRegToRegs(extR);
//         }
//     }

    auto* llvmReg = getRegister(r);
    auto* regT = getRegisterType(r);
    assert(llvmReg != nullptr && "storeRegister() unhandled reg.");

    if (replaceWithGlobalVal(tricore_reg(r))) {
        return irb.CreateStore(val, getMemToGlobalValue(tricore_reg(r), 0, 32));
    }

    if (val->getType() != llvmReg->getValueType()) {

        if (llvmReg->getValueType()->isPointerTy()) {
            auto* pt = llvm::PointerType::get(getType(extended ? 64 : 32), 0);
            val = irb.CreateIntToPtr(val, pt);

        } else {
            switch (ct) {
                case eOpConv::SEXT_TRUNC:
                    val = irb.CreateSExtOrTrunc(val, regT);
                    break;

                case eOpConv::ZEXT_TRUNC:
                    val = irb.CreateZExtOrTrunc(val, regT);
                    break;

    //             case eOpConv::FP_CAST:
    //                 val = irb.CreateFPCast(val, regT);
    //                 break;

                default:
                    assert(false && "Unhandled eOpConv type.");
            }
        }
    }

    if (extended) { //update low and high registers
        auto* lReg = getRegister(pRegs.first);
        auto* lType = getRegisterType(pRegs.first);

        auto* hReg = getRegister(pRegs.second);
        auto* hType = getRegisterType(pRegs.second);

        auto* lVal = irb.CreateTrunc(val, lType);
        auto* hVal = irb.CreateTrunc(irb.CreateLShr(val, hType->getIntegerBitWidth()), hType);

        irb.CreateStore(lVal, lReg);
        irb.CreateStore(hVal, hReg);

    }
//     else if (extR != TRICORE_REG_INVALID) { // update extended register
//         auto* extLlvmReg = loadRegister(extR, irb);
//         auto* extVal = irb.CreateZExt(val, extLlvmReg->getType());
//
//         if (pRegs.first == r) {
//             auto* maskL = llvm::ConstantInt::get(extLlvmReg->getType(), 0xffffffff00000000);
//             auto* andL = irb.CreateAnd(extLlvmReg, maskL);
//             auto* orL = irb.CreateOr(andL, extVal);
//             irb.CreateStore(orL, getRegister(extR));
//
//         } else if (pRegs.second == r) {
//             auto* maskH = llvm::ConstantInt::get(extLlvmReg->getType(), 0x0000000ffffffff);
//             auto* andH = irb.CreateAnd(extLlvmReg, maskH);
//             auto* orH = irb.CreateOr(andH, irb.CreateShl(extVal, 32));
//             irb.CreateStore(orH, getRegister(extR));
//
//         } else {
//             assert(false);
//         }
//     }

    return irb.CreateStore(val, llvmReg);
}


llvm::Value* Capstone2LlvmIrTranslatorTricore::getMemToGlobalValue(tricore_reg r, uint64_t disp, uint8_t size) {
    auto fGlobalValue = _memToGlobalValue.find(std::make_pair(r, disp));

    if (fGlobalValue != std::end(_memToGlobalValue)) {
        return fGlobalValue->second;
    } else {

        llvm::ConstantInt* init = nullptr;
        auto fInit = _initGlobalAddress.find(r);
        if (fInit == std::end(_initGlobalAddress)) {
            init = llvm::ConstantInt::get(getType(size), 0);
        } else {
            init = fInit->second;
        }

        std::stringstream ss;
        ss << getRegisterName(r) << "_" << disp;

        auto* gv = new llvm::GlobalVariable(
                        *_module,
                        getType(size),
                        false, // isConstant
                        llvm::GlobalValue::ExternalLinkage,
                        init,
                        ss.str(),
                        nullptr,
                        llvm::GlobalValue::ThreadLocalMode::NotThreadLocal,
                        0,
                        true
        );

        _memToGlobalValue.insert(std::make_pair(std::make_pair(r, disp), gv));
        return gv;
    }
}

bool Capstone2LlvmIrTranslatorTricore::replaceWithGlobalVal(tricore_reg r) const {
    return false;
//     switch (r) {
// //         case TRICORE_REG_A_0:
// //         case TRICORE_REG_A_1:
// //         case TRICORE_REG_A_2:
// //         case TRICORE_REG_A_9:
// //             return true;
//
//         default:
//             return false;
//
//     }
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

uint32_t Capstone2LlvmIrTranslatorTricore::regToExtendedReg(uint32_t r) const {
    switch (r) {
        case TRICORE_REG_D_0:
        case TRICORE_REG_D_1: return TRICORE_REG_E_0;
        case TRICORE_REG_D_2:
        case TRICORE_REG_D_3: return TRICORE_REG_E_2;
        case TRICORE_REG_D_4:
        case TRICORE_REG_D_5: return TRICORE_REG_E_4;
        case TRICORE_REG_D_6:
        case TRICORE_REG_D_7: return TRICORE_REG_E_6;
        case TRICORE_REG_D_8:
        case TRICORE_REG_D_9: return TRICORE_REG_E_8;
        case TRICORE_REG_D_10:
        case TRICORE_REG_D_11: return TRICORE_REG_E_10;
        case TRICORE_REG_D_12:
        case TRICORE_REG_D_13: return TRICORE_REG_E_12;
        case TRICORE_REG_D_14:
        case TRICORE_REG_D_15: return TRICORE_REG_E_14;

        case TRICORE_REG_A_0:
        case TRICORE_REG_A_1: return TRICORE_REG_P_0;
        case TRICORE_REG_A_2:
        case TRICORE_REG_A_3: return TRICORE_REG_P_2;
        case TRICORE_REG_A_4:
        case TRICORE_REG_A_5: return TRICORE_REG_P_4;
        case TRICORE_REG_A_6:
        case TRICORE_REG_A_7: return TRICORE_REG_P_6;
        case TRICORE_REG_A_8:
        case TRICORE_REG_A_9: return TRICORE_REG_P_8;
        case TRICORE_REG_A_10:
        case TRICORE_REG_A_11: return TRICORE_REG_P_10;
        case TRICORE_REG_A_12:
        case TRICORE_REG_A_13: return TRICORE_REG_P_12;
        case TRICORE_REG_A_14:
        case TRICORE_REG_A_15: return TRICORE_REG_P_14;

        default: return TRICORE_REG_INVALID;
    }
}

std::pair<uint32_t, uint32_t> Capstone2LlvmIrTranslatorTricore::extendedRegToRegs(uint32_t r) const {
    switch (r) {
        case TRICORE_REG_D_0:
        case TRICORE_REG_D_1:
        case TRICORE_REG_E_0: return std::make_pair(TRICORE_REG_D_0, TRICORE_REG_D_1);
        case TRICORE_REG_D_2:
        case TRICORE_REG_D_3:
        case TRICORE_REG_E_2: return std::make_pair(TRICORE_REG_D_2, TRICORE_REG_D_3);
        case TRICORE_REG_D_4:
        case TRICORE_REG_D_5:
        case TRICORE_REG_E_4: return std::make_pair(TRICORE_REG_D_4, TRICORE_REG_D_5);
        case TRICORE_REG_D_6:
        case TRICORE_REG_D_7:
        case TRICORE_REG_E_6: return std::make_pair(TRICORE_REG_D_6, TRICORE_REG_D_7);
        case TRICORE_REG_D_8:
        case TRICORE_REG_D_9:
        case TRICORE_REG_E_8: return std::make_pair(TRICORE_REG_D_8, TRICORE_REG_D_9);
        case TRICORE_REG_D_10:
        case TRICORE_REG_D_11:
        case TRICORE_REG_E_10: return std::make_pair(TRICORE_REG_D_10, TRICORE_REG_D_11);
        case TRICORE_REG_D_12:
        case TRICORE_REG_D_13:
        case TRICORE_REG_E_12: return std::make_pair(TRICORE_REG_D_12, TRICORE_REG_D_13);
        case TRICORE_REG_D_14:
        case TRICORE_REG_D_15:
        case TRICORE_REG_E_14: return std::make_pair(TRICORE_REG_D_14, TRICORE_REG_D_15);

        case TRICORE_REG_A_0:
        case TRICORE_REG_A_1:
        case TRICORE_REG_P_0: return std::make_pair(TRICORE_REG_A_0, TRICORE_REG_A_1);
        case TRICORE_REG_A_2:
        case TRICORE_REG_A_3:
        case TRICORE_REG_P_2: return std::make_pair(TRICORE_REG_A_2, TRICORE_REG_A_3);
        case TRICORE_REG_A_4:
        case TRICORE_REG_A_5:
        case TRICORE_REG_P_4: return std::make_pair(TRICORE_REG_A_4, TRICORE_REG_A_5);
        case TRICORE_REG_A_6:
        case TRICORE_REG_A_7:
        case TRICORE_REG_P_6: return std::make_pair(TRICORE_REG_A_6, TRICORE_REG_A_7);
        case TRICORE_REG_A_8:
        case TRICORE_REG_A_9:
        case TRICORE_REG_P_8: return std::make_pair(TRICORE_REG_A_8, TRICORE_REG_A_9);
        case TRICORE_REG_A_10:
        case TRICORE_REG_A_11:
        case TRICORE_REG_P_10: return std::make_pair(TRICORE_REG_A_10, TRICORE_REG_A_11);
        case TRICORE_REG_A_12:
        case TRICORE_REG_A_13:
        case TRICORE_REG_P_12: return std::make_pair(TRICORE_REG_A_12, TRICORE_REG_A_13);
        case TRICORE_REG_A_14:
        case TRICORE_REG_A_15:
        case TRICORE_REG_P_14: return std::make_pair(TRICORE_REG_A_14, TRICORE_REG_A_15);

        default: assert(false);
    }
}

llvm::IntegerType* Capstone2LlvmIrTranslatorTricore::getType(uint8_t bitSize) {
    switch (bitSize) {
        case 64: return llvm::Type::getInt64Ty(_module->getContext());
        case 32: return llvm::Type::getInt32Ty(_module->getContext());
        case 16: return llvm::Type::getInt16Ty(_module->getContext());
        case 8: return llvm::Type::getInt8Ty(_module->getContext());
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
