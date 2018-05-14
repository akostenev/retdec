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

        cs_tricore t(i);

        (this->*f)(i, &t, irb);
    } else {

        //Check if SRRS op format
        fIt = _i2fm.find(i->id & 0b11111);
        if (fIt != std::end(_i2fm)) {
            i->id = i->id & 0b11111;
            translateInstruction(i, irb);
            return;
        } else { //Check if BRN op format
            fIt = _i2fm.find(i->id & 0b111111);
            if (fIt != std::end(_i2fm)) {
                i->id = i->id & 0b111111;
                translateInstruction(i, irb);
                return;
            }
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

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb) {
    if (op.extended) {
        return loadOp(op, irb, llvm::Type::getInt64Ty(_module->getContext()));
    } else {
        return loadOp(op, irb, llvm::Type::getInt32Ty(_module->getContext()));
    }
}

llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb, llvm::Type* ty) {
    switch (op.type) {
        case TRICORE_OP_REG:
            return loadRegister(op.reg, irb, op.extended);

        case TRICORE_OP_IMM:
            switch (op.imm.ext) {
                case TRICORE_EXT_SEXT_TRUNC:
                    return llvm::ConstantInt::getSigned(ty, op.imm.value);
                    break;

                default: //ZEXT, NOTHING
                    return llvm::ConstantInt::get(ty, op.imm.value);
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
                } else {
                    assert(baseR->getType() == disp->getType());
                    addr = irb.CreateAdd(baseR, disp);
                }
            }

            if (op.mem.lea) {
                return addr;
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
                    addr = irb.CreateAdd(baseR, disp);
                }
            }

            auto* pt = llvm::PointerType::get(val->getType(), 0);
            addr = irb.CreateIntToPtr(addr, pt);
            return irb.CreateStore(val, addr);
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
        throw Capstone2LlvmIrError("loadRegister() unhandled reg.");
    }
    return irb.CreateLoad(llvmReg);
}

llvm::StoreInst* Capstone2LlvmIrTranslatorTricore::storeRegister(uint32_t r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct, bool extended) {
    // These registers should not be stored, or their store has no effect.
    if (r == TRICORE_REG_INVALID || r == TRICORE_REG_PC || r == TRICORE_REG_ZERO) {
        return nullptr;
    }

    if (extended) {
        r = regToExtendedReg(r);
    }

    auto* llvmReg = getRegister(r);
    auto* regT = getRegisterType(r);
    if (llvmReg == nullptr) {
        throw Capstone2LlvmIrError("storeRegister() unhandled reg.");
    }

    if (val->getType() != llvmReg->getValueType()) {
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
                throw Capstone2LlvmIrError("Unhandled eOpConv type.");
        }
    }

    return irb.CreateStore(val, llvmReg);
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
        case TRICORE_REG_D_0: return TRICORE_REG_E_0;
        case TRICORE_REG_D_1: return TRICORE_REG_E_0;
        case TRICORE_REG_D_2: return TRICORE_REG_E_2;
        case TRICORE_REG_D_3: return TRICORE_REG_E_2;
        case TRICORE_REG_D_4: return TRICORE_REG_E_4;
        case TRICORE_REG_D_5: return TRICORE_REG_E_4;
        case TRICORE_REG_D_6: return TRICORE_REG_E_6;
        case TRICORE_REG_D_7: return TRICORE_REG_E_6;
        case TRICORE_REG_D_8: return TRICORE_REG_E_8;
        case TRICORE_REG_D_9: return TRICORE_REG_E_8;
        case TRICORE_REG_D_10: return TRICORE_REG_E_10;
        case TRICORE_REG_D_11: return TRICORE_REG_E_10;
        case TRICORE_REG_D_12: return TRICORE_REG_E_12;
        case TRICORE_REG_D_13: return TRICORE_REG_E_12;
        case TRICORE_REG_D_14: return TRICORE_REG_E_14;
        case TRICORE_REG_D_15: return TRICORE_REG_E_14;

        case TRICORE_REG_A_0: return TRICORE_REG_P_0;
        case TRICORE_REG_A_1: return TRICORE_REG_P_0;
        case TRICORE_REG_A_2: return TRICORE_REG_P_2;
        case TRICORE_REG_A_3: return TRICORE_REG_P_2;
        case TRICORE_REG_A_4: return TRICORE_REG_P_4;
        case TRICORE_REG_A_5: return TRICORE_REG_P_4;
        case TRICORE_REG_A_6: return TRICORE_REG_P_6;
        case TRICORE_REG_A_7: return TRICORE_REG_P_6;
        case TRICORE_REG_A_8: return TRICORE_REG_P_8;
        case TRICORE_REG_A_9: return TRICORE_REG_P_8;
        case TRICORE_REG_A_10: return TRICORE_REG_P_10;
        case TRICORE_REG_A_11: return TRICORE_REG_P_10;
        case TRICORE_REG_A_12: return TRICORE_REG_P_12;
        case TRICORE_REG_A_13: return TRICORE_REG_P_12;
        case TRICORE_REG_A_14: return TRICORE_REG_P_14;
        case TRICORE_REG_A_15: return TRICORE_REG_P_14;

        default:
            assert(false);
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
        throw Capstone2LlvmIrError(
            "Missing name for register number: " + std::to_string(r));
    }
}



} // namespace capstone2llvmir
} // namespace retdec



// llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOpUnary(cs_tricore* mi, llvm::IRBuilder<>& irb) {
//     if (mi->op_count != 1) {
//         throw Capstone2LlvmIrError("This is not a unary instruction.");
//     }
//
//     return loadOp(mi->operands[0], irb);
// }

// std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOpBinary(cs_tricore* mi, llvm::IRBuilder<>& irb, eOpConv ct) {
//     if (mi->op_count != 2) {
//         throw Capstone2LlvmIrError("This is not a binary instruction.");
//     }
//
//     auto* op0 = loadOp(mi->operands[0], irb);
//     auto* op1 = loadOp(mi->operands[1], irb);
//     if (op0 == nullptr || op1 == nullptr) {
//         throw Capstone2LlvmIrError("Operands loading failed.");
//     }
//
//     if (op0->getType() != op1->getType()) {
//         switch (ct) {
//             case eOpConv::SECOND_SEXT:
//                 op1 = irb.CreateSExtOrTrunc(op1, op0->getType());
//                 break;
//             case eOpConv::SECOND_ZEXT:
//                 op1 = irb.CreateZExtOrTrunc(op1, op0->getType());
//                 break;
//             case eOpConv::NOTHING:
//                 break;
//             default:
//                 case eOpConv::THROW:
//                     throw Capstone2LlvmIrError("Binary operands' types not equal.");
//         }
//     }
//
//     return std::make_pair(op0, op1);
// }

// llvm::Value* Capstone2LlvmIrTranslatorTricore::loadOpBinaryOp1(cs_tricore* mi, llvm::IRBuilder<>& irb, llvm::Type* ty) {
//         if (mi->op_count != 2) {
//             throw Capstone2LlvmIrError("This is not a binary instruction.");
//         }
//         return loadOp(mi->operands[1], irb, ty);
// }

// std::tuple<llvm::Value*, llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOpTernary(cs_tricore* mi, llvm::IRBuilder<>& irb) {
//     if (mi->op_count != 3) {
//         throw Capstone2LlvmIrError("This is not a ternary instruction.");
//     }
//
//     auto* op0 = loadOp(mi->operands[0], irb);
//     auto* op1 = loadOp(mi->operands[1], irb);
//     auto* op2 = loadOp(mi->operands[2], irb);
//     if (op0 == nullptr || op1 == nullptr || op2 == nullptr) {
//         throw Capstone2LlvmIrError("Operands loading failed.");
//     }
//
//     return std::make_tuple(op0, op1, op2);
// }

// std::pair<llvm::Value*, llvm::Value*> Capstone2LlvmIrTranslatorTricore::loadOp1Op2(cs_tricore* mi, llvm::IRBuilder<>& irb, eOpConv ct) {
//     if (mi->op_count != 3) {
//         throw Capstone2LlvmIrError("This is not a ternary instruction.");
//     }
//
//     auto* op1 = loadOp(mi->operands[1], irb);
//     auto* op2 = loadOp(mi->operands[2], irb);
//     if (op1 == nullptr || op2 == nullptr) {
//             throw Capstone2LlvmIrError("Operands loading failed.");
//     }
//
//     if (op1->getType() != op2->getType()) {
//         sw{
//     if (mi->op_count != 3) {
//         throw Capstone2LlvmIrError("This is not a ternary instruction.");
//     }
//
//     auto* op1 = loadOp(mi->operands[1], irb);
//     auto* op2 = loadOp(mi->operands[2], irb);
//     if (op1 == nullptr || op2 == nullptr) {
//             throw Capstone2LlvmIrError("Operands loading failed.");
//     }
//
//     if (op1->getType() != op2->getType()) {
//         switch (ct) {
//             case eOpConv::SECOND_SEXT:
//             {
//                     op2 = irb.CreateSExtOrTrunc(op2, op1->getType());
//                     break;
//             }
//             case eOpConv::SECOND_ZEXT:
//             {
//                     op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
//                     break;
//             }
//             case eOpConv::NOTHING:
//             {
//                     break;
//             }
//             default:
//             case eOpConv::THROW:
//             {
//                     throw Capstone2LlvmIrError("Binary operands' types not equal.");
//             }
//         }
//     }
//
//     return std::make_pair(op1, op2);
// }itch (ct) {
//             case eOpConv::SECOND_SEXT:
//             {
//                     op2 = irb.CreateSExtOrTrunc(op2, op1->getType());
//                     break;
//             }
//             case eOpConv::SECOND_ZEXT:
//             {
//                     op2 = irb.CreateZExtOrTrunc(op2, op1->getType());
//                     break;
//             }
//             case eOpConv::NOTHING:
//             {
//                     break;
//             }
//             default:
//             case eOpConv::THROW:
//             {
//                     throw Capstone2LlvmIrError("Binary operands' types not equal.");
//             }
//         }
//     }
//
//     return std::make_pair(op1, op2);
// }