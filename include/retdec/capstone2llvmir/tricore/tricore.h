/**
 * @file include/retdec/capstone2llvmir/tricore/tricore.h
 * @brief TriCore implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H
#define RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H

#include <array>
#include <tuple>
#include <utility>
#include <map>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/tricore/tricore_defs.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorTricore : public Capstone2LlvmIrTranslator {
public:
    Capstone2LlvmIrTranslatorTricore(llvm::Module* m, cs_mode basic = CS_MODE_32, cs_mode extra = CS_MODE_LITTLE_ENDIAN);
    virtual ~Capstone2LlvmIrTranslatorTricore() = default;

    /**
    * Override translate, for tricore2capstone
    */
    virtual Capstone2LlvmIrTranslator::TranslationResult translate(const std::vector<uint8_t>& bytes, retdec::utils::Address a, llvm::IRBuilder<>& irb, bool stopOnBranch = false);

    // Public pure virtual methods that must be implemented in concrete classes.
public:
    virtual bool isAllowedBasicMode(cs_mode m) override;
    virtual bool isAllowedExtraMode(cs_mode m) override;
    virtual void modifyBasicMode(cs_mode m) override;
    virtual void modifyExtraMode(cs_mode m) override;
    virtual uint32_t getArchByteSize() override;
    virtual uint32_t getArchBitSize() override;
    virtual std::string getRegisterName(uint32_t r) const override;

    // Protected pure virtual methods that must be implemented in concrete classes.
protected:
    // TODO: This is a hack, sometimes we need cs_insn deep in helper
    // methods like @c loadRegister() where it is hard to propagate it.
    cs_insn* _insn = nullptr;

    virtual void translateInstruction(cs_insn* i, llvm::IRBuilder<>& irb) override;
    virtual llvm::StoreInst* generateSpecialAsm2LlvmInstr(llvm::IRBuilder<>& irb, cs_insn* i) override;
    virtual void initializeArchSpecific() override;
    virtual void initializeRegNameMap() override;
    virtual void initializeRegTypeMap() override;
    virtual void generateEnvironmentArchSpecific() override;
    virtual void generateDataLayout() override;
    virtual void generateRegisters() override;

    std::map<tricore_reg, llvm::ConstantInt*> _initGlobalAddress;
    llvm::ConstantInt* getInitGlobalAddress(tricore_reg r) const;

    llvm::Value* getCurrentPc(cs_insn* i);
    llvm::Value* getNextInsnAddress(cs_insn* i);

    llvm::CallInst* generateBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateCallFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateCondBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* cond, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateReturnFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);

    template<std::int32_t N>
    llvm::Value* constInt(llvm::Value* t = nullptr) {
        if (!t) {
            return llvm::ConstantInt::get(getType(), N, true);
        } else {
            return llvm::ConstantInt::get(t->getType(), N, true);
        }
    };

    llvm::IntegerType* getType(uint8_t bitSize = 32);

    template<std::size_t N>
    llvm::Value* ld(cs_tricore* t, llvm::IRBuilder<>& irb) {
        if (N >= t->op_count) {
            return nullptr;
        }
        return loadOp(t->operands[N], irb);
    };

    llvm::Value* loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb, llvm::Type* ty = nullptr);
    llvm::Instruction* storeOp(cs_tricore_op& op, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct = eOpConv::THROW);

    llvm::Value* loadRegister(tricore_reg r, llvm::IRBuilder<>& irb);
    llvm::StoreInst* storeRegister(tricore_reg r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct = eOpConv::THROW);

    void genCarry(llvm::Value* v, llvm::IRBuilder<>& irb);

protected:
    static std::map<std::size_t, void (Capstone2LlvmIrTranslatorTricore::*)(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>&)> _i2fm;
    void translateAdd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateBitOperations1(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateBitOperations2(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateBitOperations(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateCall(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translate8B(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateDiv(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateExtr(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateInsert(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateJl(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateConditionalJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateConditionalLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateMul(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateShift(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateConditionalStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateSub(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translate00(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translate0B(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateIgnore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateInsertBit(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

};

} // namespace capstone2llvmir
} // namespace retdec

#endif
