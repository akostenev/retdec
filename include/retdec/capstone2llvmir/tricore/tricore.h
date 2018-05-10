/**
 * @file include/retdec/capstone2llvmir/tricore/tricore.h
 * @brief TriCore implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H
#define RETDEC_CAPSTONE2LLVMIR_TRICORE_TRICORE_H

#include <array>
#include <bitset>
#include <tuple>
#include <utility>

#include "retdec/capstone2llvmir/capstone2llvmir.h"
#include "retdec/capstone2llvmir/tricore/tricore_defs.h"

namespace retdec {
namespace capstone2llvmir {

class Capstone2LlvmIrTranslatorTricore : public Capstone2LlvmIrTranslator {
public:
    Capstone2LlvmIrTranslatorTricore(llvm::Module* m, cs_mode basic = CS_MODE_32, cs_mode extra = CS_MODE_LITTLE_ENDIAN);
    virtual ~Capstone2LlvmIrTranslatorTricore();

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
    virtual void translateInstruction(cs_insn* i, llvm::IRBuilder<>& irb) override;
    virtual llvm::StoreInst* generateSpecialAsm2LlvmInstr(llvm::IRBuilder<>& irb, cs_insn* i) override;
    virtual void initializeArchSpecific() override;
    virtual void initializeRegNameMap() override;
    virtual void initializeRegTypeMap() override;
    virtual void generateEnvironmentArchSpecific() override;
    virtual void generateDataLayout() override;
    virtual void generateRegisters() override;

protected:
    // These are used to save lines needed to declare locale operands in
    // each translation function.
    // In C++17, we could use Structured Bindings:
    // auto [ op0, op1 ] = loadOpBinary();
    llvm::Value* op0 = nullptr;
    llvm::Value* op1 = nullptr;
    llvm::Value* op2 = nullptr;
    llvm::Value* op3 = nullptr;

    // TODO: This is a hack, sometimes we need cs_insn deep in helper
    // methods like @c loadRegister() where it is hard to propagate it.
    cs_insn* _insn = nullptr;

    //Helper funcs
protected:
    //returns e.g. E[0] for D[0], E2 for D[2]
    uint32_t regToExtendedReg(uint32_t r) const;

    llvm::IntegerType* getType(uint8_t bitSize = 32);
    llvm::Value* getCurrentPc(cs_insn* i);
    llvm::Value* getNextInsnAddress(cs_insn* i);

    llvm::CallInst* generateBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateCallFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateCondBranchFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* cond, llvm::Value* t, bool relative = true);
    llvm::CallInst* generateReturnFunctionCall(cs_insn* i, llvm::IRBuilder<>& irb, llvm::Value* t, bool relative = true);

    llvm::Value* loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb);
    llvm::Value* loadOp(cs_tricore_op& op, llvm::IRBuilder<>& irb, llvm::Type* ty);
    llvm::Instruction* storeOp(cs_tricore_op& op, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct = eOpConv::SEXT_TRUNC);

    llvm::Value* loadRegister(uint32_t r, llvm::IRBuilder<>& irb, bool extended = false);
    llvm::StoreInst* storeRegister(uint32_t r, llvm::Value* val, llvm::IRBuilder<>& irb, eOpConv ct = eOpConv::SEXT_TRUNC, bool extended = false);

protected:
    static std::map<std::size_t, void (Capstone2LlvmIrTranslatorTricore::*)(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>&)> _i2fm;
    void translateAdd(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateBitOperations1(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateBitOperations2(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateBitOperationsD(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateCall(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateExtr(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateJl(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateConditionalJ(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateLoad(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateLoad09(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateShift(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateStore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateStore89(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translateSub(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);

    void translate00(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
    void translateIgnore(cs_insn* i, cs_tricore* t, llvm::IRBuilder<>& irb);
};

} // namespace capstone2llvmir
} // namespace retdec

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

// template<std::uint16_t N>
// std::bitset<N> getBitSet(const uint8_t bytes[16])
// {
//     long unsigned int b = 0;
//     for (unsigned i = 0; i < N; i++) {
//         b |= bytes[i] << (i * 8);
//     }
//     std::bitset<N> r(b);
//     return r;
// };

#endif

