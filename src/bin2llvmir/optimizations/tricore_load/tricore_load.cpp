/**
* @file src/bin2llvmir/optimizations/tricore_load/tricore_load.cpp
* @brief Load simulator of TriCore aX Register.
*/

#include <cassert>
#include <iomanip>
#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/tricore_load/tricore_load.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/instruction.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

char TricoreLoad::ID = 0;

static RegisterPass<TricoreLoad> X(
		"tricore-load",
		"TriCore load simulator",
		false, // Only looks at CFG
		false // Analysis Pass
);

TricoreLoad::TricoreLoad() :
		ModulePass(ID)
{

}

void TricoreLoad::getAnalysisUsage(AnalysisUsage &AU) const
{

}

/**
 * @return @c True if al least one instruction was (un)volatilized.
 *         @c False otherwise.
 */
bool TricoreLoad::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	ReachingDefinitionsAnalysis RDA;
	RDA.runOnModule(M, config);

	for (auto &F : M.getFunctionList())
	for (auto &B : F)
	for (Instruction &I : B)
	{
            if (StoreInst* s = dyn_cast<StoreInst>(&I)) {
                auto str = s->getPointerOperand()->getName().str();
                if (!(str.rfind("a0.", 0) == 0 ||
                    str.rfind("a1.", 0) == 0 ||
                    str.rfind("a2.", 0) == 0 ||
                    str.rfind("a3.", 0) == 0 ||
                    str.rfind("a8.", 0) == 0 ||
                    str.rfind("a9.", 0) == 0)) {
                    continue;
                }

                /**
                * %v3_8012c21a = load i32, i32* inttoptr (i32 <OFFSET 2088> to i32*), align 8
                * store i32 %v3_8012c21a, i32* %<a2>.global-to-local, align 4
                *
                * %v1_8012c222 = add i32 %v3_8012c21a, <OFFSET 2594>
                * store i32 %v1_8012c222, i32* %a15.global-to-local, align 4
                * %v1_8012c226 = inttoptr i32 %v1_8012c222 to i16*
                * %v2_8012c226 = load i16, i16* %v1_8012c226, align 2
                * %v3_8012c226 = sext i16 %v2_8012c226 to i32
                * store i32 %v3_8012c226, i32* %d15.global-to-local, align 4
                *
                */
                if (Instruction* ins = dyn_cast<Instruction>(s->getValueOperand())) {
                    for (auto *U : ins->users()) {
                        llvm::ConstantInt* disp = nullptr;
                        llvm::ConstantInt* baseAddress = nullptr;
                        if (Instruction* fAddDispIns = dyn_cast<Instruction>(U)) {
                            if (fAddDispIns->getOpcode() == Instruction::Add) {
                                if (fAddDispIns->getNumOperands() >= 2 && fAddDispIns->getOperand(1)->getType()->isIntegerTy()) {
                                    disp = dyn_cast<ConstantInt>(fAddDispIns->getOperand(1)); //found disp

                                    if (Instruction *intToPtrIns = dyn_cast<Instruction>(fAddDispIns->getOperand(0))) {
                                        if (auto* c = dyn_cast<Constant>(intToPtrIns->getOperand(0))) {
                                            baseAddress = dyn_cast<ConstantInt>(c->getOperand(0)); //found baseAddress
                                        }
                                    }
                                }
                            }
                        }
                        if (!disp || !baseAddress) {
                            continue;
                        }

                        auto dispValue = disp->getSExtValue();
                        auto baseAddressValue = baseAddress->getZExtValue();
                        for (auto *UU : U->users()) {
                            for (auto *UUU : UU->users()) {
                                if (LoadInst* li = dyn_cast<LoadInst>(UUU)) {

                                    std::cout << "\tReplace " << s->getPointerOperand()->getName().str() <<
                                        "[0x" << std::hex << baseAddressValue << "][" << std::dec << dispValue << "] "
                                        "LOAD with const " << std::dec << dispValue << std::endl;
                                    if (li->getType() == disp->getType()) {
                                        li->replaceAllUsesWith(disp);
                                    } else {
                                        li->replaceAllUsesWith(llvm::ConstantInt::get(li->getType(), dispValue));
                                    }
                                }
                            }
                        }
                    }
                }

            }
            else if (LoadInst* li = dyn_cast<LoadInst>(&I)) {
                if (auto* c = dyn_cast<Constant>(li->getOperand(0))) {
                    auto* baseAddress = dyn_cast<ConstantInt>(c->getOperand(0)); //found baseAddress
                    std::cout << "\tReplace " << li->getPointerOperand()->getName().str() <<
                        "[0x" << std::hex << baseAddress->getZExtValue() << "] LOAD with const " << std::dec << 999 << std::endl;

                    li->replaceAllUsesWith(llvm::ConstantInt::get(li->getType(), 999));
                }
            }
	}

	return false;
}

} // namespace bin2llvmir
} // namespace retdec
