/**
* @file src/bin2llvmir/optimizations/control_flow/mips.cpp
* @brief Reconstruct control flow -- MIPS specific module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/IR/Constants.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/control_flow/control_flow.h"
#include "retdec/bin2llvmir/utils/type.h"

#define debug_enabled true
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {

bool ControlFlow::runTricore()
{
	bool changed = false;
	for (auto& f : *_module)
	{
		changed |= runTricoreFunction(&f);
	}
	return changed;
}

bool ControlFlow::runTricoreFunction(llvm::Function* f)
{
	bool changed = false;

	AsmInstruction ai(f);
	for (; ai.isValid(); ai = ai.getNext())
	{
		if (runTricoreReturn(ai))
		{
			changed = true;
			continue;
		}
		else if (runTricoreCall(ai))
		{
			changed = true;
			continue;
		}
	}

	return changed;
}

bool ControlFlow::runTricoreReturn(AsmInstruction& ai)
{
	for (auto& i : ai)
	{
		auto* c = _config->isLlvmReturnPseudoFunctionCall(&i);
		if (c == nullptr)
		{
			c = _config->isLlvmBranchPseudoFunctionCall(&i);
		}

		if (c)
		{
			auto* l = dyn_cast<LoadInst>(c->getArgOperand(0));
			if (l && l->getPointerOperand() == _config->getLlvmRegister("a11"))
			{
				_toReturn.insert({ai, c});
				return true;
			}
		}
	}

	return false;
}

bool ControlFlow::runTricoreCall(AsmInstruction& ai) {

    for (auto& i : ai) {
        auto* c = _config->isLlvmCallPseudoFunctionCall(&i);
            if (c == nullptr)
            {
                    continue;
            }
            auto* op = c->getArgOperand(0);

            retdec::utils::Address addr;
            if (auto* ci = dyn_cast<ConstantInt>(op))
            {
                    addr = ci->getZExtValue();
            }
            // we can do it here:
            // bugs.799.x86_elf_8e2d7ac57bded5f52a6b5cd6d769da31
            // LOAD:0804812E                 call    off_8049398
            //
            // we can not do it always:
            // ackermann.x86.gcc-4.7.2.O0.g.elf
            // LOAD:0804812E                 call    off_8049398
            //
            else if (auto* l = dyn_cast<LoadInst>(op))
            {
                    auto* pop = skipCasts(l->getPointerOperand());
                    if (auto* ci1 = dyn_cast<ConstantInt>(pop))
                    {
                            retdec::utils::Address a = ci1->getZExtValue();
                            auto* f1 = _config->getLlvmFunction(a);
                            auto* cf1 = _config->getConfigFunction(a);
                            auto* ci2 = _image->getConstantDefault(a);

                            if (f1 && cf1 && cf1->isDynamicallyLinked())
                            {
                                    addr = a;
                            }
                            else if (ci2 && _config->getLlvmFunction(ci2->getZExtValue()))
                            {
                                    addr = ci2->getZExtValue();
                            }
                            else if (ci2 && AsmInstruction(_module, ci2->getZExtValue()))
                            {
                                    addr = ci2->getZExtValue();
                            }
                            else if (cf1)
                            {
                                    addr = a;
                            }
                    }
            }

            if (addr.isUndefined())
            {
                    // TODO -- call variable
                    // 1.) if RDA available, try to compute it.
                    // 2.) if not computed, transform to call of variable.
                    continue;
            }

            _toCall.insert({c, addr});
            return true;
        }

        return false;
}

} // namespace bin2llvmir
} // namespace retdec
